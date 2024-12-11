package moe.karla.jmsressh.auth

import org.apache.sshd.common.AttributeRepository
import org.apache.sshd.server.auth.UserAuthFactory
import org.apache.sshd.server.auth.password.PasswordAuthenticator
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator
import org.apache.sshd.server.auth.pubkey.RejectAllPublickeyAuthenticator
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory
import org.apache.sshd.server.config.keys.AuthorizedKeysAuthenticator
import org.apache.sshd.server.session.ServerSession
import java.nio.file.Path
import java.security.PublicKey
import java.util.*
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile
import kotlin.io.path.readText

class JmsResshUserAuthingProvider(
    private val dataFolder: Path,
) : UserAuthFactoriesProvider {
    companion object {
        val publicKeyAuthorization = AttributeRepository.AttributeKey<PublickeyAuthenticator>()
        val passwordAuthorization = AttributeRepository.AttributeKey<PasswordAuthenticator>()
        val userSettings = AttributeRepository.AttributeKey<Properties>()
        val userDataFolder = AttributeRepository.AttributeKey<Path>()
    }

    object DelegatingPasswordAuthenticator : PasswordAuthenticator {
        override fun handleClientPasswordChangeRequest(
            session: ServerSession,
            username: String?,
            oldPassword: String?,
            newPassword: String?
        ): Boolean {
            return session.getAttribute(passwordAuthorization)
                .handleClientPasswordChangeRequest(session, username, oldPassword, newPassword)
        }

        override fun authenticate(username: String?, password: String?, session: ServerSession): Boolean {
            return session.getAttribute(passwordAuthorization).authenticate(username, password, session)
        }
    }

    object DelegatingPublicKeyAuthorization : PublickeyAuthenticator {
        override fun authenticate(username: String?, key: PublicKey?, session: ServerSession): Boolean {
            return session.getAttribute(publicKeyAuthorization).authenticate(username, key, session)
        }
    }


    override fun invoke(username: String, session: ServerSession): List<UserAuthFactory> {
        session.setAttribute(publicKeyAuthorization, RejectAllPublickeyAuthenticator.INSTANCE)
        val result = mutableListOf<UserAuthFactory>(UserAuthPublicKeyFactory.INSTANCE)

        if (username.contains(".") || username.contains("/") || username.contains("\\") || username.contains(":"))
            return result

        val userData = dataFolder.resolve("user").resolve(username)
        if (!userData.exists())
            return result
        session.setAttribute(userDataFolder, userData)

        if (userData.resolve("authorized_keys").exists()) {
            session.setAttribute(
                publicKeyAuthorization,
                AuthorizedKeysAuthenticator(userData.resolve("authorized_keys"))
            )
        }
        val settings = Properties()
        if (userData.resolve("settings.properties").isRegularFile()) {
            settings.load(userData.resolve("settings.properties").readText().reader())
        }
        session.setAttribute(userSettings, settings)

        val requestedPassword = settings.getProperty("authorization.password")
        if (requestedPassword != null && requestedPassword.isNotBlank()) {
            session.setAttribute(passwordAuthorization, PasswordAuthenticator { _, pwd, _ ->
                pwd == requestedPassword
            })

            result.add(UserAuthPasswordFactory.INSTANCE)
        }


        return result
    }
}