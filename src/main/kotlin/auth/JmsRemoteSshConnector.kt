package moe.karla.jmsressh.auth

import com.atlassian.onetime.core.TOTPGenerator
import com.atlassian.onetime.model.TOTPSecret
import moe.karla.jmsressh.forwardClientAttr
import org.apache.sshd.client.SshClient
import org.apache.sshd.client.auth.keyboard.UserInteraction
import org.apache.sshd.client.session.ClientSession
import org.apache.sshd.common.session.Session
import org.apache.sshd.common.session.SessionListener
import org.apache.sshd.common.util.security.SecurityUtils
import org.apache.sshd.server.session.ServerSession
import java.util.concurrent.ExecutorService
import java.util.function.Consumer
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile
import kotlin.io.path.walk

class JmsRemoteSshConnector(
    private val executor: ExecutorService,
    private val client: SshClient,
) : UserAuthPostProcessor {
    override fun invoke(
        serverSession: ServerSession,
        username: String,
        continuation: Runnable,
        failing: Consumer<String>,
    ) {
        executor.submit {

            val settings = serverSession.getAttribute(JmsResshUserAuthingProvider.userSettings)
            if (settings == null) {
                failing.accept("Missing User Settings")
                return@submit
            }

            val remoteUser = settings.getProperty("remote.user") ?: kotlin.run {
                failing.accept("settings missing remote.user")
                return@submit
            }
            val remoteHost = settings.getProperty("remote.host") ?: kotlin.run {
                failing.accept("settings missing remote.host")
                return@submit
            }
            val remotePort = settings.getProperty("remote.port")?.toIntOrNull() ?: kotlin.run {
                failing.accept("settings missing remote.port")
                return@submit
            }


            val clientSession = kotlin.runCatching {
                client.connect(remoteUser, remoteHost, remotePort).verify().session
            }.getOrElse { err ->
                failing.accept(err.toString())
                return@submit
            }

            clientSession.userInteraction = object : UserInteraction {
                override fun interactive(
                    session: ClientSession?,
                    name: String?,
                    instruction: String?,
                    lang: String?,
                    prompt: Array<out String>?,
                    echo: BooleanArray?
                ): Array<String> {
                    val secret = TOTPSecret.fromBase32EncodedString(
                        settings.getProperty("remote.totp") ?: error("setting missing remote.totp")
                    )
                    val totpGenerator = TOTPGenerator()
                    val totp = totpGenerator.generateCurrent(secret) //TOTP(value=123456)

                    return arrayOf(totp.value)
                }

                override fun getUpdatedPassword(
                    session: ClientSession?,
                    prompt: String?,
                    lang: String?
                ): String? = null

            }
            try {
                val userDataFolder = serverSession.getAttribute(JmsResshUserAuthingProvider.userDataFolder)
                if (userDataFolder.resolve("keys").exists()) {
                    val loader = SecurityUtils.getKeyPairResourceParser()
                    userDataFolder.resolve("keys").walk()
                        .filter { it.isRegularFile() }
                        .map { loader.loadKeyPairs(null, it, null) }
                        .flatten()
                        .forEach { clientSession.addPublicKeyIdentity(it) }
                }
                settings.getProperty("remote.password")?.let { clientSession.addPasswordIdentity(it) }

                clientSession.auth().verify().await()
                serverSession.setAttribute(forwardClientAttr, clientSession)

                clientSession.addSessionListener(object : SessionListener {
                    override fun sessionClosed(session: Session?) {
                        serverSession.close()
                    }
                })
                serverSession.addSessionListener(object : SessionListener {
                    override fun sessionClosed(session: Session?) {
                        clientSession.close()
                    }
                })

                continuation.run()
            } catch (e: Exception) {
                clientSession.close()
                failing.accept(e.toString())
            }
        }
    }
}