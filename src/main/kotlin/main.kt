@file:JvmName("MainKt")

package moe.karla.jmsressh

import moe.karla.jmsressh.auth.JmsRemoteSshConnector
import moe.karla.jmsressh.auth.JmsResshAuthService
import moe.karla.jmsressh.auth.JmsResshUserAuthingProvider
import moe.karla.jmsressh.command.ForwardedShellCommand
import moe.karla.jmsressh.command.ForwardingSubsystemFactory
import moe.karla.jmsressh.session.AdvancedChannelSession
import moe.karla.jmsressh.socks.startSockProxyServer
import org.apache.sshd.client.SshClient
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier
import org.apache.sshd.client.session.ClientSession
import org.apache.sshd.common.AttributeRepository
import org.apache.sshd.core.CoreModuleProperties
import org.apache.sshd.server.ServerBuilder
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider
import org.apache.sshd.server.session.ServerConnectionServiceFactory
import org.apache.sshd.server.shell.ShellFactory
import java.nio.file.Paths
import java.time.Duration
import java.util.concurrent.Executors
import kotlin.io.path.createDirectories

val forwardClientAttr = AttributeRepository.AttributeKey<ClientSession>()


fun main() {

    val client = SshClient.setUpDefaultClient()
    client.start()
    client.serverKeyVerifier = AcceptAllServerKeyVerifier.INSTANCE
    CoreModuleProperties.HEARTBEAT_REQUEST.set(client, "keepalive@keepalive")
    CoreModuleProperties.HEARTBEAT_INTERVAL.set(client, Duration.ofSeconds(10))

    val executor = Executors.newScheduledThreadPool(16)
    val server = ServerBuilder.builder()
        .channelFactories(
            listOf(
                AdvancedChannelSession.Factory,
            )
        )
        .build()
    CoreModuleProperties.IDLE_TIMEOUT.set(server, Duration.ZERO)

    val dataFolder = Paths.get("data").createDirectories()
    val keyProvider = SimpleGeneratorHostKeyProvider(dataFolder.resolve("server_key.txt"))
    server.keyPairProvider = keyProvider
    server.publickeyAuthenticator = JmsResshUserAuthingProvider.DelegatingPublicKeyAuthorization
    server.passwordAuthenticator = JmsResshUserAuthingProvider.DelegatingPasswordAuthenticator

    server.shellFactory = ShellFactory { ForwardedShellCommand() }
    server.subsystemFactories = listOf(
        ForwardingSubsystemFactory("sftp"),
    )
    server.serviceFactories = listOf(
        JmsResshAuthService.Factory(
            postAuth = JmsRemoteSshConnector(executor, client),
            userAuthFactoriesProvider = JmsResshUserAuthingProvider(dataFolder),
        ),
        ServerConnectionServiceFactory.INSTANCE,
    )

    server.port = 7411
    server.start()

    startSockProxyServer(dataFolder, keyProvider)
}