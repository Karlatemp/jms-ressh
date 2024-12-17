package moe.karla.jmsressh.socks

import io.netty.handler.proxy.Socks5ProxyHandler
import org.apache.sshd.common.FactoryManager
import org.apache.sshd.common.io.IoConnector
import org.apache.sshd.common.io.IoHandler
import org.apache.sshd.common.io.IoServiceFactory
import org.apache.sshd.common.keyprovider.KeyPairProvider
import org.apache.sshd.common.session.Session
import org.apache.sshd.common.util.net.SshdSocketAddress
import org.apache.sshd.core.CoreModuleProperties
import org.apache.sshd.netty.NettyIoServiceFactory
import org.apache.sshd.netty.NettyIoServiceFactoryFactory
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.UserAuthNoneFactory
import org.apache.sshd.server.auth.password.AcceptAllPasswordAuthenticator
import org.apache.sshd.server.auth.password.PasswordAuthenticator
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory
import org.apache.sshd.server.config.keys.AuthorizedKeysAuthenticator
import org.apache.sshd.server.forward.ForwardingFilter
import org.apache.sshd.server.forward.TcpForwardingFilter
import java.net.InetSocketAddress
import java.nio.file.Path
import java.time.Duration
import java.util.*
import kotlin.io.path.bufferedReader
import kotlin.io.path.createDirectories
import kotlin.io.path.exists

fun startSockProxyServer(dataFolder: Path, keyPairProvider: KeyPairProvider) {
    val socksData = dataFolder.resolve("socks").createDirectories()
    val settings = Properties()
    socksData.resolve("settings.properties").takeIf { it.exists() }?.let { settingsFile ->
        settingsFile.bufferedReader().use { settings.load(it) }
    }

    if (settings.getProperty("enable") != "true") return

    val server = SshServer.setUpDefaultServer()
    server.port = settings.getProperty("port")?.toIntOrNull() ?: 7341
    server.keyPairProvider = keyPairProvider
    CoreModuleProperties.IDLE_TIMEOUT.set(server, Duration.ZERO)

    val passwd = settings.getProperty("auth.password")
    server.passwordAuthenticator =
        PasswordAuthenticator { _, inputPasswd, _ ->
            passwd != null && passwd == inputPasswd
        }
    server.publickeyAuthenticator = AuthorizedKeysAuthenticator(socksData.resolve("authorized_keys"))

    if (settings.getProperty("auth.noauth") == "true") {
        server.passwordAuthenticator = AcceptAllPasswordAuthenticator.INSTANCE
        server.publickeyAuthenticator = AcceptAllPublickeyAuthenticator.INSTANCE
        server.userAuthFactories = listOf(
            UserAuthNoneFactory.INSTANCE,
            UserAuthPasswordFactory.INSTANCE,
            UserAuthPublicKeyFactory.INSTANCE,
        )
    }

    server.forwardingFilter = object : ForwardingFilter {
        override fun canForwardAgent(session: Session?, requestType: String?): Boolean = false
        override fun canForwardX11(session: Session?, requestType: String?): Boolean = false
        override fun canListen(address: SshdSocketAddress?, session: Session?): Boolean = false
        override fun canConnect(
            type: TcpForwardingFilter.Type?,
            address: SshdSocketAddress?,
            session: Session?
        ): Boolean = true
    }
    val socks5Host = InetSocketAddress(
        settings.getProperty("socks5.host"),
        settings.getProperty("socks5.port").toInt(),
    )

    server.ioServiceFactoryFactory = object : NettyIoServiceFactoryFactory() {
        override fun create(manager: FactoryManager): IoServiceFactory {
            val factory = NettyIoServiceFactory(manager, eventLoopGroup)
            factory.ioServiceEventListener = manager.ioServiceEventListener
            return object : IoServiceFactory by factory {
                override fun createConnector(handler: IoHandler): IoConnector {
                    return NettySocksIoConnector(manager, factory, handler) {
                        Socks5ProxyHandler(socks5Host)
                    }
                }
            }
        }
    }

    server.start()
}