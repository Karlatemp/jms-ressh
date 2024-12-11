package moe.karla.jmsressh.auth

import org.apache.sshd.common.*
import org.apache.sshd.common.auth.AbstractUserAuthServiceFactory
import org.apache.sshd.common.config.keys.KeyRandomArt
import org.apache.sshd.common.io.IoWriteFuture
import org.apache.sshd.common.session.Session
import org.apache.sshd.common.util.GenericUtils
import org.apache.sshd.common.util.NumberUtils
import org.apache.sshd.common.util.ValidateUtils
import org.apache.sshd.common.util.buffer.Buffer
import org.apache.sshd.common.util.closeable.AbstractCloseable
import org.apache.sshd.common.util.io.IoUtils
import org.apache.sshd.core.CoreModuleProperties
import org.apache.sshd.server.ServerFactoryManager
import org.apache.sshd.server.auth.*
import org.apache.sshd.server.session.ServerSession
import org.apache.sshd.server.session.ServerSessionHolder
import java.io.File
import java.io.IOException
import java.net.MalformedURLException
import java.net.URI
import java.net.URISyntaxException
import java.net.URL
import java.nio.charset.Charset
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.function.Consumer

typealias UserAuthFactoriesProvider = (username: String, session: ServerSession) -> List<UserAuthFactory>
typealias UserAuthPostProcessor = (
    session: ServerSession,
    username: String,
    continuation: Runnable,
    failing: Consumer<String>,
) -> Unit

open class JmsResshAuthService(
    s: Session,
    private val postAuth: UserAuthPostProcessor = { _, _, c, _ -> c.run() },
    private val userAuthFactoriesProvider: UserAuthFactoriesProvider,
) : AbstractCloseable(),
    Service, ServerSessionHolder {

    class Factory(
        private val userAuthFactoriesProvider: UserAuthFactoriesProvider,
        private val postAuth: UserAuthPostProcessor = { _, _, c, _ -> c.run() },
    ) : ServiceFactory {
        override fun getName(): String = AbstractUserAuthServiceFactory.DEFAULT_NAME

        override fun create(session: Session): Service =
            JmsResshAuthService(session, postAuth, userAuthFactoriesProvider)

    }

    private val welcomeSent = AtomicBoolean(false)
    private val properties: Map<String, Any> = ConcurrentHashMap()
    private val welcomePhase: WelcomeBannerPhase
    private val serverSession: ServerSession = ValidateUtils.checkInstanceOf(
        s, ServerSession::class.java, "Server side service used on client side: %s", s
    )

    private var userAuthFactories: List<UserAuthFactory>? = null
    private var authUserName: String? = null
    private var authMethod: String? = null
    private var authService: String? = null
    private var currentAuth: UserAuth? = null

    private val maxAuthRequests: Int
    private var nbAuthRequests = 0

    init {
        if (s.isAuthenticated) {
            throw SshException("Session already authenticated")
        }

        welcomePhase = CoreModuleProperties.WELCOME_BANNER_PHASE.getRequired(this)
        maxAuthRequests = CoreModuleProperties.MAX_AUTH_REQUESTS.getRequired(this)

        s.resetAuthTimeout()
    }

    override fun start() {
        // do nothing
    }

    override fun getSession(): ServerSession {
        return getServerSession()
    }

    override fun getServerSession(): ServerSession {
        return serverSession
    }

    override fun getProperties(): Map<String, Any> {
        return properties
    }

    @Synchronized
    @Throws(Exception::class)
    override fun process(cmd: Int, buffer: Buffer) {
        var authed = java.lang.Boolean.FALSE
        val session = getServerSession()
        val debugEnabled = log.isDebugEnabled

        if (cmd == SshConstants.SSH_MSG_USERAUTH_REQUEST.toInt()) {
            val authHolder = AtomicReference(authed)
            if (!handleUserAuthRequestMessage(session, buffer, authHolder)) {
                return
            }

            authed = authHolder.get()
        } else {
            if (WelcomeBannerPhase.FIRST_AUTHCMD == welcomePhase) {
                sendWelcomeBanner(session)
            }

            checkNotNull(this.currentAuth) {
                "No current authentication mechanism for cmd=" + SshConstants.getCommandMessageName(
                    cmd
                )
            }

            if (debugEnabled) {
                log.debug(
                    "process({}) Received authentication message={} for mechanism={}",
                    session, SshConstants.getCommandMessageName(cmd), currentAuth!!.name
                )
            }

            buffer.rpos(buffer.rpos() - 1)
            try {
                authed = currentAuth!!.next(buffer)
            } catch (async: AsyncAuthException) {
                async.addListener { authenticated: Boolean -> asyncAuth(cmd, buffer, authenticated) }
                return
            } catch (e: Exception) {
                // Continue
                warn(
                    "process({}) Failed ({}) to authenticate using current method={}: {}",
                    session, e.javaClass.simpleName, currentAuth!!.name, e.message, e
                )
            }
        }

        if (authed == null) {
            handleAuthenticationInProgress(cmd, buffer)
        } else if (authed) {
            handleAuthenticationSuccess(cmd, buffer)
        } else {
            handleAuthenticationFailure(cmd, buffer)
        }
    }

    @Throws(Exception::class)
    protected fun handleUserAuthRequestMessage(
        session: ServerSession, buffer: Buffer, authHolder: AtomicReference<Boolean?>
    ): Boolean {
        val debugEnabled = log.isDebugEnabled
        /*
         * According to RFC4252 section 5.1:
         *
         *
         * When SSH_MSG_USERAUTH_SUCCESS has been sent, any further authentication requests received after that SHOULD
         * be silently ignored.
         */
        if (session.isAuthenticated) {
            val username = buffer.string
            val service = buffer.string
            val method = buffer.string

            if (debugEnabled) {
                log.debug(
                    "handleUserAuthRequestMessage({}) ignore user={}, service={}, method={}"
                        + " auth. request since session already authenticated",
                    session, username, service, method
                )
            }
            return false
        }

        if (WelcomeBannerPhase.FIRST_REQUEST == welcomePhase) {
            sendWelcomeBanner(session)
        }

        if (currentAuth != null) {
            try {
                currentAuth!!.destroy()
            } finally {
                currentAuth = null
            }
        }

        val username = buffer.string
        val service = buffer.string
        val method = buffer.string
        if (debugEnabled) {
            log.debug(
                "handleUserAuthRequestMessage({}) Received SSH_MSG_USERAUTH_REQUEST user={}, service={}, method={}",
                session, username, service, method
            )
        }

        if ((this.authUserName == null) || (this.authService == null)) {
            this.authUserName = username
            this.authService = service
        } else if (this.authUserName == username && this.authService == service) {
            nbAuthRequests++
            if (nbAuthRequests > maxAuthRequests) {
                var disconnectSession = true
                try {
                    val handler = session.sessionDisconnectHandler
                    disconnectSession = (handler == null)
                        || (!handler.handleAuthCountDisconnectReason(
                        session, this, service, method, username, nbAuthRequests, maxAuthRequests
                    ))
                } catch (e: IOException) {
                    warn(
                        "handleUserAuthRequestMessage({}) failed ({}) to invoke disconnect handler due to"
                            + " user={}/{}, service={}/{} - {}/{} auth requests: {}",
                        session, e.javaClass.simpleName,
                        this.authUserName, username, this.authService, service,
                        nbAuthRequests, maxAuthRequests, e.message, e
                    )
                } catch (e: RuntimeException) {
                    warn(
                        "handleUserAuthRequestMessage({}) failed ({}) to invoke disconnect handler due to"
                            + " user={}/{}, service={}/{} - {}/{} auth requests: {}",
                        session, e.javaClass.simpleName,
                        this.authUserName, username, this.authService, service,
                        nbAuthRequests, maxAuthRequests, e.message, e
                    )
                }

                if (disconnectSession) {
                    session.disconnect(
                        SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                        "Too many authentication failures: $nbAuthRequests"
                    )
                    return false
                }

                if (debugEnabled) {
                    log.debug(
                        "handleUserAuthRequestMessage({}) ignore mismatched authentication counts: user={}/{}, service={}/{}: {}/{}",
                        session, this.authUserName, username, this.authService, service, nbAuthRequests, maxAuthRequests
                    )
                }
            }
        } else {
            var disconnectSession = true
            try {
                val handler = session.sessionDisconnectHandler
                disconnectSession = (handler == null)
                    || (!handler.handleAuthParamsDisconnectReason(
                    session, this, this.authUserName, username, this.authService, service
                ))
            } catch (e: IOException) {
                warn(
                    "handleUserAuthRequestMessage({}) failed ({}) to invoke disconnect handler due to"
                        + " user={}/{}, service={}/{} mismatched parameters: {}",
                    session, e.javaClass.simpleName,
                    this.authUserName, username, this.authService, service, e.message, e
                )
            } catch (e: RuntimeException) {
                warn(
                    "handleUserAuthRequestMessage({}) failed ({}) to invoke disconnect handler due to"
                        + " user={}/{}, service={}/{} mismatched parameters: {}",
                    session, e.javaClass.simpleName,
                    this.authUserName, username, this.authService, service, e.message, e
                )
            }

            if (disconnectSession) {
                session.disconnect(
                    SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                    ("Change of username or service is not allowed (" + this.authUserName + ", " + this.authService + ")"
                        + " -> (" + username + ", " + service + ")")
                )
            } else {
                if (debugEnabled) {
                    log.debug(
                        "handleUserAuthRequestMessage({}) ignore mismatched authentication parameters: user={}/{}, service={}/{}",
                        session, this.authUserName, username, this.authService, service
                    )
                }
            }
            return false
        }

        // TODO: verify that the service is supported
        this.authMethod = method
        if (debugEnabled) {
            log.debug(
                "handleUserAuthRequestMessage({}) Authenticating user '{}' with service '{}' and method '{}' (attempt {} / {})",
                session, username, service, method, nbAuthRequests, maxAuthRequests
            )
        }

        if (userAuthFactories == null) {
            userAuthFactories = userAuthFactoriesProvider(username, session)
        }

        val factory = NamedResource.findByName(
            method, java.lang.String.CASE_INSENSITIVE_ORDER, userAuthFactories
        )
        if (factory == null) {
            if (debugEnabled) {
                log.debug("handleUserAuthRequestMessage({}) no authentication factory for method={}", session, method)
            }

            return true
        }

        currentAuth = ValidateUtils.checkNotNull(
            factory.createUserAuth(session), "No authenticator created for method=%s", method
        )
        try {
            val authed = currentAuth!!.auth(session, username, service, buffer)
            authHolder.set(authed)
        } catch (async: AsyncAuthException) {
            async.addListener { authenticated: Boolean ->
                asyncAuth(
                    SshConstants.SSH_MSG_USERAUTH_REQUEST.toInt(),
                    buffer,
                    authenticated
                )
            }
            return false
        } catch (e: Exception) {
            warn(
                "handleUserAuthRequestMessage({}) Failed ({}) to authenticate using factory method={}: {}",
                session, e.javaClass.simpleName, method, e.message, e
            )
        }

        return true
    }

    @Synchronized
    protected fun asyncAuth(cmd: Int, buffer: Buffer, authed: Boolean) {
        try {
            if (authed) {
                handleAuthenticationSuccess(cmd, buffer)
            } else {
                handleAuthenticationFailure(cmd, buffer)
            }
        } catch (e: Exception) {
            val session = getServerSession()
            warn(
                "asyncAuth({}) Error ({}) performing async authentication via cmd={}: {}",
                session, e.javaClass.simpleName, cmd, e.message, e
            )
        }
    }

    @Throws(Exception::class)
    protected fun handleAuthenticationInProgress(cmd: Int, inputMessage: Buffer) {
        val username = if (currentAuth == null) null else currentAuth!!.username
        if (log.isDebugEnabled) {
            log.debug(
                "handleAuthenticationInProgress({}@{}) {}",
                username, getServerSession(), SshConstants.getCommandMessageName(cmd)
            )
        }
    }

    @Throws(Exception::class)
    protected fun handleAuthenticationSuccess(cmd: Int, inputMessage: Buffer) {
        val username = Objects.requireNonNull(currentAuth, "No current auth")!!.username
        val session = getServerSession()
        val debugEnabled = log.isDebugEnabled
        if (debugEnabled) {
            log.debug(
                "handleAuthenticationSuccess({}@{}) {}",
                username, session, SshConstants.getCommandMessageName(cmd)
            )
        }

        val maxSessionCount = CoreModuleProperties.MAX_CONCURRENT_SESSIONS.getOrNull(session)
        if (maxSessionCount != null) {
            val currentSessionCount = session.getActiveSessionCountForUser(username)
            if (currentSessionCount >= maxSessionCount) {
                var disconnectSession = true
                try {
                    val handler = session.sessionDisconnectHandler
                    disconnectSession = (handler == null)
                        || (!handler.handleSessionsCountDisconnectReason(
                        session, this, username, currentSessionCount, maxSessionCount
                    ))
                } catch (e: IOException) {
                    warn(
                        "handleAuthenticationSuccess({}@{}) failed ({}) to invoke disconnect handler due to {}/{} sessions count: {}",
                        username, session, e.javaClass.simpleName, currentSessionCount, maxSessionCount,
                        e.message, e
                    )
                } catch (e: RuntimeException) {
                    warn(
                        "handleAuthenticationSuccess({}@{}) failed ({}) to invoke disconnect handler due to {}/{} sessions count: {}",
                        username, session, e.javaClass.simpleName, currentSessionCount, maxSessionCount,
                        e.message, e
                    )
                }

                if (disconnectSession) {
                    session.disconnect(
                        SshConstants.SSH2_DISCONNECT_TOO_MANY_CONNECTIONS,
                        ("Too many concurrent connections (" + currentSessionCount + ") - max. allowed: "
                            + maxSessionCount)
                    )
                    return
                }

                if (debugEnabled) {
                    log.debug(
                        "handleAuthenticationSuccess({}@{}) ignore {}/{} sessions count due to handler intervention",
                        username, session, currentSessionCount, maxSessionCount
                    )
                }
            }
        }

        try {
            currentAuth!!.destroy()
        } finally {
            currentAuth = null
        }

        postAuth(
            serverSession,
            username,
            Runnable {
                if (WelcomeBannerPhase.POST_SUCCESS == welcomePhase) {
                    sendWelcomeBanner(session)
                }

                session.signalAuthenticationSuccess(username, authService, inputMessage)
            },
            Consumer { reason ->
                session.disconnect(SshConstants.SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, reason)
            }
        )
    }

    @Throws(Exception::class)
    protected fun handleAuthenticationFailure(cmd: Int, inputMessage: Buffer) {
        val session = getServerSession()
        val debugEnabled = log.isDebugEnabled
        if (WelcomeBannerPhase.FIRST_FAILURE == welcomePhase) {
            sendWelcomeBanner(session)
        }

        val username = currentAuth?.username
        if (debugEnabled) {
            log.debug(
                "handleAuthenticationFailure({}@{}) {}",
                username, session, SshConstants.getCommandMessageName(cmd)
            )
        }

        val remaining = userAuthFactories.orEmpty().joinToString(",") { it.name }
        if (debugEnabled) {
            log.debug("handleAuthenticationFailure({}@{}) remaining methods: {}", username, session, remaining)
        }

        val buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_FAILURE, remaining.length + java.lang.Byte.SIZE)
        buffer.putString(remaining)
        buffer.putBoolean(false) // no partial success ...
        session.writePacket(buffer)

        if (currentAuth != null) {
            try {
                currentAuth!!.destroy()
            } finally {
                currentAuth = null
            }
        }
    }

    /**
     * Sends the welcome banner (if any configured) and if not already invoked
     *
     * @param  session     The [ServerSession] to send the welcome banner to
     * @return             The sent welcome banner [IoWriteFuture] - `null` if none sent
     * @throws IOException If failed to send the banner
     */
    @Throws(IOException::class)
    fun sendWelcomeBanner(session: ServerSession): IoWriteFuture? {
        if (welcomeSent.getAndSet(true)) {
            if (log.isDebugEnabled) {
                log.debug("sendWelcomeBanner({}) already sent", session)
            }
            return null
        }

        val welcomeBanner = resolveWelcomeBanner(session)
        if (GenericUtils.isEmpty(welcomeBanner)) {
            return null
        }

        val lang = CoreModuleProperties.WELCOME_BANNER_LANGUAGE.getRequired(this)
        val buffer = session.createBuffer(
            SshConstants.SSH_MSG_USERAUTH_BANNER,
            welcomeBanner!!.length + GenericUtils.length(lang) + java.lang.Long.SIZE
        )
        buffer.putString(welcomeBanner)
        buffer.putString(lang)

        if (log.isDebugEnabled) {
            log.debug(
                "sendWelcomeBanner({}) send banner (length={}, lang={})",
                session, welcomeBanner.length, lang
            )
        }
        return session.writePacket(buffer)
    }

    @Throws(IOException::class)
    protected fun resolveWelcomeBanner(session: ServerSession): String? {
        var bannerValue: Any? = CoreModuleProperties.WELCOME_BANNER.getOrNull(this)
            ?: return null

        if (bannerValue is CharSequence) {
            val message = bannerValue.toString()
            if (GenericUtils.isEmpty(message)) {
                return null
            }

            if (CoreModuleProperties.AUTO_WELCOME_BANNER_VALUE.equals(message, ignoreCase = true)) {
                try {
                    return KeyRandomArt.combine(session, ' ', session.keyPairProvider)
                } catch (e: IOException) {
                    throw e
                } catch (e: Exception) {
                    throw IOException(e)
                }
            }

            if (!message.contains("://")) {
                return message
            }

            try {
                bannerValue = URI(message)
            } catch (e: URISyntaxException) {
                log.error("resolveWelcomeBanner({}) bad path URI {}: {}", session, message, e.message)
                throw MalformedURLException(
                    e.javaClass.simpleName + " - bad URI (" + message + "): " + e.message
                )
            }

            if (message.startsWith("file:/")) {
                bannerValue = Paths.get(bannerValue)
            }
        }

        if (bannerValue is File) {
            bannerValue = bannerValue.toPath()
        }

        if (bannerValue is Path) {
            val path = bannerValue
            if ((!Files.exists(path)) || (Files.size(path) <= 0L)) {
                if (log.isDebugEnabled) {
                    log.debug("resolveWelcomeBanner({}) file is empty/does not exist {}", session, path)
                }
                return null
            }
            bannerValue = path.toUri()
        }

        if (bannerValue is URI) {
            bannerValue = bannerValue.toURL()
        }

        if (bannerValue is URL) {
            val cs = CoreModuleProperties.WELCOME_BANNER_CHARSET.getRequired(this)
            return loadWelcomeBanner(session, bannerValue, cs)
        }

        return bannerValue.toString()
    }

    @Throws(IOException::class)
    protected fun loadWelcomeBanner(session: ServerSession?, url: URL, cs: Charset): String {
        url.openStream().use { stream ->
            val bytes = IoUtils.toByteArray(stream)
            return if (NumberUtils.isEmpty(bytes)) "" else String(bytes, cs)
        }
    }

    val factoryManager: ServerFactoryManager
        get() = serverSession!!.factoryManager
}
