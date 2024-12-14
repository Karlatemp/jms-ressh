/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package moe.karla.jmsressh.socks

import io.netty.bootstrap.Bootstrap
import io.netty.channel.ChannelHandler
import io.netty.channel.ChannelInitializer
import io.netty.channel.ChannelOption
import io.netty.channel.group.DefaultChannelGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import io.netty.handler.logging.LogLevel
import io.netty.handler.logging.LoggingHandler
import io.netty.handler.proxy.Socks5ProxyHandler
import io.netty.util.concurrent.Future
import io.netty.util.concurrent.GlobalEventExecutor
import org.apache.sshd.common.AttributeRepository
import org.apache.sshd.common.FactoryManager
import org.apache.sshd.common.io.DefaultIoConnectFuture
import org.apache.sshd.common.io.IoConnectFuture
import org.apache.sshd.common.io.IoConnector
import org.apache.sshd.common.io.IoHandler
import org.apache.sshd.core.CoreModuleProperties
import org.apache.sshd.netty.NettyIoService
import org.apache.sshd.netty.NettyIoServiceFactory
import org.apache.sshd.netty.NettyIoSession
import java.lang.invoke.MethodHandles
import java.net.SocketAddress
import java.time.Duration

/**
 * The Netty based IoConnector implementation.
 *
 * @author [Apache MINA SSHD Project](mailto:dev@mina.apache.org)
 */
class NettySocksIoConnector(
    private val manager: FactoryManager,
    factory: NettyIoServiceFactory,
    handler: IoHandler,
    private val socks5: () -> Socks5ProxyHandler
) : NettyIoService(factory, handler), IoConnector {
    companion object {
        // Shared across all connectors
        private val LOGGING_TRACE = LoggingHandler(
            NettySocksIoConnector::class.java, LogLevel.TRACE
        )

        private val SESSION_ADAPTER_GETTER = NettyIoSession::class.java.getDeclaredField("adapter").also {
            it.isAccessible = true
        }.let { MethodHandles.lookup().unreflectGetter(it) }

        private val SERVICE_FACTORY_EVENTLOOP =
            NettyIoServiceFactory::class.java.getDeclaredField("eventLoopGroup").also {
                it.isAccessible = true
            }.let { MethodHandles.lookup().unreflectGetter(it) }
    }


    init {
        channelGroup = DefaultChannelGroup("sshd-connector-channels", GlobalEventExecutor.INSTANCE)
    }

    override fun connect(
        address: SocketAddress,
        context: AttributeRepository?,
        localAddress: SocketAddress?
    ): IoConnectFuture {
        if (log.isDebugEnabled) {
            log.debug("Connecting to {}", address)
        }

        val future: IoConnectFuture = DefaultIoConnectFuture(address, null)
        val bootstrap = Bootstrap().group(SERVICE_FACTORY_EVENTLOOP.invoke(factory) as NioEventLoopGroup)
            .channel(NioSocketChannel::class.java)
            .attr(CONNECT_FUTURE_KEY, future)
            .handler(object : ChannelInitializer<SocketChannel>() {
                @Throws(Exception::class)
                override fun initChannel(ch: SocketChannel) {
                    val listener = ioServiceEventListener
                    val local = ch.localAddress()
                    val remote = ch.remoteAddress()
                    try {
                        if (listener != null) {
                            try {
                                listener.connectionEstablished(this@NettySocksIoConnector, local, context, remote)
                            } catch (e: Exception) {
                                ch.close()
                                throw e
                            }
                        }

                        val session = NettyIoSession(this@NettySocksIoConnector, handler, null)
                        if (context != null) {
                            session.setAttribute(AttributeRepository::class.java, context)
                        }

                        val p = ch.pipeline()
                        p.addFirst(socks5())
                        p.addLast(LOGGING_TRACE) // TODO make this configurable
                        p.addLast(SESSION_ADAPTER_GETTER.invoke(session) as ChannelHandler)
                    } catch (e: Exception) {
                        if (listener != null) {
                            try {
                                listener.abortEstablishedConnection(
                                    this@NettySocksIoConnector,
                                    local,
                                    context,
                                    remote,
                                    e
                                )
                            } catch (exc: Exception) {
                                if (log.isDebugEnabled) {
                                    log.debug(
                                        ("initChannel(" + ch + ") listener=" + listener
                                            + " ignoring abort event exception"),
                                        exc
                                    )
                                }
                            }
                        }

                        throw e
                    }
                }
            })

        CoreModuleProperties.IO_CONNECT_TIMEOUT[manager].ifPresent { d: Duration ->
            if (d.isZero || d.isNegative) {
                return@ifPresent
            }
            var millis: Long
            millis = try {
                d.toMillis()
            } catch (e: ArithmeticException) {
                Int.MAX_VALUE.toLong()
            }
            if (millis > Int.MAX_VALUE) {
                millis = Int.MAX_VALUE.toLong()
            }
            bootstrap.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, millis.toInt())
        }
        val chf = if (localAddress != null) {
            bootstrap.connect(address, localAddress)
        } else {
            bootstrap.connect(address)
        }
        future.addListener { f: IoConnectFuture ->
            if (f.isCanceled) {
                if (chf.cancel(true) || chf.isCancelled) {
                    f.cancellation.setCanceled()
                }
            }
        }
        chf.addListener { cf: Future<in Void?> ->
            val t = cf.cause()
            if (t != null) {
                future.exception = t
            } else if (cf.isCancelled) {
                val cancellation = future.cancel()
                cancellation?.setCanceled()
            }
        }
        // The future is completed when the session gets a channelActivated event.
        return future
    }

}
