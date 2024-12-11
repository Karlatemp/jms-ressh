package moe.karla.jmsressh.command

import moe.karla.jmsressh.forwardClientAttr
import moe.karla.jmsressh.session.AdvancedChannelSession
import org.apache.sshd.client.channel.ChannelSession
import org.apache.sshd.client.channel.ChannelShell
import org.apache.sshd.client.session.ClientSession
import org.apache.sshd.common.SshConstants
import org.apache.sshd.common.channel.Channel
import org.apache.sshd.common.channel.ChannelListener
import org.apache.sshd.common.session.Session
import org.apache.sshd.server.Environment
import org.apache.sshd.server.Signal

abstract class ForwardingExecutionCommand : BaseForwardingCommand() {
    private lateinit var executionSession: ChannelSession

    abstract fun createChannel(
        channel: AdvancedChannelSession,
        client: ClientSession,
        env: Environment,
    ): ChannelSession

    override fun start(channel: org.apache.sshd.server.channel.ChannelSession, env: Environment) {
        channel as AdvancedChannelSession

        val client = channel.session.getAttribute(forwardClientAttr)

        executionSession = createChannel(channel, client, env)

        executionSession.out = this.outputStream
        executionSession.err = this.errorStream
        executionSession.`in` = this.inputStream

        runCatching {
            executionSession.open().verify()

            env.addSignalListener { _, signal ->
                when (signal) {
                    Signal.WINCH -> {
                        (executionSession as? ChannelShell)?.sendWindowChange(
                            channel.tColumns,
                            channel.tRows,
                            channel.tHeight,
                            channel.tWidth,
                        )
                    }
                    Signal.INT -> {
                        val session: Session = executionSession.session
                        val buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_REQUEST, java.lang.Long.SIZE)
                        buffer.putUInt(executionSession.recipient)
                        buffer.putString("break")
                        buffer.putBoolean(false) // want-reply
                        buffer.putInt(0) // breakLength
                        executionSession.writePacket(buffer)
                    }
                    else -> {
                        val session: Session = executionSession.session
                        val buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_REQUEST, java.lang.Long.SIZE)
                        buffer.putUInt(executionSession.recipient)
                        buffer.putString("signal")
                        buffer.putBoolean(false) // want-reply
                        buffer.putString(signal.name)
                        executionSession.writePacket(buffer)
                    }
                }
            }
            executionSession.addChannelListener(object : ChannelListener {
                override fun channelClosed(channel: Channel?, reason: Throwable?) {
                    println("Closed")

                    exitCallback?.onExit(executionSession.exitStatus ?: -1)
                }
            })
        }.onFailure {
            exitCallback?.onExit(666, it.message)
        }
    }

    override fun destroy(channel: org.apache.sshd.server.channel.ChannelSession) {
        executionSession.close()
    }
}