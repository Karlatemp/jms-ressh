package moe.karla.jmsressh.command

import moe.karla.jmsressh.session.AdvancedChannelSession
import org.apache.sshd.client.session.ClientSession
import org.apache.sshd.common.channel.PtyChannelConfiguration
import org.apache.sshd.server.Environment

class ForwardedShellCommand : ForwardingExecutionCommand() {
    override fun createChannel(
        channel: AdvancedChannelSession,
        client: ClientSession,
        env: Environment,
    ): org.apache.sshd.client.channel.ChannelSession {
        return client.createShellChannel(PtyChannelConfiguration().apply {
            this.ptyType = env.env[Environment.ENV_TERM]

            this.ptyModes = env.ptyModes
            this.ptyLines = channel.tRows
            this.ptyColumns = channel.tColumns

            this.ptyWidth = channel.tWidth
            this.ptyHeight = channel.tHeight
        }, env.env)
    }
}