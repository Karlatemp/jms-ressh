package moe.karla.jmsressh.command

import moe.karla.jmsressh.session.AdvancedChannelSession
import org.apache.sshd.client.session.ClientSession
import org.apache.sshd.server.Environment

class ForwardingSubsystemCommand(
    private val name: String,
) : ForwardingExecutionCommand() {
    override fun createChannel(
        channel: AdvancedChannelSession,
        client: ClientSession,
        env: Environment,
    ): org.apache.sshd.client.channel.ChannelSession {
        return client.createSubsystemChannel(name)
    }
}