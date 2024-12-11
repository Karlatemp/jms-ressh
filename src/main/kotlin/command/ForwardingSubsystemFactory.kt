package moe.karla.jmsressh.command

import org.apache.sshd.server.channel.ChannelSession
import org.apache.sshd.server.command.Command
import org.apache.sshd.server.subsystem.SubsystemFactory

class ForwardingSubsystemFactory(
    private val name: String
) : SubsystemFactory {
    override fun getName(): String = name

    override fun createSubsystem(channel: ChannelSession?): Command = ForwardingSubsystemCommand(name)
}