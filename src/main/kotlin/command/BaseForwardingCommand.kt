package moe.karla.jmsressh.command

import org.apache.sshd.common.channel.ChannelOutputStream
import org.apache.sshd.server.ExitCallback
import org.apache.sshd.server.command.Command
import java.io.InputStream
import java.io.OutputStream

abstract class BaseForwardingCommand : Command {
    @JvmField
    var inputStream: InputStream? = null

    @JvmField
    var outputStream: OutputStream? = null

    @JvmField
    var errorStream: OutputStream? = null

    @JvmField
    var exitCallback: ExitCallback? = null

    override fun setInputStream(`in`: InputStream?) {
        this.inputStream = `in`
    }

    override fun setOutputStream(out: OutputStream?) {
        this.outputStream = out
        (out as? ChannelOutputStream)?.isNoDelay = true
    }

    override fun setErrorStream(err: OutputStream?) {
        this.errorStream = err
        (err as? ChannelOutputStream)?.isNoDelay = true
    }

    override fun setExitCallback(callback: ExitCallback?) {
        this.exitCallback = callback
    }
}