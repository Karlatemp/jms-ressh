package moe.karla.jmsressh.session

import org.apache.sshd.common.channel.Channel
import org.apache.sshd.common.channel.PtyMode
import org.apache.sshd.common.channel.RequestHandler
import org.apache.sshd.common.session.Session
import org.apache.sshd.server.channel.ChannelSession
import org.apache.sshd.server.channel.ChannelSessionFactory

class AdvancedChannelSession : ChannelSession() {
    var tColumns: Int = 0
    var tRows: Int = 0
    var tWidth: Int = 0
    var tHeight: Int = 0

    object Factory : ChannelSessionFactory() {
        override fun createChannel(session: Session?): Channel {
            return AdvancedChannelSession()
        }
    }

    override fun handlePtyReqParsed(
        term: String?,
        tColumns: Int,
        tRows: Int,
        tWidth: Int,
        tHeight: Int,
        ptyModes: MutableMap<PtyMode, Int>?
    ): RequestHandler.Result {
        this.tColumns = tColumns
        this.tRows = tRows
        this.tWidth = tWidth
        this.tHeight = tHeight
        super.handlePtyReqParsed(term, tColumns, tRows, tWidth, tHeight, ptyModes)


        return RequestHandler.Result.ReplySuccess
    }

    override fun handleWindowChangeParsed(tColumns: Int, tRows: Int, tWidth: Int, tHeight: Int): RequestHandler.Result {
        this.tColumns = tColumns
        this.tRows = tRows
        this.tWidth = tWidth
        this.tHeight = tHeight

        super.handleWindowChangeParsed(tColumns, tRows, tWidth, tHeight)


        return RequestHandler.Result.ReplySuccess
    }
}