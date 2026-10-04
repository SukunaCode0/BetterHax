package libmitm

import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream

class TUN {
    var fileDescriber: Int = -1
    var mtu: Int = 1500
    var iPv6Config: Int = Libmitm.IPv6Disable
    var logger: ((String) -> Unit)? = null
        set(v) {
            field = v
            try {
                core?.logger = v
            } catch (_: Throwable) {
            }
        }
    private var udpProtector: ((java.net.DatagramSocket) -> Boolean)? = null
    private var tcpProtector: ((java.net.Socket) -> Boolean)? = null

    private var core: TunCore? = null
    private var pfd: ParcelFileDescriptor? = null

    constructor()

    constructor(input: InputStream, output: OutputStream) {
        core = TunCore(input, output)
    }

    fun setProtectors(udp: ((java.net.DatagramSocket) -> Boolean)?, tcp: ((java.net.Socket) -> Boolean)?) {
        udpProtector = udp
        tcpProtector = tcp
        core?.let {
            it.udpProtector = udp
            it.tcpProtector = tcp
        }
    }

    private fun log(s: String) {
        try {
            logger?.invoke(s)
        } catch (_: Throwable) {
        }
    }

    @Synchronized
    fun start() {
        log("tun.start-enter")
        if (core != null) {
            log("tun.core-reuse")
            core!!.start()
            log("tun.started-reused")
            return
        }
        if (fileDescriber < 0) throw IllegalStateException("fileDescriber not set")
        log("tun.adopt-try fd=" + fileDescriber)
        val p = ParcelFileDescriptor.adoptFd(fileDescriber)
        pfd = p
        log("tun.adopt-ok")
        core = TunCore(FileInputStream(p.fileDescriptor), FileOutputStream(p.fileDescriptor))
        core!!.udpProtector = udpProtector
        core!!.tcpProtector = tcpProtector
        core!!.logger = logger
        log("tun.core-ok")
        core!!.start()
        log("tun.core-started")
    }

    @Synchronized
    fun close() {
        try {
            core?.close()
        } catch (_: Throwable) {
        }
        core = null
        try {
            pfd?.close()
        } catch (_: Throwable) {
        }
        pfd = null
    }
}
