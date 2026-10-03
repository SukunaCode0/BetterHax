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

    private var core: TunCore? = null
    private var pfd: ParcelFileDescriptor? = null

    constructor()

    constructor(input: InputStream, output: OutputStream) {
        core = TunCore(input, output)
    }

    @Synchronized
    fun start() {
        if (core != null) {
            core!!.start()
            return
        }
        if (fileDescriber < 0) throw IllegalStateException("fileDescriber not set")
        val p = ParcelFileDescriptor.adoptFd(fileDescriber)
        pfd = p
        core = TunCore(FileInputStream(p.fileDescriptor), FileOutputStream(p.fileDescriptor))
        core!!.start()
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
