package libmitm

import java.io.IOException
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class RakConn(
    val version: Long,
    val localAddr: String,
    val localPort: Long,
    val remoteAddr: String,
    val remotePort: Long
) {
    private val open = AtomicBoolean(true)
    private val inbound = LinkedBlockingQueue<ByteArray>()
    internal var onWrite: (ByteArray) -> Unit = {}
    internal var onClose: () -> Unit = {}

    val isOpen: Boolean get() = open.get()

    fun read(): ByteArray {
        while (true) {
            if (!open.get()) throw IOException("connection closed")
            val b = inbound.poll(200, TimeUnit.MILLISECONDS)
            if (b != null) return b
        }
    }

    fun write(data: ByteArray) {
        if (!open.get()) return
        try {
            onWrite(data)
        } catch (_: Throwable) {
        }
    }

    internal fun push(data: ByteArray) {
        if (!open.get()) return
        while (inbound.size > 128) inbound.poll()
        inbound.offer(data)
    }

    fun close() {
        if (open.compareAndSet(true, false)) {
            try {
                onClose()
            } catch (_: Throwable) {
            }
        }
    }
}
