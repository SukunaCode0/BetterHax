package libmitm

import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

object Libmitm {
    const val IPv6Enable = 0
    const val IPv6Disable = 1
    const val IPv6Only = 2

    private val pending = LinkedBlockingQueue<RakConn>()

    @JvmStatic
    fun pollConnection(): RakConn? {
        return try {
            pending.take()
        } catch (_: InterruptedException) {
            null
        }
    }

    internal fun offer(conn: RakConn) {
        pending.offer(conn)
    }

    internal fun drain() {
        pending.clear()
    }

    private val realSeen = java.util.concurrent.ConcurrentHashMap<String, Long>()

    fun markReal(k: String) {
        if (realSeen.size > 512) realSeen.clear()
        realSeen[k] = System.currentTimeMillis()
    }

    fun hasReal(k: String): Boolean {
        val t = realSeen[k] ?: return false
        if (System.currentTimeMillis() - t > 120000) {
            realSeen.remove(k)
            return false
        }
        return true
    }
}
