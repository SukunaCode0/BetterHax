package libmitm

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

internal object IpProto {
    const val UDP = 17
    const val TCP = 6
}

internal fun getU16(b: ByteArray, off: Int): Int = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

internal fun putU16(b: ByteArray, off: Int, v: Int) {
    b[off] = ((v ushr 8) and 0xFF).toByte()
    b[off + 1] = (v and 0xFF).toByte()
}

internal fun getU32(b: ByteArray, off: Int): Long =
    ((b[off].toLong() and 0xFF) shl 24) or ((b[off + 1].toLong() and 0xFF) shl 16) or
        ((b[off + 2].toLong() and 0xFF) shl 8) or (b[off + 3].toLong() and 0xFF)

internal fun putU32(b: ByteArray, off: Int, v: Long) {
    b[off] = ((v ushr 24) and 0xFF).toByte()
    b[off + 1] = ((v ushr 16) and 0xFF).toByte()
    b[off + 2] = ((v ushr 8) and 0xFF).toByte()
    b[off + 3] = (v and 0xFF).toByte()
}

internal fun ipChecksum(data: ByteArray, off: Int, len: Int): Int {
    var sum = 0L
    var i = off
    while (i + 1 < off + len) {
        sum += getU16(data, i).toLong()
        i += 2
    }
    if (i < off + len) sum += (data[i].toInt() and 0xFF) shl 8
    while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
    return (sum.inv() and 0xFFFF).toInt()
}

internal fun pseudoChecksum(src: ByteArray, dst: ByteArray, v6: Boolean, proto: Int, payload: ByteArray): Int {
    var sum = 0L
    fun addBytes(a: ByteArray) {
        var i = 0
        while (i + 1 < a.size) {
            sum += getU16(a, i).toLong()
            i += 2
        }
        if (i < a.size) sum += (a[i].toInt() and 0xFF) shl 8
    }
    addBytes(src)
    addBytes(dst)
    if (v6) {
        sum += payload.size.toLong()
        sum += proto.toLong()
    } else {
        sum += proto.toLong()
        sum += payload.size.toLong()
    }
    var i = 0
    while (i + 1 < payload.size) {
        sum += getU16(payload, i).toLong()
        i += 2
    }
    if (i < payload.size) sum += (payload[i].toInt() and 0xFF) shl 8
    while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
    val c = (sum.inv() and 0xFFFF).toInt()
    return if (!v6 && proto == IpProto.UDP && c == 0) 0xFFFF else c
}

internal fun buildIPv4(src: ByteArray, dst: ByteArray, proto: Int, payload: ByteArray, id: Int): ByteArray {
    val out = ByteArray(20 + payload.size)
    out[0] = 0x45.toByte()
    out[1] = 0.toByte()
    putU16(out, 2, out.size)
    putU16(out, 4, id and 0xFFFF)
    putU16(out, 6, 0x4000)
    out[8] = 64.toByte()
    out[9] = proto.toByte()
    putU16(out, 10, 0)
    System.arraycopy(src, 0, out, 12, 4)
    System.arraycopy(dst, 0, out, 16, 4)
    putU16(out, 10, ipChecksum(out, 0, 20))
    System.arraycopy(payload, 0, out, 20, payload.size)
    return out
}

internal fun buildIPv6(src: ByteArray, dst: ByteArray, nextHeader: Int, payload: ByteArray): ByteArray {
    val out = ByteArray(40 + payload.size)
    out[0] = 0x60.toByte()
    putU16(out, 4, payload.size)
    out[6] = nextHeader.toByte()
    out[7] = 64.toByte()
    System.arraycopy(src, 0, out, 8, 16)
    System.arraycopy(dst, 0, out, 24, 16)
    System.arraycopy(payload, 0, out, 40, payload.size)
    return out
}

internal fun buildUdp(srcPort: Int, dstPort: Int, payload: ByteArray, srcIp: ByteArray, dstIp: ByteArray, v6: Boolean): ByteArray {
    val out = ByteArray(8 + payload.size)
    putU16(out, 0, srcPort)
    putU16(out, 2, dstPort)
    putU16(out, 4, out.size)
    putU16(out, 6, 0)
    System.arraycopy(payload, 0, out, 8, payload.size)
    putU16(out, 6, pseudoChecksum(srcIp, dstIp, v6, IpProto.UDP, out))
    return out
}

internal object TcpFlag {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val ACK = 0x10
}

internal fun buildTcp(
    srcPort: Int, dstPort: Int, seq: Long, ack: Long, flags: Int,
    window: Int, payload: ByteArray, srcIp: ByteArray, dstIp: ByteArray, v6: Boolean, mss: Int = 0
): ByteArray {
    val optLen = if (mss > 0) 4 else 0
    val out = ByteArray(20 + optLen + payload.size)
    putU16(out, 0, srcPort)
    putU16(out, 2, dstPort)
    putU32(out, 4, seq)
    putU32(out, 8, ack)
    out[12] = (((20 + optLen) / 4) shl 4).toByte()
    out[13] = flags.toByte()
    putU16(out, 14, window)
    putU16(out, 16, 0)
    putU16(out, 18, 0)
    if (mss > 0) {
        out[20] = 2.toByte()
        out[21] = 4.toByte()
        putU16(out, 22, mss)
    }
    System.arraycopy(payload, 0, out, 20 + optLen, payload.size)
    putU16(out, 16, pseudoChecksum(srcIp, dstIp, v6, IpProto.TCP, out))
    return out
}

internal fun parseMss(tcp: ByteArray): Int {
    val hlen = ((tcp[12].toInt() and 0xFF) ushr 4) * 4
    var i = 20
    while (i + 1 < hlen) {
        val kind = tcp[i].toInt() and 0xFF
        if (kind == 0) break
        if (kind == 1) {
            i++
            continue
        }
        if (i + 1 >= tcp.size) break
        val l = tcp[i + 1].toInt() and 0xFF
        if (l < 2) break
        if (kind == 2 && l == 4 && i + 3 < tcp.size) return getU16(tcp, i + 2)
        i += l
    }
    return 0
}

internal data class FlowId(
    val v6: Boolean,
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int,
    val proto: Int
)

internal class PacketFramer {
    private val buf = ByteArrayOutputStream()
    fun feed(data: ByteArray, off: Int, len: Int): List<ByteArray> {
        buf.write(data, off, len)
        val out = mutableListOf<ByteArray>()
        while (true) {
            val b = buf.toByteArray()
            if (b.size < 20) return out
            val ver = (b[0].toInt() and 0xFF) ushr 4
            val need = when (ver) {
                4 -> {
                    if (b.size < 20) return out
                    getU16(b, 2)
                }
                6 -> {
                    if (b.size < 40) return out
                    40 + getU16(b, 4)
                }
                else -> return out
            }
            if (need <= 0 || need > 65575) {
                buf.reset()
                if (b.size > 1) buf.write(b, 1, b.size - 1)
                continue
            }
            if (b.size < need) return out
            out.add(b.copyOfRange(0, need))
            buf.reset()
            if (b.size > need) buf.write(b, need, b.size - need)
        }
    }
}

class TunCore(
    private val tunInput: InputStream,
    private val tunOutput: OutputStream,
    private val gamePorts: Set<Int> = setOf(19132, 19133)
) {
    var udpProtector: ((DatagramSocket) -> Boolean)? = null
    var tcpProtector: ((Socket) -> Boolean)? = null
    private val errorLogCount = AtomicInteger(0)
    private val running = AtomicBoolean(false)
    private val ipId = AtomicInteger(Random.nextInt(65536))
    private val threads = mutableListOf<Thread>()
    private val framer = PacketFramer()

    private data class GameFlow(val session: RakServerSession, var lastSeen: Long, val id: FlowId)
    private val gameFlows = ConcurrentHashMap<FlowId, GameFlow>()
    private val rakServerGuid = Random.nextLong() and Long.MAX_VALUE
    var logger: ((String) -> Unit)? = null
    private val gameInPkts = AtomicLong(0)
    private val gameInBytes = AtomicLong(0)
    private val gameOutPkts = AtomicLong(0)
    private val gameOutBytes = AtomicLong(0)
    private val relayErrs = AtomicLong(0)
    private val writeErrs = AtomicLong(0)
    @Volatile private var firstWriteErr: String? = null
    private val tcpHandshakes = AtomicLong(0)
    private val pingFwd = AtomicLong(0)
    private val pongReal = AtomicLong(0)
    @Volatile private var pingSock: DatagramSocket? = null
    private data class PingTarget(val clientIp: ByteArray, val clientPort: Int, val at: Long, val serverKey: String, val pingTs: Long)
    private val pingTargets = ConcurrentHashMap<String, PingTarget>()
    private val pingOutLogged = ConcurrentHashMap<String, Long>()
    private val pongInLogged = ConcurrentHashMap<String, Long>()
    private val pongHexKeys = ConcurrentHashMap<String, Long>()
    private val pongNoMatch = AtomicLong(0)
    private val pingV6drop = AtomicLong(0)

    private fun shouldLog(m: ConcurrentHashMap<String, Long>, key: String): Boolean {
        val now = System.currentTimeMillis()
        val last = m[key]
        if (last == null || now - last > 30000) {
            m[key] = now
            return true
        }
        return false
    }
    private val iface4: ByteArray by lazy { InetAddress.getByName("10.13.37.1").address }
    private val iface6: ByteArray by lazy { InetAddress.getByName("1337::1").address }
    private fun ifaceAddr(v6: Boolean): ByteArray = if (v6) iface6 else iface4
    private val ipInPkts = AtomicLong(0)

    private data class UdpFlow(val socket: DatagramSocket, var lastSeen: Long, val id: FlowId)
    private val udpFlows = ConcurrentHashMap<FlowId, UdpFlow>()

    private inner class TcpConn(val id: FlowId) {
        @Volatile var state = 0
        var socket: Socket? = null
        var iss: Long = Random.nextLong() and 0xFFFFFFFFL
        var sndUna: Long = 0
        var sndNxt: Long = 0
        var rcvNxt: Long = 0
        var appMss = 1360
        var closed = false
        var finSent = false
        var unackedSince: Long = 0
        var lastUnacked: ByteArray? = null
        var pendingAppData = ByteArray(0)
        var upBytes = 0L
        var dnBytes = 0L
        var dupAcks = 0L
        var dialMs = -1L
        val lock = Any()
    }

    private val tcpConns = ConcurrentHashMap<FlowId, TcpConn>()

    fun start() {
        if (!running.compareAndSet(false, true)) return
        spawn("reader") { readerLoop() }
        spawn("sweeper") { sweeperLoop() }
    }

    fun close() {
        if (!running.compareAndSet(true, false)) return
        try {
            tunInput.close()
        } catch (_: Throwable) {
        }
        try {
            tunOutput.close()
        } catch (_: Throwable) {
        }
        synchronized(threads) { threads.toList() }.forEach { it.interrupt() }
        gameFlows.values.forEach {
            try {
                it.session.shutdown()
            } catch (_: Throwable) {
            }
        }
        gameFlows.clear()
        udpFlows.values.forEach {
            try {
                it.socket.close()
            } catch (_: Throwable) {
            }
        }
        udpFlows.clear()
        try {
            pingSock?.close()
        } catch (_: Throwable) {
        }
        pingSock = null
        tcpConns.values.forEach { killTcp(it) }
        tcpConns.clear()
    }

    private fun spawn(name: String, block: () -> Unit) {
        val t = Thread({
            try {
                block()
            } catch (_: InterruptedException) {
            } catch (_: IOException) {
            } catch (t: Throwable) {
                if (errorLogCount.getAndIncrement() < 8) {
                    try {
                        android.util.Log.e("TunCore", "thread died: " + t.javaClass.simpleName + ": " + t.message)
                    } catch (_: Throwable) {
                    }
                }
            }
        }, "libmitm-$name")
        t.isDaemon = true
        synchronized(threads) { threads.add(t) }
        t.start()
    }

    private fun writeTun(pkt: ByteArray) {
        if (!running.get()) return
        synchronized(tunOutput) {
            try {
                tunOutput.write(pkt)
                tunOutput.flush()
            } catch (t: Throwable) {
                writeErrs.incrementAndGet()
                if (firstWriteErr == null) {
                    firstWriteErr = t.javaClass.simpleName + ":" + t.message
                }
            }
        }
    }

    private fun readerLoop() {
        val tmp = ByteArray(4096)
        while (running.get()) {
            val n = try {
                tunInput.read(tmp)
            } catch (_: IOException) {
                return
            }
            if (n < 0) return
            if (n == 0) continue
            val packets = try {
                framer.feed(tmp, 0, n)
            } catch (_: Throwable) {
                continue
            }
            for (p in packets) {
                ipInPkts.incrementAndGet()
                try {
                    handlePacket(p)
                } catch (_: Throwable) {
                }
            }
        }
    }

    private fun handlePacket(pkt: ByteArray) {
        if (pkt.isEmpty()) return
        when ((pkt[0].toInt() and 0xFF) ushr 4) {
            4 -> handleIPv4(pkt)
            6 -> handleIPv6(pkt)
        }
    }

    private fun handleIPv4(pkt: ByteArray) {
        if (pkt.size < 20) return
        val ihl = (pkt[0].toInt() and 0x0F) * 4
        if (pkt.size < ihl) return
        val total = getU16(pkt, 2)
        if (total > pkt.size || total < ihl) return
        if ((getU16(pkt, 6) and 0x1FFF) != 0) return
        val proto = pkt[9].toInt() and 0xFF
        val src = pkt.copyOfRange(12, 16)
        val dst = pkt.copyOfRange(16, 20)
        val payload = pkt.copyOfRange(ihl, total)
        when (proto) {
            IpProto.UDP -> handleUdp(false, src, dst, payload)
            IpProto.TCP -> handleTcp(false, src, dst, payload)
        }
    }

    private fun handleIPv6(pkt: ByteArray) {
        if (pkt.size < 40) return
        val payLen = getU16(pkt, 4)
        if (40 + payLen > pkt.size) return
        val next = pkt[6].toInt() and 0xFF
        if (next != IpProto.UDP && next != IpProto.TCP) return
        val src = pkt.copyOfRange(8, 24)
        val dst = pkt.copyOfRange(24, 40)
        val payload = pkt.copyOfRange(40, 40 + payLen)
        when (next) {
            IpProto.UDP -> handleUdp(true, src, dst, payload)
            IpProto.TCP -> handleTcp(true, src, dst, payload)
        }
    }

    private fun isBroadcastOrMulticast(v6: Boolean, dst: ByteArray): Boolean {
        if (!v6) {
            if (dst.all { it == 255.toByte() }) return true
            if ((dst[3].toInt() and 0xFF) == 255) return true
            val first = dst[0].toInt() and 0xFF
            if (first >= 224 && first <= 239) return true
            return false
        }
        return (dst[0].toInt() and 0xFF) == 0xFF
    }

    private val RAKNET_MAGIC = byteArrayOf(0x00, 0xFF.toByte(), 0xFF.toByte(), 0x00, 0xFE.toByte(), 0xFE.toByte(), 0xFE.toByte(), 0xFE.toByte(), 0xFD.toByte(), 0xFD.toByte(), 0xFD.toByte(), 0xFD.toByte(), 0x12, 0x34, 0x56, 0x78)

    private fun hasMagicAt(payload: ByteArray, off: Int): Boolean {
        if (payload.size < off + 16) return false
        for (i in RAKNET_MAGIC.indices) if (payload[off + i] != RAKNET_MAGIC[i]) return false
        return true
    }

    private fun isRakNet(payload: ByteArray): Boolean {
        if (payload.isEmpty()) return false
        return when (payload[0].toInt() and 0xFF) {
            0x01, 0x02 -> hasMagicAt(payload, 9)
            0x05, 0x06, 0x07, 0x08 -> hasMagicAt(payload, 1)
            0x00, 0x03, 0x04 -> hasMagicAt(payload, 1) || hasMagicAt(payload, 9)
            0xA0, 0xC0, in 0x80..0x8F -> true
            else -> false
        }
    }

    private fun ipStr(v6: Boolean, b: ByteArray): String = InetAddress.getByAddress(b).hostAddress

    private val dnsNames = java.util.concurrent.ConcurrentHashMap<String, String>()

    private fun noteDnsAnswers(payload: ByteArray) {
        try {
            if (payload.size < 13) return
            var p = 12
            var guard = 0
            fun skipName(): Boolean {
                while (p < payload.size && guard++ < 64) {
                    val l = payload[p].toInt() and 0xFF
                    if (l == 0) { p++; return true }
                    if ((l and 0xC0) == 0xC0) { p += 2; return true }
                    p += 1 + l
                }
                return false
            }
            fun readName(): String {
                val sb = StringBuilder()
                var pp = p
                var g2 = 0
                while (pp < payload.size && g2++ < 16) {
                    val l = payload[pp].toInt() and 0xFF
                    if (l == 0) break
                    if ((l and 0xC0) == 0xC0) {
                        val off = ((l and 0x3F) shl 8) or (payload[pp + 1].toInt() and 0xFF)
                        var qq = off
                        var g3 = 0
                        while (qq < payload.size && g3++ < 16) {
                            val l3 = payload[qq].toInt() and 0xFF
                            if (l3 == 0 || (l3 and 0xC0) == 0xC0) break
                            if (qq + 1 + l3 > payload.size) break
                            if (sb.isNotEmpty()) sb.append('.')
                            sb.append(String(payload, qq + 1, l3, Charsets.US_ASCII))
                            qq += 1 + l3
                        }
                        break
                    }
                    if (pp + 1 + l > payload.size) break
                    if (sb.isNotEmpty()) sb.append('.')
                    sb.append(String(payload, pp + 1, l, Charsets.US_ASCII))
                    pp += 1 + l
                }
                return sb.toString()
            }
            val qdCount = getU16(payload, 4)
            val anCount = getU16(payload, 6)
            var qname = ""
            var qi = 0
            while (qi < qdCount && p + 4 <= payload.size && guard++ < 64) {
                if (qi == 0) qname = readName()
                if (!skipName()) return
                if (p + 4 > payload.size) return
                p += 4
                qi++
            }
            if (qname.isEmpty()) return
            var n = 0
            while (n < anCount && p + 10 <= payload.size && guard++ < 256) {
                if (!skipName()) break
                if (p + 10 > payload.size) break
                val typ = getU16(payload, p)
                val rdLen = getU16(payload, p + 8)
                p += 10
                if (typ == 1 && rdLen == 4 && p + 4 <= payload.size) {
                    val ip = InetAddress.getByAddress(payload.copyOfRange(p, p + 4)).hostAddress
                    if (dnsNames.size > 512) dnsNames.clear()
                    dnsNames[ip] = qname
                }
                p += rdLen
                n++
            }
        } catch (_: Throwable) {
        }
    }

    private fun dnsName(payload: ByteArray): String {
        try {
            if (payload.size < 13) return "?"
            var p = 12
            val sb = StringBuilder()
            var guard = 0
            while (p < payload.size && guard++ < 32) {
                val l = payload[p].toInt() and 0xFF
                if (l == 0) break
                if ((l and 0xC0) == 0xC0) break
                if (p + 1 + l > payload.size) break
                if (sb.isNotEmpty()) sb.append('.')
                sb.append(String(payload, p + 1, l, Charsets.US_ASCII))
                p += 1 + l
            }
            return if (sb.isEmpty()) "?" else sb.toString()
        } catch (_: Throwable) {
            return "?"
        }
    }

    private fun addrBytes(s: String): ByteArray = InetAddress.getByName(s).address

    private fun wrap(v6: Boolean, src: ByteArray, dst: ByteArray, proto: Int, payload: ByteArray): ByteArray {
        return if (v6) buildIPv6(src, dst, proto, payload)
        else buildIPv4(src, dst, proto, payload, ipId.getAndIncrement())
    }

    private fun handleUdp(v6: Boolean, src: ByteArray, dst: ByteArray, udp: ByteArray) {
        if (udp.size < 8) return
        val sport = getU16(udp, 0)
        val dport = getU16(udp, 2)
        val payload = udp.copyOfRange(8, udp.size)
        val id = FlowId(v6, ipStr(v6, src), sport, ipStr(v6, dst), dport, IpProto.UDP)
        if (dport != 53 && dport != 443 && (dport in gamePorts || (!isBroadcastOrMulticast(v6, dst) && isRakNet(payload)))) {
            handleGameUdp(id, v6, src, dst, sport, dport, payload)
            return
        }
        var flow = udpFlows[id]
        if (flow == null) {
            pruneUdpFlows()
            val sock = try {
                DatagramSocket().also { s ->
                    try {
                        udpProtector?.invoke(s)
                    } catch (_: Throwable) {
                    }
                    try { s.receiveBufferSize = 1024 * 1024 } catch (_: Throwable) { }
                    try { s.sendBufferSize = 256 * 1024 } catch (_: Throwable) { }
                }
            } catch (_: Throwable) {
                return
            }
            flow = UdpFlow(sock, System.currentTimeMillis(), id)
            udpFlows[id] = flow
            val f = flow
            if (dport == 53) {
                try { logger?.invoke("dns.q " + dnsName(payload)) } catch (_: Throwable) { }
            }
            spawn("udp-fwd") { udpForwardLoop(f) }
            try {
                sock.send(DatagramPacket(payload, payload.size, InetAddress.getByAddress(dst), dport))
            } catch (_: Throwable) {
                udpFlows.remove(id)
                try {
                    sock.close()
                } catch (_: Throwable) {
                }
                return
            }
        } else {
            flow.lastSeen = System.currentTimeMillis()
            try {
                flow.socket.send(DatagramPacket(payload, payload.size, InetAddress.getByAddress(dst), dport))
            } catch (_: Throwable) {
            }
        }
    }

    private fun udpForwardLoop(flow: UdpFlow) {
        val buf = ByteArray(65535)
        while (running.get()) {
            val p = DatagramPacket(buf, buf.size)
            try {
                flow.socket.receive(p)
            } catch (_: Throwable) {
                return
            }
            flow.lastSeen = System.currentTimeMillis()
            val v6 = flow.id.v6
            val data = p.data.copyOfRange(0, p.length)
            if (flow.id.dstPort == 53) {
                try { logger?.invoke("dns.r " + data.size + "B") } catch (_: Throwable) { }
                try { noteDnsAnswers(data) } catch (_: Throwable) { }
            }
            val udp = buildUdp(p.port, flow.id.srcPort, data, p.address.address, addrBytes(flow.id.srcIp), v6)
            writeTun(wrap(v6, addrBytes(flow.id.dstIp), addrBytes(flow.id.srcIp), IpProto.UDP, udp))
        }
    }

    private fun pruneUdpFlows() {
        if (udpFlows.size <= 64) return
        val oldest = udpFlows.entries.minByOrNull { it.value.lastSeen } ?: return
        udpFlows.remove(oldest.key)
        try {
            oldest.value.socket.close()
        } catch (_: Throwable) {
        }
    }

    private fun pruneGameFlows() {
        if (gameFlows.size <= 32) return
        val oldest = gameFlows.entries.minByOrNull { it.value.lastSeen } ?: return
        gameFlows.remove(oldest.key)
        try {
            oldest.value.session.shutdown()
        } catch (_: Throwable) {
        }
    }

    internal fun flowLabel(id: FlowId): String {
        return id.dstIp + ":" + id.dstPort + (if (id.v6) "6" else "4")
    }

    private fun handleGameUdp(id: FlowId, v6: Boolean, src: ByteArray, dst: ByteArray, sport: Int, dport: Int, payload: ByteArray) {
        gameInPkts.incrementAndGet()
        gameInBytes.addAndGet(payload.size.toLong())
        if (payload.isNotEmpty() && (payload[0].toInt() and 0xFF) == 0x01) forwardPing(id, v6, src, dst, sport, dport, payload)
        var flow = gameFlows[id]
        if (flow == null) {
            pruneGameFlows()
            val conn = RakConn(11L, id.dstIp, dport.toLong(), id.srcIp, sport.toLong())
            val srcCopy = src.copyOf()
            val dstCopy = dst.copyOf()
            var sess: RakServerSession? = null
            sess = RakServerSession(conn, rakServerGuid, 1400, srcCopy, sport) { bytes ->
                if (bytes.isNotEmpty() && (bytes[0].toInt() and 0xFF) == 0x08) {
                    try { logger?.invoke("relay.offer " + id.dstIp + ":" + id.dstPort + " from=" + id.srcIp + ":" + id.srcPort) } catch (_: Throwable) { }
                }
                val f = gameFlows[id]
                if (f != null) {
                    f.lastSeen = System.currentTimeMillis()
                    val udp = buildUdp(dport, sport, bytes, dstCopy, srcCopy, v6)
                    gameOutPkts.incrementAndGet()
                    gameOutBytes.addAndGet(bytes.size.toLong())
                    writeTun(wrap(v6, dstCopy, srcCopy, IpProto.UDP, udp))
                }
            }
            conn.onWrite = { bytes ->
                try {
                    sess?.sendConnected(bytes)
                } catch (t: Throwable) {
                    val n = relayErrs.incrementAndGet()
                    if (n <= 4) try { logger?.invoke("relay.err out " + flowLabel(id) + " " + t.javaClass.simpleName) } catch (_: Throwable) { }
                }
            }
            conn.onClose = {
                try {
                    sess?.shutdown()
                } catch (_: Throwable) {
                }
                gameFlows.remove(id)
            }
            flow = GameFlow(sess, System.currentTimeMillis(), id)
            gameFlows[id] = flow
            try { val hx = payload.take(16).joinToString("") { "%02x".format(it) }; logger?.invoke("game.open " + flowLabel(id) + " src=" + id.srcIp + ":" + id.srcPort + " id=" + (payload[0].toInt() and 0xFF) + " hex=" + hx) } catch (_: Throwable) { }
        }
        flow.lastSeen = System.currentTimeMillis()
        try {
            flow.session.handleIncoming(payload)
        } catch (t: Throwable) {
            val n = relayErrs.incrementAndGet()
            if (n <= 4) try { logger?.invoke("relay.err in " + flowLabel(id) + " " + t.javaClass.simpleName) } catch (_: Throwable) { }
        }
    }

    private fun handleTcp(v6: Boolean, src: ByteArray, dst: ByteArray, tcp: ByteArray) {
        if (tcp.size < 20) return
        val sport = getU16(tcp, 0)
        val dport = getU16(tcp, 2)
        val seq = getU32(tcp, 4)
        val ack = getU32(tcp, 8)
        val flags = tcp[13].toInt() and 0xFF
        val hlen = ((tcp[12].toInt() and 0xFF) ushr 4) * 4
        if (tcp.size < hlen) return
        val payload = tcp.copyOfRange(hlen, tcp.size)
        val id = FlowId(v6, ipStr(v6, src), sport, ipStr(v6, dst), dport, IpProto.TCP)
        var conn = tcpConns[id]
        if (conn == null) {
            if (tcpConns.size > 256) {
                sendRst(v6, src, dst, sport, dport, 0, (seq + 1) and 0xFFFFFFFFL)
                return
            }
            if ((flags and TcpFlag.SYN) == 0) {
                sendRst(v6, src, dst, sport, dport, 0, (seq + 1) and 0xFFFFFFFFL)
                return
            }
            conn = TcpConn(id)
            tcpConns[id] = conn
            conn.rcvNxt = (seq + 1) and 0xFFFFFFFFL
            try { logger?.invoke("tcp.open " + id.dstIp + ":" + id.dstPort + (dnsNames[id.dstIp]?.let { "($it)" } ?: "")) } catch (_: Throwable) { }
            val m = parseMss(tcp)
            if (m > 0) conn.appMss = m.coerceIn(536, 1360)
            dialTcp(conn, v6, src.copyOf(), dst.copyOf(), sport, dport)
            synchronized(conn.lock) {
                conn.state = 1
                val synAck = buildTcp(dport, sport, conn.iss, conn.rcvNxt, TcpFlag.SYN or TcpFlag.ACK,
                    65535, ByteArray(0), dst, src, v6, mss = 1360)
                conn.sndNxt = (conn.iss + 1) and 0xFFFFFFFFL
                conn.unackedSince = System.currentTimeMillis()
                writeTun(wrap(v6, dst, src, IpProto.TCP, synAck))
            }
            return
        }
        synchronized(conn.lock) {
            if (conn.closed) return
            if ((flags and TcpFlag.RST) != 0) {
                try { logger?.invoke("tcp.rst-game " + id.dstIp + ":" + id.dstPort + " up=" + conn.upBytes + " dn=" + conn.dnBytes) } catch (_: Throwable) { }
                killTcp(conn)
                return
            }
            if (seq != conn.rcvNxt) {
                if ((flags and TcpFlag.SYN) != 0 && seq == ((conn.rcvNxt - 1) and 0xFFFFFFFFL)) {
                    val synAck = buildTcp(dport, sport, conn.iss, conn.rcvNxt, TcpFlag.SYN or TcpFlag.ACK,
                        65535, ByteArray(0), dst, src, v6, mss = 1360)
                    writeTun(wrap(v6, dst, src, IpProto.TCP, synAck))
                } else {
                    conn.dupAcks++
                    sendAck(conn, v6, src, dst, sport, dport)
                }
                return
            }
            if ((flags and TcpFlag.ACK) != 0 && conn.state == 1 && ack == conn.sndNxt) {
                conn.state = 2
                conn.sndUna = ack
                tcpHandshakes.incrementAndGet()
            } else if ((flags and TcpFlag.ACK) != 0) {
                advanceAck(conn, ack)
            }
            if (payload.isNotEmpty()) {
                conn.rcvNxt = (conn.rcvNxt + payload.size) and 0xFFFFFFFFL
                conn.upBytes += payload.size.toLong()
                val sock = conn.socket
                if (sock != null && conn.state == 2) {
                    try {
                        val o = sock.getOutputStream()
                        o.write(payload)
                        o.flush()
                    } catch (_: Throwable) {
                        sendRstConn(conn, v6, src, dst, sport, dport)
                        return
                    }
                } else {
                    if (conn.pendingAppData.size + payload.size > 65536) {
                        sendRstConn(conn, v6, src, dst, sport, dport)
                        return
                    }
                    conn.pendingAppData = conn.pendingAppData + payload
                }
            }
            if ((flags and TcpFlag.FIN) != 0) {
                conn.rcvNxt = (conn.rcvNxt + 1) and 0xFFFFFFFFL
                try { logger?.invoke("tcp.fin-game " + id.dstIp + ":" + id.dstPort + " up=" + conn.upBytes + " dn=" + conn.dnBytes) } catch (_: Throwable) { }
                try {
                    conn.socket?.shutdownOutput()
                } catch (_: Throwable) {
                }
            }
            if (conn.state == 2 || conn.state == 1) sendAck(conn, v6, src, dst, sport, dport)
        }
    }

    private fun advanceAck(conn: TcpConn, ack: Long) {
        val d1 = (ack - conn.sndUna) and 0xFFFFFFFFL
        val d2 = (conn.sndNxt - ack) and 0xFFFFFFFFL
        if (d1 < 0x80000000L && d2 < 0x80000000L) {
            conn.sndUna = ack
            if (ack == conn.sndNxt) {
                conn.unackedSince = 0
                conn.lastUnacked = null
            }
        }
    }

    private fun sendAck(conn: TcpConn, v6: Boolean, src: ByteArray, dst: ByteArray, sport: Int, dport: Int) {
        val seg = buildTcp(dport, sport, conn.sndNxt, conn.rcvNxt, TcpFlag.ACK, 65535,
            ByteArray(0), dst, src, v6)
        writeTun(wrap(v6, dst, src, IpProto.TCP, seg))
    }

    private fun sendRst(v6: Boolean, src: ByteArray, dst: ByteArray, sport: Int, dport: Int, seq: Long, ack: Long) {
        val seg = buildTcp(dport, sport, seq, ack, TcpFlag.RST or TcpFlag.ACK, 0, ByteArray(0), dst, src, v6)
        writeTun(wrap(v6, dst, src, IpProto.TCP, seg))
    }

    private fun sendRstConn(conn: TcpConn, v6: Boolean, src: ByteArray, dst: ByteArray, sport: Int, dport: Int) {
        sendRst(v6, src, dst, sport, dport, conn.sndNxt, conn.rcvNxt)
        killTcp(conn)
    }

    private fun dialTcp(conn: TcpConn, v6: Boolean, src: ByteArray, dst: ByteArray, sport: Int, dport: Int) {
        spawn("tcp-dial") {
            val t0 = System.currentTimeMillis()
            val sock = try {
                val s = Socket()
                s.tcpNoDelay = true
                try {
                    tcpProtector?.invoke(s)
                } catch (_: Throwable) {
                }
                s.connect(InetSocketAddress(InetAddress.getByAddress(dst), dport), 15000)
                s
            } catch (_: Throwable) {
                synchronized(conn.lock) {
                    if (!conn.closed && conn.socket == null) {
                        try { logger?.invoke("tcp.dialfail " + conn.id.dstIp + ":" + conn.id.dstPort) } catch (_: Throwable) { }
                        sendRst(v6, src, dst, sport, dport, 0, conn.rcvNxt)
                        killTcp(conn)
                    }
                }
                return@spawn
            }
            synchronized(conn.lock) {
                if (conn.closed) {
                    try {
                        sock.close()
                    } catch (_: Throwable) {
                    }
                    return@spawn
                }
                conn.dialMs = System.currentTimeMillis() - t0
                try { logger?.invoke("tcp.connected " + conn.id.dstIp + ":" + conn.id.dstPort + " dialMs=" + conn.dialMs) } catch (_: Throwable) { }
                conn.socket = sock
                if (conn.pendingAppData.isNotEmpty()) {
                    try {
                        val o = sock.getOutputStream()
                        o.write(conn.pendingAppData)
                        o.flush()
                        conn.pendingAppData = ByteArray(0)
                    } catch (_: Throwable) {
                        sendRstConn(conn, v6, src, dst, sport, dport)
                        return@spawn
                    }
                }
                if (conn.state == 2) {
                    try {
                        conn.socket?.shutdownOutput()
                    } catch (_: Throwable) {
                    }
                }
            }
            spawn("tcp-read") { tcpReadLoop(conn) }
        }
    }

    private fun tcpReadLoop(conn: TcpConn) {
        val id = conn.id
        val v6 = id.v6
        val src = addrBytes(id.srcIp)
        val dst = addrBytes(id.dstIp)
        val buf = ByteArray(1360)
        while (running.get()) {
            val sock = synchronized(conn.lock) { conn.socket } ?: return
            val n = try {
                sock.getInputStream().read(buf)
            } catch (_: Throwable) {
                break
            }
            if (n < 0) break
            if (n == 0) continue
            val data = buf.copyOfRange(0, n)
            var first = false
            val seg = synchronized(conn.lock) {
                if (conn.closed || conn.state != 2) {
                    null
                } else {
                    val s = buildTcp(id.dstPort, id.srcPort, conn.sndNxt, conn.rcvNxt,
                        TcpFlag.ACK, 65535, data, dst, src, v6)
                    conn.sndNxt = (conn.sndNxt + data.size) and 0xFFFFFFFFL
                    if (conn.dnBytes == 0L) first = true
                    conn.dnBytes += data.size.toLong()
                    conn.unackedSince = System.currentTimeMillis()
                    conn.lastUnacked = wrap(v6, dst, src, IpProto.TCP, s)
                    conn.lastUnacked
                }
            } ?: continue
            if (first) try { logger?.invoke("tcp.dn-first " + id.dstIp + ":" + id.dstPort + " len=" + data.size) } catch (_: Throwable) { }
            writeTun(seg)
        }
        synchronized(conn.lock) {
            if (conn.closed) return
            if (conn.state == 2 && !conn.finSent) {
                conn.finSent = true
                val seg = buildTcp(id.dstPort, id.srcPort, conn.sndNxt, conn.rcvNxt,
                    TcpFlag.FIN or TcpFlag.ACK, 65535, ByteArray(0), dst, src, v6)
                conn.sndNxt = (conn.sndNxt + 1) and 0xFFFFFFFFL
                conn.lastUnacked = wrap(v6, dst, src, IpProto.TCP, seg)
                writeTun(conn.lastUnacked!!)
            }
        }
    }

    private fun killTcp(conn: TcpConn) {
        synchronized(conn.lock) {
            if (conn.closed) return
            conn.closed = true
            try { logger?.invoke("tcp.close " + conn.id.dstIp + ":" + conn.id.dstPort + " up=" + conn.upBytes + " dn=" + conn.dnBytes + " dup=" + conn.dupAcks + " dialMs=" + conn.dialMs) } catch (_: Throwable) { }
            try {
                conn.socket?.close()
            } catch (_: Throwable) {
            }
        }
        tcpConns.remove(conn.id)
    }

    private fun getPingSock(): DatagramSocket? {
        var s = pingSock
        if (s == null) {
            synchronized(this) {
                s = pingSock
                if (s == null) {
                    try {
                        val ns = DatagramSocket()
                        try {
                            ns.broadcast = true
                        } catch (_: Throwable) {
                        }
                        try { ns.receiveBufferSize = 1024 * 1024 } catch (_: Throwable) { }
                        try { ns.sendBufferSize = 256 * 1024 } catch (_: Throwable) { }
                        try {
                            udpProtector?.invoke(ns)
                        } catch (_: Throwable) {
                        }
                        pingSock = ns
                        s = ns
                        spawn("ping-relay") { pingRelayLoop(ns) }
                    } catch (_: Throwable) {
                        return null
                    }
                }
            }
        }
        return s
    }

    private fun forwardPing(id: FlowId, v6: Boolean, src: ByteArray, dst: ByteArray, sport: Int, dport: Int, payload: ByteArray) {
        if (v6) {
            val n = pingV6drop.incrementAndGet()
            if (n <= 4) try { logger?.invoke("ping.v6drop " + id.dstIp + ":" + id.dstPort) } catch (_: Throwable) { }
            return
        }
        try {
            val sock = getPingSock() ?: return
            if (pingTargets.size > 256) { pingTargets.clear(); pingOutLogged.clear(); pongInLogged.clear(); pongHexKeys.clear() }
            val key = id.dstIp + ":" + id.dstPort
            val pts = try { if (payload.size >= 9) getU64Be(payload, 1) else -1L } catch (_: Throwable) { -1L }
            pingTargets[key] = PingTarget(src.copyOf(), sport, System.currentTimeMillis(), key, pts)
            if (shouldLog(pingOutLogged, key)) {
                val phex = try { payload.take(33).joinToString("") { "%02x".format(it) } } catch (_: Throwable) { "?" }
                try { logger?.invoke("ping.out " + key + " ts=" + pts + " hex=" + phex) } catch (_: Throwable) { }
            }
            sock.send(DatagramPacket(payload, payload.size, InetAddress.getByAddress(dst), dport))
            pingFwd.incrementAndGet()
        } catch (_: Throwable) {
        }
    }

    private fun pingRelayLoop(sock: DatagramSocket) {
        val buf = ByteArray(2048)
        while (running.get()) {
            val p = DatagramPacket(buf, buf.size)
            try {
                sock.receive(p)
            } catch (_: Throwable) {
                return
            }
            if (p.length < 1 || (p.data[0].toInt() and 0xFF) != 0x1C) continue
            try {
                val rip = p.address.hostAddress
                val nowMs = System.currentTimeMillis()
                val tg0: PingTarget? = pingTargets[rip + ":" + p.port]
                    ?: pingTargets.entries.firstOrNull { it.key.startsWith(rip + ":") && nowMs - it.value.at < 3000 }?.value
                    ?: pingTargets.entries.filter { nowMs - it.value.at < 1500 }.maxByOrNull { it.value.at }?.let {
                        if (shouldLog(pongInLogged, it.key + "|redir")) try { logger?.invoke("pong.redir " + it.key + " rip=" + rip + ":" + p.port) } catch (_: Throwable) { }
                        it.value
                    }
                if (tg0 == null) {
                    val n = pongNoMatch.incrementAndGet()
                    if (n <= 6) try { logger?.invoke("pong.nomatch " + rip + ":" + p.port) } catch (_: Throwable) { }
                    continue
                }
                val tgv = tg0
                if (nowMs - tgv.at > 3000) continue
                val data = p.data.copyOfRange(0, p.length)
                if (shouldLog(pongHexKeys, tgv.serverKey)) {
                    try {
                        val rts = if (data.size >= 9) getU64Be(data, 1) else -1L
                        val rguid = if (data.size >= 17) getU64Be(data, 9) else -1L
                        var magicOk = false
                        var mhex = "?"
                        if (data.size >= 33) {
                            mhex = data.copyOfRange(17, 33).joinToString("") { "%02x".format(it) }
                            magicOk = true
                            for (i in RAKNET_MAGIC.indices) if (data[17 + i] != RAKNET_MAGIC[i]) { magicOk = false; break }
                        }
                        val mlen = if (data.size >= 35) getU16(data, 33) else -1
                        try { logger?.invoke("pong.hex " + tgv.serverKey + " len=" + data.size + " ts=" + rts + " tsMatch=" + (rts == tgv.pingTs) + " guid=" + rguid + " magicOk=" + magicOk + " mhex=" + mhex + " mlen=" + mlen + " remain=" + (data.size - 35)) } catch (_: Throwable) { }
                    } catch (_: Throwable) {
                    }
                }
                if (shouldLog(pongInLogged, tgv.serverKey)) {
                    val motd = try {
                        if (data.size > 35) {
                            val mlen = getU16(data, 33)
                            String(data, 35, minOf(35 + mlen, data.size) - 35, Charsets.UTF_8).take(120)
                        } else "?"
                    } catch (_: Throwable) { "?" }
                    try { logger?.invoke("pong.in " + tgv.serverKey + " rip=" + rip + ":" + p.port + " ageMs=" + (nowMs - tgv.at) + " motd=" + motd) } catch (_: Throwable) { }
                }
                Libmitm.markReal(tgv.serverKey)
                Libmitm.markReal(rip + ":" + p.port)
                val expIpStr = tgv.serverKey.substringBeforeLast(":")
                val expIp = try { InetAddress.getByName(expIpStr).address } catch (_: Throwable) { p.address.address }
                val udp = buildUdp(p.port, tgv.clientPort, data, expIp, tgv.clientIp, false)
                pongReal.incrementAndGet()
                writeTun(buildIPv4(expIp, tgv.clientIp, IpProto.UDP, udp, ipId.getAndIncrement()))
            } catch (_: Throwable) {
            }
        }
    }

    private fun sweeperLoop() {
        var tick = 0
        while (running.get()) {
            try {
                Thread.sleep(500)
            } catch (_: InterruptedException) {
                return
            }
            val now = System.currentTimeMillis()
            udpFlows.entries.removeIf {
                if (now - it.value.lastSeen > 30000) {
                    try {
                        it.value.socket.close()
                    } catch (_: Throwable) {
                    }
                    true
                } else false
            }
            gameFlows.entries.removeIf {
                if (now - it.value.lastSeen > 600000) {
                    try {
                        it.value.session.shutdown()
                    } catch (_: Throwable) {
                    }
                    true
                } else false
            }
            for (f in gameFlows.values) {
                try {
                    f.session.tick(now)
                } catch (_: Throwable) {
                }
            }
            tick++
            if (tick % 60 == 0) {
                try {
                    var din = 0L
                    var dout = 0L
                    var pin = 0L
                    var pout = 0L
                    for (f in gameFlows.values) {
                        din += f.session.datagramsIn
                        dout += f.session.datagramsOut
                        pin += f.session.payloadsIn
                        pout += f.session.payloadsOut
                    }
                    try {
                        val det = gameFlows.values.take(4).joinToString(" ") { flowLabel(it.id) + ":" + it.session.idSummary() }
                        logger?.invoke("rakdetail " + det + " werr=" + writeErrs.get() + (if (firstWriteErr != null) ":" + firstWriteErr else "") + " tcphs=" + tcpHandshakes.get())
                    } catch (_: Throwable) {
                    }
                    logger?.invoke("rakstat flows=" + gameFlows.size + " udp=" + udpFlows.size + " tcp=" + tcpConns.size +
                        " ipin=" + ipInPkts.get() +
                        " gin=" + gameInPkts.get() + "/" + (gameInBytes.get() / 1024) + "KB" +
                        " gout=" + gameOutPkts.get() + "/" + (gameOutBytes.get() / 1024) + "KB" +
                        " din=" + din + " dout=" + dout + " pin=" + pin + " pout=" + pout +
                        " pfwd=" + pingFwd.get() + " preal=" + pongReal.get() + " dual=1")
                } catch (_: Throwable) {
                }
            }
            for (conn in tcpConns.values) {
                var resend: ByteArray? = null
                var giveUp = false
                synchronized(conn.lock) {
                    if (!conn.closed && conn.unackedSince != 0L && now - conn.unackedSince > 1000) {
                        if (now - conn.unackedSince > 30000) {
                            giveUp = true
                        } else {
                            resend = conn.lastUnacked
                            conn.unackedSince = now
                        }
                    }
                }
                if (giveUp) {
                    try { logger?.invoke("tcp.giveup " + conn.id.dstIp + ":" + conn.id.dstPort + " up=" + conn.upBytes + " dn=" + conn.dnBytes + " dup=" + conn.dupAcks + " dialMs=" + conn.dialMs) } catch (_: Throwable) { }
                    killTcp(conn)
                } else if (resend != null) {
                    writeTun(resend!!)
                }
            }
        }
    }
}
