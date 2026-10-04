package libmitm

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

class TunCoreTest {

    private data class TunPair(val core: TunCore, val toTun: PipedOutputStream, val fromTun: PipedInputStream)

    private fun newTun(): TunPair {
        val toTunOut = PipedOutputStream()
        val toTunIn = PipedInputStream(toTunOut, 65536)
        val fromTunOut = PipedOutputStream()
        val fromTunIn = PipedInputStream(fromTunOut, 65536)
        val core = TunCore(toTunIn, fromTunOut)
        core.start()
        Libmitm.drain()
        return TunPair(core, toTunOut, fromTunIn)
    }

    private fun readTunPacket(`in`: PipedInputStream): ByteArray {
        val framer = PacketFramer()
        val tmp = ByteArray(4096)
        val deadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < deadline) {
            if (`in`.available() > 0) {
                val n = `in`.read(tmp)
                val ps = framer.feed(tmp, 0, n)
                if (ps.isNotEmpty()) return ps[0]
            } else {
                Thread.sleep(10)
            }
        }
        throw AssertionError("timed out waiting for tun packet")
    }

    private fun gameUdp(srcIp: String, sport: Int, dstIp: String, dport: Int, payload: ByteArray): ByteArray {
        val s = InetAddress.getByName(srcIp).address
        val d = InetAddress.getByName(dstIp).address
        return buildIPv4(s, d, IpProto.UDP, buildUdp(sport, dport, payload, s, d, false), 1234)
    }

    private fun parseUdpFromTun(pkt: ByteArray): Triple<String, Int, ByteArray> {
        val ihl = (pkt[0].toInt() and 0x0F) * 4
        val total = getU16(pkt, 2)
        assertEquals(0, ipChecksum(pkt, 0, ihl))
        val srcIp = InetAddress.getByAddress(pkt.copyOfRange(12, 16)).hostAddress
        val udp = pkt.copyOfRange(ihl, total)
        val sport = getU16(udp, 0)
        val payload = udp.copyOfRange(8, udp.size)
        val dstIp = InetAddress.getByAddress(pkt.copyOfRange(16, 20)).hostAddress
        val check = pseudoChecksum(pkt.copyOfRange(12, 16), pkt.copyOfRange(16, 20), false, IpProto.UDP, udp)
        assertTrue(check == 0 || check == 0xFFFF)
        return Triple("$srcIp:$sport->$dstIp:${getU16(udp, 2)}", sport, payload)
    }

    @Test(timeout = 30000)
    fun rfc791ChecksumVector() {
        val hdr = byteArrayOf(
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
            0xC0.toByte(), 0xA8.toByte(), 0x00, 0x01, 0xC0.toByte(), 0xA8.toByte(), 0x00, 0xC7.toByte()
        )
        assertEquals(0xB861, ipChecksum(hdr, 0, hdr.size))
        putU16(hdr, 10, 0xB861)
        assertEquals(0, ipChecksum(hdr, 0, hdr.size))
    }

    private fun rakMagic(): ByteArray {
        return byteArrayOf(0x00, 0xFF.toByte(), 0xFF.toByte(), 0x00, 0xFE.toByte(), 0xFE.toByte(), 0xFE.toByte(), 0xFE.toByte(), 0xFD.toByte(), 0xFD.toByte(), 0xFD.toByte(), 0xFD.toByte(), 0x12, 0x34, 0x56, 0x78)
    }

    private fun openReq1(): ByteArray {
        val b = ByteArray(1 + 16 + 1 + 100)
        b[0] = 0x05
        System.arraycopy(rakMagic(), 0, b, 1, 16)
        return b
    }

    private fun openReq2(): ByteArray {
        val b = ByteArray(1 + 16 + 8 + 8)
        b[0] = 0x07
        System.arraycopy(rakMagic(), 0, b, 1, 16)
        return b
    }

    private fun connectedDatagram(seq: Int, payload: ByteArray): ByteArray {
        val frame = ByteArray(1 + 2 + 3 + 4 + payload.size)
        frame[0] = 0x60
        val bits = payload.size * 8
        frame[1] = ((bits ushr 8) and 0xFF).toByte()
        frame[2] = (bits and 0xFF).toByte()
        frame[9] = 0
        System.arraycopy(payload, 0, frame, 10, payload.size)
        val dg = ByteArray(4 + frame.size)
        dg[0] = 0x84.toByte()
        dg[1] = (seq and 0xFF).toByte()
        dg[2] = ((seq ushr 8) and 0xFF).toByte()
        dg[3] = ((seq ushr 16) and 0xFF).toByte()
        System.arraycopy(frame, 0, dg, 4, frame.size)
        return dg
    }

    private fun readDatagramFromTun(`in`: PipedInputStream): ByteArray {
        val deadline = System.currentTimeMillis() + 8000
        while (System.currentTimeMillis() < deadline) {
            val triple = parseUdpFromTun(readTunPacket(`in`))
            val id = triple.third[0].toInt() and 0xFF
            if (id in 0x80..0x8F) return triple.third
        }
        throw AssertionError("timed out waiting for raknet datagram")
    }

    private fun datagramPayload(dg: ByteArray): ByteArray {
        var pos = 4
        pos += 1
        val bitLen = ((dg[pos].toInt() and 0xFF) shl 8) or (dg[pos + 1].toInt() and 0xFF)
        pos += 2 + 3 + 4
        return dg.copyOfRange(pos, pos + (bitLen + 7) / 8)
    }

    @Test(timeout = 60000)
    fun gameUdpInterceptAndRewrite() {
        val t = newTun()
        try {
            t.toTun.write(gameUdp("10.13.37.2", 5000, "1.2.3.4", 19132, openReq1()))
            t.toTun.flush()
            assertEquals(0x06, parseUdpFromTun(readTunPacket(t.fromTun)).third[0].toInt() and 0xFF)
            t.toTun.write(gameUdp("10.13.37.2", 5000, "1.2.3.4", 19132, openReq2()))
            t.toTun.flush()
            assertEquals(0x08, parseUdpFromTun(readTunPacket(t.fromTun)).third[0].toInt() and 0xFF)
            val conn = Libmitm.pollConnection() ?: throw AssertionError("no connection offered")
            assertEquals("1.2.3.4", conn.localAddr)
            assertEquals(19132L, conn.localPort)
            assertEquals("10.13.37.2", conn.remoteAddr)
            assertEquals(5000L, conn.remotePort)
            assertEquals(11L, conn.version)
            val payload = "raknet-hello".toByteArray()
            t.toTun.write(gameUdp("10.13.37.2", 5000, "1.2.3.4", 19132, connectedDatagram(0, payload)))
            t.toTun.flush()
            assertArrayEquals(payload, conn.read())
            conn.write("raknet-world".toByteArray())
            assertArrayEquals("raknet-world".toByteArray(), datagramPayload(readDatagramFromTun(t.fromTun)))
            conn.close()
        } finally {
            t.core.close()
        }
    }

@Test(timeout = 60000)
    fun udpPassthrough() {
        val echo = DatagramSocket(0)
        val echoPort = echo.localPort
        val t = newTun()
        try {
            val recv = LinkedBlockingQueue<ByteArray>()
            val th = Thread {
                val b = ByteArray(2048)
                val p = DatagramPacket(b, b.size)
                echo.receive(p)
                recv.offer(p.data.copyOfRange(0, p.length))
                echo.send(DatagramPacket("echo-back".toByteArray(), 9, p.address, p.port))
            }
            th.isDaemon = true
            th.start()
            val payload = "ping-it".toByteArray()
            t.toTun.write(gameUdp("10.13.37.2", 6000, "127.0.0.1", echoPort, payload))
            t.toTun.flush()
            assertArrayEquals(payload, recv.poll(5, TimeUnit.SECONDS) ?: throw AssertionError("echo server got nothing"))
            val out = readTunPacket(t.fromTun)
            val (route, _, data) = parseUdpFromTun(out)
            assertTrue(route.endsWith("->10.13.37.2:6000"))
            assertArrayEquals("echo-back".toByteArray(), data)
        } finally {
            t.core.close()
            echo.close()
        }
    }

    @Test(timeout = 60000)
    fun customPortRakNetSniffIntercept() {
        val t = newTun()
        try {
            val ping = ByteArray(1 + 8 + 16 + 8)
            ping[0] = 0x01
            System.arraycopy(rakMagic(), 0, ping, 9, 16)
            t.toTun.write(gameUdp("10.13.37.2", 5001, "9.9.9.9", 22222, ping))
            t.toTun.flush()
            assertEquals(0x1C, parseUdpFromTun(readTunPacket(t.fromTun)).third[0].toInt() and 0xFF)
            t.toTun.write(gameUdp("10.13.37.2", 5001, "9.9.9.9", 22222, openReq1()))
            t.toTun.flush()
            assertEquals(0x06, parseUdpFromTun(readTunPacket(t.fromTun)).third[0].toInt() and 0xFF)
            t.toTun.write(gameUdp("10.13.37.2", 5001, "9.9.9.9", 22222, openReq2()))
            t.toTun.flush()
            assertEquals(0x08, parseUdpFromTun(readTunPacket(t.fromTun)).third[0].toInt() and 0xFF)
            val conn = Libmitm.pollConnection() ?: throw AssertionError("custom-port raknet not intercepted")
            assertEquals("9.9.9.9", conn.localAddr)
            assertEquals(22222L, conn.localPort)
            conn.close()
        } finally {
            t.core.close()
        }
    }

@Test(timeout = 60000)
    fun tcpRelayHandshakeAndData() {
        val server = ServerSocket(0)
        val port = server.localPort
        val got = LinkedBlockingQueue<ByteArray>()
        val th = Thread {
            val s = server.accept()
            val inp = s.getInputStream()
            val b = ByteArray(256)
            val n = inp.read(b)
            got.offer(b.copyOfRange(0, n))
            s.getOutputStream().write("serv-data".toByteArray())
            s.getOutputStream().flush()
            Thread.sleep(500)
            s.close()
        }
        th.isDaemon = true
        th.start()
        val t = newTun()
        try {
            val gIp = InetAddress.getByName("10.13.37.2").address
            val sIp = InetAddress.getByName("127.0.0.1").address
            val iss = 1000L
            fun tcpToTun(seq: Long, ack: Long, flags: Int, payload: ByteArray): ByteArray {
                val seg = buildTcp(7000, port, seq, ack, flags, 65535, payload, gIp, sIp, false)
                return buildIPv4(gIp, sIp, IpProto.TCP, seg, 77)
            }
            t.toTun.write(tcpToTun(iss, 0, TcpFlag.SYN, ByteArray(0)))
            t.toTun.flush()
            val synAck = readTcpFromTun(t.fromTun)
            assertEquals(TcpFlag.SYN or TcpFlag.ACK, synAck.flags)
            assertEquals(iss + 1, synAck.ack)
            t.toTun.write(tcpToTun(iss + 1, synAck.seq + 1, TcpFlag.ACK, "cli-data".toByteArray()))
            t.toTun.flush()
            assertArrayEquals("cli-data".toByteArray(), got.poll(5, TimeUnit.SECONDS) ?: throw AssertionError("server got nothing"))
            val dataPkt = readTcpFromTun(t.fromTun, skipPureAck = true)
            assertArrayEquals("serv-data".toByteArray(), dataPkt.payload)
            t.toTun.write(tcpToTun(iss + 1 + 8, dataPkt.seq + 9, TcpFlag.ACK or TcpFlag.FIN, ByteArray(0)))
            t.toTun.flush()
            val fin = readTcpFromTun(t.fromTun, skipPureAck = true)
            assertTrue((fin.flags and TcpFlag.FIN) != 0)
        } finally {
            t.core.close()
            server.close()
        }
    }

    private data class TcpSeg(val seq: Long, val ack: Long, val flags: Int, val payload: ByteArray)

    private fun readTcpFromTun(`in`: PipedInputStream, skipPureAck: Boolean = false): TcpSeg {
        val deadline = System.currentTimeMillis() + 8000
        val framer = PacketFramer()
        val tmp = ByteArray(4096)
        while (System.currentTimeMillis() < deadline) {
            if (`in`.available() > 0) {
                val n = `in`.read(tmp)
                for (pkt in framer.feed(tmp, 0, n)) {
                    if (((pkt[0].toInt() and 0xFF) ushr 4) != 4) continue
                    val ihl = (pkt[0].toInt() and 0x0F) * 4
                    if ((pkt[9].toInt() and 0xFF) != IpProto.TCP) continue
                    val total = getU16(pkt, 2)
                    val tcp = pkt.copyOfRange(ihl, total)
                    val hlen = ((tcp[12].toInt() and 0xFF) ushr 4) * 4
                    val flags = tcp[13].toInt() and 0xFF
                    val payload = tcp.copyOfRange(hlen, tcp.size)
                    if (skipPureAck && payload.isEmpty() && (flags and (TcpFlag.FIN or TcpFlag.RST)) == 0) continue
                    return TcpSeg(getU32(tcp, 4), getU32(tcp, 8), flags, payload)
                }
            } else {
                Thread.sleep(10)
            }
        }
        throw AssertionError("timed out waiting for tcp packet")
    }
}
