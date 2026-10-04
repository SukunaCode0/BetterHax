package libmitm

internal fun getU16Le(b: ByteArray, off: Int): Int =
    (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8)

internal fun putU16Le(b: ByteArray, off: Int, v: Int) {
    b[off] = (v and 0xFF).toByte()
    b[off + 1] = ((v ushr 8) and 0xFF).toByte()
}

internal fun getU24Le(b: ByteArray, off: Int): Int =
    (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8) or ((b[off + 2].toInt() and 0xFF) shl 16)

internal fun putU24Le(b: ByteArray, off: Int, v: Int) {
    b[off] = (v and 0xFF).toByte()
    b[off + 1] = ((v ushr 8) and 0xFF).toByte()
    b[off + 2] = ((v ushr 16) and 0xFF).toByte()
}

internal fun getU32Le(b: ByteArray, off: Int): Long =
    (b[off].toLong() and 0xFF) or ((b[off + 1].toLong() and 0xFF) shl 8) or
        ((b[off + 2].toLong() and 0xFF) shl 16) or ((b[off + 3].toLong() and 0xFF) shl 24)

internal fun putU32Le(b: ByteArray, off: Int, v: Long) {
    b[off] = (v and 0xFF).toByte()
    b[off + 1] = ((v ushr 8) and 0xFF).toByte()
    b[off + 2] = ((v ushr 16) and 0xFF).toByte()
    b[off + 3] = ((v ushr 24) and 0xFF).toByte()
}

internal fun putU64Be(b: ByteArray, off: Int, v: Long) {
    putU32(b, off, (v ushr 32) and 0xFFFFFFFFL)
    putU32(b, off + 4, v and 0xFFFFFFFFL)
}

internal fun getU64Be(b: ByteArray, off: Int): Long =
    (getU32(b, off) shl 32) or getU32(b, off + 4)

private val RAK_MAGIC_OUT = byteArrayOf(
    0x00, 0xFF.toByte(), 0xFF.toByte(), 0x00,
    0xFE.toByte(), 0xFE.toByte(), 0xFE.toByte(), 0xFE.toByte(),
    0xFD.toByte(), 0xFD.toByte(), 0xFD.toByte(), 0xFD.toByte(),
    0x12, 0x34, 0x56, 0x78
)

private const val RELIABLE_ORDERED = 3

class RakServerSession(
    val conn: RakConn,
    private val serverGuid: Long,
    private val mtu: Int = 1400,
    private val clientIp: ByteArray,
    private val clientPort: Int,
    private val sender: (ByteArray) -> Unit
) {
    private val lock = Any()
    private var offered = false
    private var closed = false
    private var sendSeq = 0
    private var msgIndex = 0
    private var orderIndex = 0
    private var splitId = 0

    private data class Pending(val bytes: ByteArray, var sentAt: Long, var resends: Int)
    private val unacked = LinkedHashMap<Int, Pending>()
    private val pendingAcks = LinkedHashSet<Int>()
    private val seenSeqs = LinkedHashSet<Int>()

    private data class SplitBuf(val count: Int, val parts: Array<ByteArray?>, var arrived: Int, var updatedAt: Long)
    private val splits = HashMap<Int, SplitBuf>()

    var datagramsIn = 0L
    var datagramsOut = 0L
    var payloadsIn = 0L
    var payloadsOut = 0L
    var offeredAt = 0L

    @Volatile
    var lastActivity = System.currentTimeMillis()

    fun handleIncoming(d: ByteArray) {
        if (d.isEmpty() || closed) return
        lastActivity = System.currentTimeMillis()
        when (d[0].toInt() and 0xFF) {
            0x01, 0x02 -> handlePing(d)
            0x05 -> handleOpen1(d)
            0x07 -> handleOpen2(d)
            0x00 -> handleConnectedPing(d)
            0x15 -> shutdown()
            0xC0 -> handleAckNack(d, true)
            0xA0 -> handleAckNack(d, false)
            in 0x80..0x8F -> handleDatagram(d)
            else -> {
            }
        }
    }

    private fun sendRaw(bytes: ByteArray) {
        try {
            sender(bytes)
        } catch (_: Throwable) {
        }
    }

    private fun handlePing(d: ByteArray) {
        if (d.size < 1 + 8 + 16) return
        val time = getU64Be(d, 1)
        val pongStr = ("MCPE;BetterHax Relay;748;1.26.50;0;20;" + serverGuid +
            ";Bedrock level;Survival;1;19132;19132;").toByteArray(Charsets.UTF_8)
        val out = ByteArray(1 + 8 + 8 + 16 + pongStr.size)
        out[0] = 0x1C.toByte()
        putU64Be(out, 1, time)
        putU64Be(out, 9, serverGuid)
        System.arraycopy(RAK_MAGIC_OUT, 0, out, 17, 16)
        System.arraycopy(pongStr, 0, out, 33, pongStr.size)
        sendRaw(out)
    }

    private fun handleOpen1(d: ByteArray) {
        if (d.size < 1 + 16 + 1) return
        val clientMtu = (d.size + 28).coerceIn(400, 1500)
        val serverMtu = minOf(clientMtu, mtu)
        val out = ByteArray(1 + 16 + 8 + 1 + 2)
        out[0] = 0x06.toByte()
        System.arraycopy(RAK_MAGIC_OUT, 0, out, 1, 16)
        putU64Be(out, 17, serverGuid)
        out[25] = 0
        putU16(out, 26, serverMtu)
        sendRaw(out)
    }

    private fun handleOpen2(d: ByteArray) {
        if (d.size < 1 + 16 + 8) return
        val out = ByteArray(1 + 16 + 8 + 7 + 2 + 1)
        out[0] = 0x08.toByte()
        System.arraycopy(RAK_MAGIC_OUT, 0, out, 1, 16)
        putU64Be(out, 17, serverGuid)
        var p = 25
        out[p++] = 0x04.toByte()
        if (clientIp.size == 4) {
            System.arraycopy(clientIp, 0, out, p, 4)
            p += 4
        } else {
            p += 4
        }
        putU16(out, p, clientPort)
        p += 2
        putU16(out, p, minOf(mtu, 1400))
        p += 2
        out[p] = 0
        sendRaw(out)
        synchronized(lock) {
            if (!offered && !closed) {
                offered = true
                offeredAt = System.currentTimeMillis()
                Libmitm.offer(conn)
            }
        }
    }

    private fun handleConnectedPing(d: ByteArray) {
        if (d.size < 9) return
        val clientTime = getU64Be(d, 1)
        val out = ByteArray(17)
        out[0] = 0x03.toByte()
        putU64Be(out, 1, clientTime)
        putU64Be(out, 9, System.currentTimeMillis())
        sendRaw(out)
    }

    private fun handleAckNack(d: ByteArray, isAck: Boolean) {
        if (d.size < 3) return
        val count = getU16(d, 1)
        var pos = 3
        synchronized(lock) {
            var i = 0
            while (i < count && pos + 4 <= d.size) {
                val single = d[pos++].toInt() != 0
                val start = getU24Le(d, pos)
                pos += 3
                val end = if (single) {
                    start
                } else {
                    if (pos + 3 > d.size) break
                    val e = getU24Le(d, pos)
                    pos += 3
                    e
                }
                var s = start
                while (s <= end) {
                    if (isAck) {
                        unacked.remove(s)
                    } else {
                        unacked[s]?.let {
                            sendRaw(it.bytes)
                            it.sentAt = System.currentTimeMillis()
                            it.resends++
                        }
                    }
                    s++
                }
                i++
            }
        }
    }

    private fun flushAcks() {
        val list: IntArray
        synchronized(lock) {
            if (pendingAcks.isEmpty()) return
            list = pendingAcks.toIntArray()
            pendingAcks.clear()
        }
        val out = ByteArray(3 + list.size * 4)
        out[0] = 0xC0.toByte()
        putU16(out, 1, list.size)
        var pos = 3
        for (s in list) {
            out[pos++] = 1
            putU24Le(out, pos, s)
            pos += 3
        }
        sendRaw(out)
    }

    private fun handleDatagram(d: ByteArray) {
        if (d.size < 4) return
        val seq = getU24Le(d, 1)
        synchronized(lock) {
            if (!seenSeqs.add(seq)) return
            if (seenSeqs.size > 1024) {
                val it = seenSeqs.iterator()
                var n = seenSeqs.size - 512
                while (n-- > 0 && it.hasNext()) {
                    it.next()
                    it.remove()
                }
            }
            pendingAcks.add(seq)
            if (pendingAcks.size >= 16) {
            } else {
                flushAcksLocked()
            }
        }
        datagramsIn++
        var pos = 4
        while (pos + 1 < d.size) {
            val flags = d[pos++].toInt() and 0xFF
            val rel = (flags ushr 5) and 0x07
            val split = ((flags ushr 4) and 0x01) != 0
            if (pos + 2 > d.size) return
            val bitLen = ((d[pos].toInt() and 0xFF) shl 8) or (d[pos + 1].toInt() and 0xFF)
            pos += 2
            val byteLen = (bitLen + 7) / 8
            if (rel >= 2 && rel <= 4) {
                if (pos + 3 > d.size) return
                pos += 3
            }
            if (rel == 1 || rel == 3 || rel == 4) {
                if (pos + 4 > d.size) return
                pos += 4
            }
            var splitCount = 0
            var splitIdx = 0
            var splitFrameId = 0
            if (split) {
                if (pos + 10 > d.size) return
                splitCount = getU32Le(d, pos).toInt()
                pos += 4
                splitFrameId = getU16Le(d, pos)
                pos += 2
                splitIdx = getU32Le(d, pos).toInt()
                pos += 4
            }
            if (pos + byteLen > d.size) return
            val payload = d.copyOfRange(pos, pos + byteLen)
            pos += byteLen
            if (!split) {
                deliver(payload)
            } else {
                if (splitCount <= 0 || splitCount > 128 || splitIdx >= splitCount) return
                var complete: ByteArray? = null
                synchronized(lock) {
                    var sb = splits[splitFrameId]
                    if (sb == null || sb.count != splitCount) {
                        if (splits.size > 16) splits.clear()
                        sb = SplitBuf(splitCount, arrayOfNulls(splitCount), 0, System.currentTimeMillis())
                        splits[splitFrameId] = sb
                    }
                    if (sb.parts[splitIdx] == null) {
                        sb.parts[splitIdx] = payload
                        sb.arrived++
                        sb.updatedAt = System.currentTimeMillis()
                    }
                    if (sb.arrived == sb.count) {
                        var total = 0
                        for (p in sb.parts) total += p!!.size
                        val joined = ByteArray(total)
                        var o = 0
                        for (p in sb.parts) {
                            System.arraycopy(p!!, 0, joined, o, p.size)
                            o += p.size
                        }
                        splits.remove(splitFrameId)
                        complete = joined
                    }
                }
                if (complete != null) deliver(complete!!)
            }
        }
    }

    private fun flushAcksLocked() {
        val list: IntArray
        synchronized(lock) {
            if (pendingAcks.isEmpty()) return
            list = pendingAcks.toIntArray()
            pendingAcks.clear()
        }
        val out = ByteArray(3 + list.size * 4)
        out[0] = 0xC0.toByte()
        putU16(out, 1, list.size)
        var pos = 3
        for (s in list) {
            out[pos++] = 1
            putU24Le(out, pos, s)
            pos += 3
        }
        sendRaw(out)
    }

    private fun deliver(payload: ByteArray) {
        if (payload.isEmpty() || closed) return
        val shouldPush = synchronized(lock) { offered && !closed }
        if (!shouldPush) return
        payloadsIn++
        try {
            conn.push(payload)
        } catch (_: Throwable) {
        }
    }

    fun sendConnected(payload: ByteArray) {
        if (payload.isEmpty()) return
        synchronized(lock) {
            if (!offered || closed) return
            val maxChunk = mtu - 128
            var offset = 0
            var frameSplitId = 0
            var frameSplitCount = 0
            if (payload.size > maxChunk) {
                frameSplitCount = (payload.size + maxChunk - 1) / maxChunk
                if (frameSplitCount > 128) return
                splitId = (splitId + 1) and 0xFFFF
                frameSplitId = splitId
            }
            var splitIdx = 0
            while (offset < payload.size) {
                val end = minOf(offset + maxChunk, payload.size)
                val chunk = payload.copyOfRange(offset, end)
                offset = end
                val split = frameSplitCount > 0
                val headerLen = 1 + 2 + 3 + 4 + (if (split) 10 else 0)
                val frame = ByteArray(headerLen + chunk.size)
                var p = 0
                frame[p++] = (((RELIABLE_ORDERED shl 5) or (if (split) 0x10 else 0)) and 0xFF).toByte()
                val bits = chunk.size * 8
                frame[p++] = ((bits ushr 8) and 0xFF).toByte()
                frame[p++] = (bits and 0xFF).toByte()
                putU24Le(frame, p, msgIndex)
                p += 3
                msgIndex = (msgIndex + 1) and 0xFFFFFF
                putU24Le(frame, p, orderIndex)
                p += 3
                frame[p++] = 0
                if (split) {
                    putU32Le(frame, p, frameSplitCount.toLong())
                    p += 4
                    putU16Le(frame, p, frameSplitId)
                    p += 2
                    putU32Le(frame, p, splitIdx.toLong())
                    p += 4
                    splitIdx++
                }
                System.arraycopy(chunk, 0, frame, p, chunk.size)
                val dg = ByteArray(4 + frame.size)
                dg[0] = 0x84.toByte()
                putU24Le(dg, 1, sendSeq)
                System.arraycopy(frame, 0, dg, 4, frame.size)
                if (unacked.size > 512) unacked.clear()
                unacked[sendSeq] = Pending(dg, System.currentTimeMillis(), 0)
                sendSeq = (sendSeq + 1) and 0xFFFFFF
                datagramsOut++
                payloadsOut++
                sendRaw(dg)
            }
            if (frameSplitCount == 0) {
                orderIndex = (orderIndex + 1) and 0xFFFFFF
            } else {
                orderIndex = (orderIndex + 1) and 0xFFFFFF
            }
        }
    }

    fun tick(now: Long) {
        synchronized(lock) {
            if (closed) return
            val it = unacked.entries.iterator()
            while (it.hasNext()) {
                val e = it.next()
                if (now - e.value.sentAt > 500) {
                    if (e.value.resends >= 10) {
                        it.remove()
                    } else {
                        sendRaw(e.value.bytes)
                        e.value.sentAt = now
                        e.value.resends++
                    }
                }
            }
            if (pendingAcks.isNotEmpty()) {
                flushAcksLocked()
            }
            val si = splits.entries.iterator()
            while (si.hasNext()) {
                if (now - si.next().value.updatedAt > 10000) si.remove()
            }
        }
    }

    fun shutdown() {
        synchronized(lock) {
            if (closed) return
            closed = true
            unacked.clear()
            pendingAcks.clear()
            splits.clear()
        }
        try {
            conn.close()
        } catch (_: Throwable) {
        }
    }
}
