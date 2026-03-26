package sh.haven.et.protocol

import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * ET wire protocol encoding/decoding.
 *
 * Two framing formats:
 * - Handshake: 8-byte little-endian length + protobuf bytes (unencrypted)
 * - Data: 4-byte big-endian length + [enc_flag][header][payload] (encrypted)
 *
 * Protobuf messages are hand-coded (no protobuf dependency) since ET uses
 * only a small subset of simple proto2 messages.
 */
object EtProtocol {

    const val PROTOCOL_VERSION = 6

    // Packet header types
    const val HEADER_HEARTBEAT: Byte = 254.toByte()
    const val HEADER_INITIAL_PAYLOAD: Byte = 253.toByte()
    const val HEADER_INITIAL_RESPONSE: Byte = 252.toByte()
    const val HEADER_KEEP_ALIVE: Byte = 0
    const val HEADER_TERMINAL_BUFFER: Byte = 1
    const val HEADER_TERMINAL_INFO: Byte = 2

    // ConnectResponse status values
    const val STATUS_NEW_CLIENT = 1
    const val STATUS_RETURNING_CLIENT = 2
    const val STATUS_INVALID_KEY = 3
    const val STATUS_MISMATCHED_PROTOCOL = 4

    // --- Handshake framing (8-byte LE length prefix, unencrypted) ---

    fun writeHandshakeMessage(out: OutputStream, payload: ByteArray) {
        val lenBuf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        lenBuf.putLong(payload.size.toLong())
        out.write(lenBuf.array())
        out.write(payload)
        out.flush()
    }

    fun readHandshakeMessage(input: InputStream): ByteArray {
        val lenBuf = readExact(input, 8)
        val length = ByteBuffer.wrap(lenBuf).order(ByteOrder.LITTLE_ENDIAN).long
        require(length in 0..128 * 1024 * 1024) { "Invalid handshake length: $length" }
        if (length == 0L) return ByteArray(0)
        return readExact(input, length.toInt())
    }

    // --- Data framing (4-byte BE length prefix) ---

    fun writeDataPacket(out: OutputStream, encrypted: Boolean, header: Byte, payload: ByteArray) {
        val totalLen = 1 + 1 + payload.size
        val lenBuf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
        lenBuf.putInt(totalLen)
        out.write(lenBuf.array())
        out.write(if (encrypted) 1 else 0)
        out.write(header.toInt())
        out.write(payload)
        out.flush()
    }

    fun readDataPacket(input: InputStream): Triple<Boolean, Byte, ByteArray> {
        val lenBuf = readExact(input, 4)
        val length = ByteBuffer.wrap(lenBuf).order(ByteOrder.BIG_ENDIAN).int
        require(length in 2..1_048_576) { "Invalid data packet length: $length" }
        val data = readExact(input, length)
        val encrypted = data[0].toInt() != 0
        val header = data[1]
        val payload = data.copyOfRange(2, data.size)
        return Triple(encrypted, header, payload)
    }

    // --- Minimal protobuf encoding (hand-coded, no dependency) ---

    /**
     * Encode ConnectRequest { clientId = id, version = ver }
     */
    fun encodeConnectRequest(clientId: String, version: Int): ByteArray {
        val idBytes = clientId.toByteArray()
        val buf = mutableListOf<Byte>()
        buf.add(0x0a) // field 1, wire type 2
        buf.addAll(encodeVarint(idBytes.size.toLong()))
        buf.addAll(idBytes.toList())
        buf.add(0x10) // field 2, wire type 0
        buf.addAll(encodeVarint(version.toLong()))
        return buf.toByteArray()
    }

    /**
     * Decode ConnectResponse { status = int, error = string? }
     */
    fun decodeConnectResponse(data: ByteArray): Pair<Int, String?> {
        var status = 0
        var error: String? = null
        var pos = 0
        while (pos < data.size) {
            val tag = data[pos++].toInt() and 0xFF
            when (tag) {
                0x08 -> { val (v, p) = decodeVarint(data, pos); status = v.toInt(); pos = p }
                0x12 -> { val (len, p) = decodeVarint(data, pos); error = String(data, p, len.toInt()); pos = p + len.toInt() }
                else -> pos = skipField(data, pos, tag)
            }
        }
        return Pair(status, error)
    }

    /**
     * Encode InitialPayload { jumphost = false }
     */
    fun encodeInitialPayload(jumphost: Boolean = false): ByteArray {
        return byteArrayOf(0x08, if (jumphost) 1 else 0)
    }

    /**
     * Decode InitialResponse { error = string? }
     */
    fun decodeInitialResponse(data: ByteArray): String? {
        var error: String? = null
        var pos = 0
        while (pos < data.size) {
            val tag = data[pos++].toInt() and 0xFF
            when (tag) {
                0x0a -> { val (len, p) = decodeVarint(data, pos); error = String(data, p, len.toInt()); pos = p + len.toInt() }
                else -> pos = skipField(data, pos, tag)
            }
        }
        return error
    }

    /**
     * Encode TerminalBuffer { buffer = bytes }
     */
    fun encodeTerminalBuffer(buffer: ByteArray): ByteArray {
        val buf = mutableListOf<Byte>()
        buf.add(0x0a)
        buf.addAll(encodeVarint(buffer.size.toLong()))
        buf.addAll(buffer.toList())
        return buf.toByteArray()
    }

    /**
     * Decode TerminalBuffer { buffer = bytes }
     */
    fun decodeTerminalBuffer(data: ByteArray): ByteArray {
        var buffer = ByteArray(0)
        var pos = 0
        while (pos < data.size) {
            val tag = data[pos++].toInt() and 0xFF
            when (tag) {
                0x0a -> { val (len, p) = decodeVarint(data, pos); buffer = data.copyOfRange(p, p + len.toInt()); pos = p + len.toInt() }
                else -> pos = skipField(data, pos, tag)
            }
        }
        return buffer
    }

    /**
     * Encode TerminalInfo { row = r, column = c, width = w, height = h }
     */
    fun encodeTerminalInfo(rows: Int, cols: Int, width: Int = 0, height: Int = 0): ByteArray {
        val buf = mutableListOf<Byte>()
        buf.add(0x10); buf.addAll(encodeVarint(rows.toLong()))
        buf.add(0x18); buf.addAll(encodeVarint(cols.toLong()))
        buf.add(0x20); buf.addAll(encodeVarint(width.toLong()))
        buf.add(0x28); buf.addAll(encodeVarint(height.toLong()))
        return buf.toByteArray()
    }

    // --- Protobuf varint helpers ---

    private fun encodeVarint(value: Long): List<Byte> {
        var v = value
        val result = mutableListOf<Byte>()
        while (v > 0x7F) {
            result.add(((v and 0x7F) or 0x80).toByte())
            v = v ushr 7
        }
        result.add((v and 0x7F).toByte())
        return result
    }

    private fun decodeVarint(data: ByteArray, start: Int): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var pos = start
        while (pos < data.size) {
            val b = data[pos++].toInt() and 0xFF
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            require(shift < 64) { "Varint too long" }
        }
        return Pair(result, pos)
    }

    private fun skipField(data: ByteArray, pos: Int, tag: Int): Int {
        return when (tag and 0x07) {
            0 -> { val (_, p) = decodeVarint(data, pos); p }
            1 -> pos + 8
            2 -> { val (len, p) = decodeVarint(data, pos); p + len.toInt() }
            5 -> pos + 4
            else -> throw IllegalArgumentException("Unknown wire type in tag $tag")
        }
    }

    private fun readExact(input: InputStream, length: Int): ByteArray {
        val buf = ByteArray(length)
        var offset = 0
        while (offset < length) {
            val n = input.read(buf, offset, length - offset)
            if (n < 0) throw java.io.EOFException("Unexpected EOF (expected $length bytes, got $offset)")
            offset += n
        }
        return buf
    }
}
