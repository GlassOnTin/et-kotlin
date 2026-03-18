package sh.haven.et

import org.junit.Assert.*
import org.junit.Test
import sh.haven.et.crypto.EtCrypto
import sh.haven.et.protocol.EtProtocol
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class EtProtocolTest {

    @Test
    fun `handshake message roundtrip`() {
        val payload = "hello".toByteArray()
        val buf = ByteArrayOutputStream()
        EtProtocol.writeHandshakeMessage(buf, payload)
        assertArrayEquals(payload, EtProtocol.readHandshakeMessage(ByteArrayInputStream(buf.toByteArray())))
    }

    @Test
    fun `handshake framing is 8-byte LE length prefix`() {
        val buf = ByteArrayOutputStream()
        EtProtocol.writeHandshakeMessage(buf, byteArrayOf(0x41, 0x42, 0x43))
        val bytes = buf.toByteArray()
        assertEquals(11, bytes.size)
        assertEquals(3, bytes[0].toInt())
        for (i in 1..7) assertEquals(0, bytes[i].toInt())
    }

    @Test
    fun `data packet roundtrip`() {
        val payload = "terminal data".toByteArray()
        val buf = ByteArrayOutputStream()
        EtProtocol.writeDataPacket(buf, true, EtProtocol.HEADER_TERMINAL_BUFFER, payload)
        val (enc, hdr, result) = EtProtocol.readDataPacket(ByteArrayInputStream(buf.toByteArray()))
        assertTrue(enc)
        assertEquals(EtProtocol.HEADER_TERMINAL_BUFFER, hdr)
        assertArrayEquals(payload, result)
    }

    @Test
    fun `ConnectResponse decodes NEW_CLIENT`() {
        val (status, error) = EtProtocol.decodeConnectResponse(byteArrayOf(0x08, 0x01))
        assertEquals(EtProtocol.STATUS_NEW_CLIENT, status)
        assertNull(error)
    }

    @Test
    fun `TerminalBuffer roundtrip`() {
        val original = "ls -la\n".toByteArray()
        assertArrayEquals(original, EtProtocol.decodeTerminalBuffer(EtProtocol.encodeTerminalBuffer(original)))
    }

    @Test
    fun `TerminalBuffer binary data roundtrip`() {
        val original = ByteArray(256) { it.toByte() }
        assertArrayEquals(original, EtProtocol.decodeTerminalBuffer(EtProtocol.encodeTerminalBuffer(original)))
    }

    @Test
    fun `encrypted packet roundtrip with crypto`() {
        val key = "abcdefghijklmnopqrstuvwxyz012345".toByteArray()
        val writer = EtCrypto(key, EtCrypto.CLIENT_SERVER_NONCE_MSB)
        val reader = EtCrypto(key, EtCrypto.CLIENT_SERVER_NONCE_MSB)

        val plainPayload = EtProtocol.encodeTerminalBuffer("hello world".toByteArray())
        val encrypted = writer.encrypt(plainPayload)

        val buf = ByteArrayOutputStream()
        EtProtocol.writeDataPacket(buf, true, EtProtocol.HEADER_TERMINAL_BUFFER, encrypted)

        val (isEnc, header, ciphertext) = EtProtocol.readDataPacket(ByteArrayInputStream(buf.toByteArray()))
        assertTrue(isEnc)
        assertEquals(EtProtocol.HEADER_TERMINAL_BUFFER, header)
        assertArrayEquals("hello world".toByteArray(), EtProtocol.decodeTerminalBuffer(reader.decrypt(ciphertext)))
    }

    @Test
    fun `multiple data packets in one stream`() {
        val buf = ByteArrayOutputStream()
        EtProtocol.writeDataPacket(buf, true, EtProtocol.HEADER_TERMINAL_BUFFER, "first".toByteArray())
        EtProtocol.writeDataPacket(buf, true, EtProtocol.HEADER_KEEP_ALIVE, ByteArray(0))
        EtProtocol.writeDataPacket(buf, true, EtProtocol.HEADER_TERMINAL_BUFFER, "second".toByteArray())

        val input = ByteArrayInputStream(buf.toByteArray())
        val (_, h1, p1) = EtProtocol.readDataPacket(input)
        val (_, h2, _) = EtProtocol.readDataPacket(input)
        val (_, h3, p3) = EtProtocol.readDataPacket(input)

        assertEquals(EtProtocol.HEADER_TERMINAL_BUFFER, h1)
        assertArrayEquals("first".toByteArray(), p1)
        assertEquals(EtProtocol.HEADER_KEEP_ALIVE, h2)
        assertEquals(EtProtocol.HEADER_TERMINAL_BUFFER, h3)
        assertArrayEquals("second".toByteArray(), p3)
    }
}
