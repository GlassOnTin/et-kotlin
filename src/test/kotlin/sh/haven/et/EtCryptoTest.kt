package sh.haven.et

import org.junit.Assert.*
import org.junit.Test
import sh.haven.et.crypto.EtCrypto

class EtCryptoTest {

    private val testKey = "abcdefghijklmnopqrstuvwxyz012345".toByteArray()

    @Test
    fun `encrypt then decrypt roundtrip`() {
        val enc = EtCrypto(testKey, EtCrypto.CLIENT_SERVER_NONCE_MSB)
        val dec = EtCrypto(testKey, EtCrypto.CLIENT_SERVER_NONCE_MSB)
        val pt = "Hello, Eternal Terminal!".toByteArray()
        val ct = enc.encrypt(pt)
        assertEquals(pt.size + EtCrypto.MAC_BYTES, ct.size)
        assertArrayEquals(pt, dec.decrypt(ct))
    }

    @Test
    fun `multiple messages stay in sync`() {
        val enc = EtCrypto(testKey, EtCrypto.CLIENT_SERVER_NONCE_MSB)
        val dec = EtCrypto(testKey, EtCrypto.CLIENT_SERVER_NONCE_MSB)
        for (i in 0 until 10) {
            val msg = "Message $i".toByteArray()
            assertArrayEquals(msg, dec.decrypt(enc.encrypt(msg)))
        }
    }

    @Test
    fun `client-server nonce streams are independent`() {
        val cw = EtCrypto(testKey, EtCrypto.CLIENT_SERVER_NONCE_MSB)
        val sr = EtCrypto(testKey, EtCrypto.CLIENT_SERVER_NONCE_MSB)
        val sw = EtCrypto(testKey, EtCrypto.SERVER_CLIENT_NONCE_MSB)
        val cr = EtCrypto(testKey, EtCrypto.SERVER_CLIENT_NONCE_MSB)
        assertArrayEquals("c2s".toByteArray(), sr.decrypt(cw.encrypt("c2s".toByteArray())))
        assertArrayEquals("s2c".toByteArray(), cr.decrypt(sw.encrypt("s2c".toByteArray())))
    }

    @Test(expected = SecurityException::class)
    fun `wrong key fails MAC`() {
        val enc = EtCrypto(testKey, EtCrypto.CLIENT_SERVER_NONCE_MSB)
        val dec = EtCrypto("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345".toByteArray(), EtCrypto.CLIENT_SERVER_NONCE_MSB)
        dec.decrypt(enc.encrypt("secret".toByteArray()))
    }

    @Test(expected = SecurityException::class)
    fun `tampered ciphertext fails MAC`() {
        val enc = EtCrypto(testKey, EtCrypto.CLIENT_SERVER_NONCE_MSB)
        val dec = EtCrypto(testKey, EtCrypto.CLIENT_SERVER_NONCE_MSB)
        val ct = enc.encrypt("secret".toByteArray())
        ct[EtCrypto.MAC_BYTES] = (ct[EtCrypto.MAC_BYTES].toInt() xor 0x01).toByte()
        dec.decrypt(ct)
    }

    @Test
    fun `matches libsodium crypto_secretbox output`() {
        val key = "abcdefghijklmnopqrstuvwxyz012345".toByteArray()
        val expected = "e0a49906f02079386e4d8c885424bd035ca76d24bc0171cbccf2a6589da361ea2a0a91e48415ed88"
        val crypto = EtCrypto(key, EtCrypto.CLIENT_SERVER_NONCE_MSB)
        val result = crypto.encrypt("Hello, Eternal Terminal!".toByteArray())
        assertEquals(expected, result.joinToString("") { "%02x".format(it) })
    }

    @Test
    fun `empty plaintext roundtrip`() {
        val enc = EtCrypto(testKey, EtCrypto.CLIENT_SERVER_NONCE_MSB)
        val dec = EtCrypto(testKey, EtCrypto.CLIENT_SERVER_NONCE_MSB)
        val ct = enc.encrypt(ByteArray(0))
        assertEquals(EtCrypto.MAC_BYTES, ct.size)
        assertEquals(0, dec.decrypt(ct).size)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `wrong key size throws`() {
        EtCrypto("short".toByteArray(), EtCrypto.CLIENT_SERVER_NONCE_MSB)
    }
}
