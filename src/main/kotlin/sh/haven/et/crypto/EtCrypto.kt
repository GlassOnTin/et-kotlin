package sh.haven.et.crypto

import org.bouncycastle.crypto.engines.XSalsa20Engine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

/**
 * XSalsa20-Poly1305 authenticated encryption, compatible with
 * libsodium's crypto_secretbox_easy / crypto_secretbox_open_easy.
 *
 * ET uses this with:
 * - 32-byte key (raw ASCII passkey bytes from etterminal bootstrap)
 * - 24-byte nonce, incremented before each encrypt/decrypt
 * - Client→Server nonce MSB = 0, Server→Client nonce MSB = 1
 * - MAC is 16 bytes (Poly1305), prepended to ciphertext
 *
 * NaCl crypto_secretbox layout:
 * - First 32 bytes of XSalsa20 keystream = Poly1305 one-time key
 * - Plaintext XOR starts at stream offset 32
 * - Output = MAC (16 bytes) + ciphertext
 */
class EtCrypto(key: ByteArray, nonceMsb: Byte) {

    companion object {
        const val KEY_BYTES = 32
        const val NONCE_BYTES = 24
        const val MAC_BYTES = 16
        const val CLIENT_SERVER_NONCE_MSB: Byte = 0
        const val SERVER_CLIENT_NONCE_MSB: Byte = 1
    }

    private val key = key.copyOf()
    private val nonce = ByteArray(NONCE_BYTES).also { it[NONCE_BYTES - 1] = nonceMsb }

    init {
        require(key.size == KEY_BYTES) { "Key must be $KEY_BYTES bytes, got ${key.size}" }
    }

    /**
     * Increment nonce (little-endian, matching libsodium's sodium_increment).
     * Called before each encrypt/decrypt to stay in sync with the peer.
     */
    private fun incrementNonce() {
        for (i in 0 until NONCE_BYTES) {
            val carry = (nonce[i].toInt() and 0xFF) + 1
            nonce[i] = carry.toByte()
            if (carry and 0x100 == 0) break
        }
    }

    /**
     * Encrypt plaintext. Returns MAC (16 bytes) + ciphertext.
     * Compatible with crypto_secretbox_easy output format.
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        incrementNonce()

        val engine = XSalsa20Engine()
        engine.init(true, ParametersWithIV(KeyParameter(key), nonce))

        // First 32 bytes of keystream = Poly1305 one-time key
        val subkey = ByteArray(32)
        engine.processBytes(subkey, 0, 32, subkey, 0)

        // Encrypt plaintext (starting at stream offset 32)
        val ciphertext = ByteArray(plaintext.size)
        engine.processBytes(plaintext, 0, plaintext.size, ciphertext, 0)

        // Compute Poly1305 MAC over ciphertext
        val mac = ByteArray(MAC_BYTES)
        val poly = Poly1305()
        poly.init(KeyParameter(subkey))
        poly.update(ciphertext, 0, ciphertext.size)
        poly.doFinal(mac, 0)

        return mac + ciphertext
    }

    /**
     * Decrypt ciphertext (MAC + encrypted data). Returns plaintext.
     * Compatible with crypto_secretbox_open_easy input format.
     * Throws [SecurityException] on authentication failure.
     */
    fun decrypt(macAndCiphertext: ByteArray): ByteArray {
        require(macAndCiphertext.size >= MAC_BYTES) { "Ciphertext too short" }

        incrementNonce()

        val receivedMac = macAndCiphertext.copyOfRange(0, MAC_BYTES)
        val ciphertext = macAndCiphertext.copyOfRange(MAC_BYTES, macAndCiphertext.size)

        // First 32 bytes of keystream = Poly1305 one-time key
        val engine = XSalsa20Engine()
        engine.init(false, ParametersWithIV(KeyParameter(key), nonce))

        val subkey = ByteArray(32)
        engine.processBytes(subkey, 0, 32, subkey, 0)

        // Verify MAC before decrypting
        val expectedMac = ByteArray(MAC_BYTES)
        val poly = Poly1305()
        poly.init(KeyParameter(subkey))
        poly.update(ciphertext, 0, ciphertext.size)
        poly.doFinal(expectedMac, 0)

        if (!constantTimeEquals(receivedMac, expectedMac)) {
            throw SecurityException("Poly1305 MAC verification failed")
        }

        // Decrypt (XSalsa20 is symmetric)
        val plaintext = ByteArray(ciphertext.size)
        engine.processBytes(ciphertext, 0, ciphertext.size, plaintext, 0)

        return plaintext
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) {
            diff = diff or (a[i].toInt() xor b[i].toInt())
        }
        return diff == 0
    }
}
