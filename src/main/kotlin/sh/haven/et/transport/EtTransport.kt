package sh.haven.et.transport

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import sh.haven.et.EtLogger
import sh.haven.et.NoOpEtLogger
import sh.haven.et.crypto.EtCrypto
import sh.haven.et.protocol.EtProtocol
import java.io.Closeable
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

private const val TAG = "EtTransport"

/**
 * Pure Kotlin ET client transport.
 *
 * Manages a TCP connection to an Eternal Terminal server using the
 * ET wire protocol (XSalsa20-Poly1305 encrypted, protobuf-framed).
 *
 * Lifecycle:
 * 1. SSH bootstrap runs externally (exec etterminal, get id/passkey)
 * 2. [start] connects TCP, sends ConnectRequest, receives ConnectResponse
 * 3. Exchanges encrypted InitialPayload/InitialResponse
 * 4. Enters steady-state: TERMINAL_BUFFER packets for stdin/stdout,
 *    TERMINAL_INFO for resize, KEEP_ALIVE for heartbeats
 *
 * @param serverHost Host to connect to (IP or hostname)
 * @param port ET server port (default 2022)
 * @param clientId 16-char client ID from etterminal bootstrap
 * @param passkey 32-char passkey from etterminal bootstrap
 * @param onOutput Callback for received terminal data (buffer, offset, length)
 * @param onDisconnect Callback when connection drops (cleanExit: Boolean)
 * @param logger Optional logger implementation
 */
class EtTransport(
    private val serverHost: String,
    private val port: Int,
    private val clientId: String,
    private val passkey: String,
    private val onOutput: (ByteArray, Int, Int) -> Unit,
    private val onDisconnect: ((Boolean) -> Unit)? = null,
    private val logger: EtLogger = NoOpEtLogger,
) : Closeable {

    @Volatile
    private var closed = false

    private var socket: Socket? = null
    private var outputStream: OutputStream? = null
    private var readJob: Job? = null
    private var writer: EtCrypto? = null
    private var reader: EtCrypto? = null
    private val writeExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "et-writer").apply { isDaemon = true }
    }

    /**
     * Start the ET transport. Call from a coroutine scope.
     * Connects TCP, performs handshake, then enters read loop.
     */
    fun start(scope: CoroutineScope) {
        if (closed) return
        logger.d(TAG, "Starting ET transport: $serverHost:$port")

        readJob = scope.launch(Dispatchers.IO) {
            try {
                val sock = Socket()
                sock.connect(InetSocketAddress(serverHost, port), 10_000)
                sock.tcpNoDelay = true
                sock.soTimeout = 10_000  // Timeout for all handshake reads
                socket = sock
                outputStream = sock.getOutputStream()

                val input = sock.getInputStream()
                val output = sock.getOutputStream()

                // Phase 1: Unencrypted handshake
                logger.d(TAG, "Sending ConnectRequest (clientId=${clientId.take(6)}...)")
                val request = EtProtocol.encodeConnectRequest(clientId, EtProtocol.PROTOCOL_VERSION)
                EtProtocol.writeHandshakeMessage(output, request)

                val responseBytes = EtProtocol.readHandshakeMessage(input)
                val (status, error) = EtProtocol.decodeConnectResponse(responseBytes)
                logger.d(TAG, "ConnectResponse: status=$status error=$error")

                when (status) {
                    EtProtocol.STATUS_NEW_CLIENT -> {}
                    EtProtocol.STATUS_RETURNING_CLIENT -> {
                        logger.d(TAG, "Returning client — recovery not yet implemented")
                    }
                    EtProtocol.STATUS_INVALID_KEY -> throw Exception("ET server rejected key (INVALID_KEY)")
                    EtProtocol.STATUS_MISMATCHED_PROTOCOL -> throw Exception("ET protocol version mismatch")
                    else -> throw Exception("Unknown ConnectResponse status: $status")
                }

                // Phase 2: Set up encryption
                val keyBytes = passkey.toByteArray(Charsets.US_ASCII)
                writer = EtCrypto(keyBytes, EtCrypto.CLIENT_SERVER_NONCE_MSB)
                reader = EtCrypto(keyBytes, EtCrypto.SERVER_CLIENT_NONCE_MSB)

                // Phase 3: Send encrypted InitialPayload directly (already on IO thread, before read loop)
                val initialPayload = EtProtocol.encodeInitialPayload(jumphost = false)
                val encrypted = writer!!.encrypt(initialPayload)
                EtProtocol.writeDataPacket(output, true, EtProtocol.HEADER_INITIAL_PAYLOAD, encrypted)

                val (_, respHeader, respPayload) = EtProtocol.readDataPacket(input)
                if (respHeader == EtProtocol.HEADER_INITIAL_RESPONSE) {
                    val decrypted = reader!!.decrypt(respPayload)
                    val respError = EtProtocol.decodeInitialResponse(decrypted)
                    if (respError != null && respError.isNotEmpty()) {
                        throw Exception("ET InitialResponse error: $respError")
                    }
                    logger.d(TAG, "Handshake complete")
                } else {
                    logger.d(TAG, "Unexpected header after InitialPayload: $respHeader")
                }

                // Clear handshake timeout for steady-state (keepalives handle liveness)
                sock.soTimeout = 0

                // Phase 4: Steady-state read loop
                while (!closed) {
                    val (_, header, payload) = EtProtocol.readDataPacket(input)
                    val decrypted = reader!!.decrypt(payload)

                    when (header) {
                        EtProtocol.HEADER_TERMINAL_BUFFER -> {
                            val termData = EtProtocol.decodeTerminalBuffer(decrypted)
                            if (termData.isNotEmpty() && !closed) {
                                onOutput(termData, 0, termData.size)
                            }
                        }
                        EtProtocol.HEADER_KEEP_ALIVE -> {
                            sendEncryptedPacket(output, EtProtocol.HEADER_KEEP_ALIVE, ByteArray(0))
                        }
                        EtProtocol.HEADER_TERMINAL_INFO -> {}
                        else -> logger.d(TAG, "Ignoring packet header=${header.toInt() and 0xFF}")
                    }
                }

                if (!closed) {
                    logger.d(TAG, "EOF")
                    onDisconnect?.invoke(true)
                }
            } catch (e: Exception) {
                if (!closed) {
                    logger.e(TAG, "Transport error: ${e.message}", e)
                    onDisconnect?.invoke(false)
                }
            }
        }
    }

    /**
     * Send keyboard input to the ET server.
     * Safe to call from any thread.
     */
    fun sendInput(data: ByteArray) {
        if (closed) return
        if (writer == null || outputStream == null) return
        val copy = data.copyOf()
        try {
            writeExecutor.execute {
                if (closed) return@execute
                val w = writer ?: return@execute
                val out = outputStream ?: return@execute
                try {
                    val payload = EtProtocol.encodeTerminalBuffer(copy)
                    val encrypted = w.encrypt(payload)
                    EtProtocol.writeDataPacket(out, true, EtProtocol.HEADER_TERMINAL_BUFFER, encrypted)
                } catch (e: Exception) {
                    if (!closed) logger.e(TAG, "Send error", e)
                }
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {}
    }

    /**
     * Notify the ET server of a terminal resize.
     */
    fun resize(cols: Int, rows: Int) {
        if (closed) return
        if (writer == null || outputStream == null) return
        try {
            writeExecutor.execute {
                if (closed) return@execute
                val w = writer ?: return@execute
                val out = outputStream ?: return@execute
                try {
                    val payload = EtProtocol.encodeTerminalInfo(rows = rows, cols = cols)
                    val encrypted = w.encrypt(payload)
                    EtProtocol.writeDataPacket(out, true, EtProtocol.HEADER_TERMINAL_INFO, encrypted)
                } catch (e: Exception) {
                    if (!closed) logger.e(TAG, "Resize error", e)
                }
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {}
    }

    /** Send an encrypted packet on the IO thread (called from read loop). */
    private fun sendEncryptedPacket(out: OutputStream, header: Byte, plaintext: ByteArray) {
        // Called from the read loop (already on IO thread), must serialize with writeExecutor
        try {
            writeExecutor.execute {
                if (closed) return@execute
                val w = writer ?: return@execute
                try {
                    val encrypted = w.encrypt(plaintext)
                    EtProtocol.writeDataPacket(out, true, header, encrypted)
                } catch (e: Exception) {
                    if (!closed) logger.e(TAG, "Send error", e)
                }
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {}
    }

    override fun close() {
        if (closed) return
        closed = true
        writeExecutor.shutdown()
        try { writeExecutor.awaitTermination(1, TimeUnit.SECONDS) } catch (_: Exception) {}
        readJob?.cancel()
        try { socket?.close() } catch (_: Exception) {}
        socket = null
        outputStream = null
    }
}
