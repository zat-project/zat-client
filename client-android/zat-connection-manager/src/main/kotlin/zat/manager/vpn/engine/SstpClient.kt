package zat.manager.vpn.engine

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * SstpClient — Step 8.3
 *
 * Low-level SSTP (Secure Socket Tunneling Protocol) + PPP client.
 * Establishes a PPP-over-HTTPS tunnel to VPN Gate SSTP servers.
 *
 * Connection flow:
 *   1. TLS handshake (accepting self-signed VPN Gate certs)
 *   2. HTTP SSTP upgrade (SSTP_DUPLEX_POST)
 *   3. SSTP handshake (CALL_CONNECT_REQUEST → ACK)
 *   4. PPP negotiation (LCP → PAP auth → IPCP)
 *   5. SSTP CALL_CONNECTED
 *   6. Bidirectional data forwarding (TUN ↔ SSTP/PPP)
 *
 * Privacy:
 *   - Only host/IP and operational state transitions are logged.
 *   - VPN Gate credentials are not logged.
 *   - No user identity, Telegram data, or config contents are logged.
 *   - No data is written to disk.
 */
class SstpClient(
    private val host: String,
    private val ip: String,
    private val port: Int,
    private val caPem: String?,
    private val vpnService: VpnService,
    private val tunFd: Int,
    private val onTunReady: ((assignedIpv4: String) -> ParcelFileDescriptor?)? = null,
    private val onStateChanged: (String) -> Unit,
) {
    companion object {
        private const val TAG = "ZAT"

        // SSTP framing
        private const val SSTP_VERSION = 0x10
        // MS-SSTP §2.2.1: the C (control) flag is the LOW bit (0x01) of the 2nd
        // header byte, not the high bit. Using 0x80 made the client read every
        // server control packet as data ("Expected SSTP control, got data") and
        // also marked our own control packets as data on the wire.
        private const val SSTP_CONTROL_BIT = 0x01
        private const val SSTP_HEADER_LEN = 4

        // SSTP control message types
        private const val MSG_CALL_CONNECT_REQUEST = 0x0001
        private const val MSG_CALL_CONNECT_ACK = 0x0002
        private const val MSG_CALL_CONNECTED = 0x0004
        private const val MSG_CALL_ABORT = 0x0005
        private const val MSG_CALL_DISCONNECT = 0x0006
        private const val MSG_CALL_DISCONNECT_ACK = 0x0007
        private const val MSG_ECHO_REQUEST = 0x0008
        private const val MSG_ECHO_RESPONSE = 0x0009

        // SSTP attribute IDs
        private const val ATTR_ENCAPSULATED_PROTOCOL = 0x01
        private const val ATTR_CRYPTO_BINDING = 0x03
        private const val ATTR_CRYPTO_BINDING_REQ = 0x04

        // PPP framing
        private const val PPP_ADDR = 0xFF
        private const val PPP_CTRL = 0x03

        // PPP protocol numbers
        private const val PPP_LCP = 0xC021
        private const val PPP_PAP = 0xC023
        private const val PPP_IPCP = 0x8021
        private const val PPP_IP = 0x0021

        // LCP codes
        private const val LCP_CONF_REQ = 1
        private const val LCP_CONF_ACK = 2
        private const val LCP_CONF_NAK = 3
        private const val LCP_CONF_REJ = 4
        private const val LCP_ECHO_REQ = 9
        private const val LCP_ECHO_REPLY = 10

        // LCP option types
        private const val LCP_OPT_MRU = 1
        private const val LCP_OPT_AUTH = 3
        private const val LCP_OPT_MAGIC = 5

        // PAP codes
        private const val PAP_AUTH_REQ = 1
        private const val PAP_AUTH_ACK = 2
        private const val PAP_AUTH_NAK = 3

        // IPCP codes and options
        private const val IPCP_CONF_REQ = 1
        private const val IPCP_CONF_ACK = 2
        private const val IPCP_CONF_NAK = 3
        private const val IPCP_CONF_REJ = 4
        private const val IPCP_OPT_IP = 3

        // VPN Gate default credentials
        private const val VG_USER = "vpn"
        private const val VG_PASS = "vpn"

        // Inner MTU kept conservative: an inner IP packet is wrapped in
        // PPP(4) + SSTP(4) + a TLS record + outer TCP/IP, so 1350 leaves headroom
        // to avoid fragmentation/drops on networks with a sub-1500 path MTU.
        private const val MTU = 1350
        private const val CONNECT_TIMEOUT_MS = 10_000
    }

    @Volatile
    var running = false
        private set

    private var sslSocket: SSLSocket? = null
    private var input: InputStream? = null
    private var output: OutputStream? = null
    private var nonce: ByteArray? = null
    private var assignedIp = byteArrayOf(0, 0, 0, 0)
    private var pppId: Byte = 1
    private val random = SecureRandom()
    private var tunPfd: ParcelFileDescriptor? = null

    /**
     * Connects to the SSTP server and enters data forwarding.
     * Blocks until disconnection or error.
     */
    fun connect() {
        running = true
        try {
            onStateChanged("CONNECTING")

            connectTls()
            Log.i(TAG, "SSTP: TLS connected to $ip:$port")

            sendHttpUpgrade()
            readHttpResponse()
            Log.i(TAG, "SSTP: HTTP upgrade accepted")

            sendCallConnectRequest()
            readCallConnectAck()
            Log.i(TAG, "SSTP: handshake complete")

            negotiatePpp()
            Log.i(TAG, "SSTP: PPP negotiation complete")

            // Re-establish the tun with the PPP-assigned address so the OS routes
            // app traffic with the correct source IP, via a proper (non-reflection)
            // file descriptor. ZatVpnService retains ownership of this PFD.
            tunPfd = onTunReady?.invoke(fmtIp(assignedIp))

            sendCallConnected()
            onStateChanged("CONNECTED")
            Log.i(TAG, "SSTP: tunnel established, forwarding data")

            forwardData()
        } catch (_: InterruptedException) {
            Log.i(TAG, "SSTP: interrupted")
        } catch (e: IOException) {
            if (running) {
                Log.w(TAG, "SSTP: connection error: ${e.message}")
                onStateChanged("ERROR")
            }
        } catch (e: Exception) {
            if (running) {
                Log.w(TAG, "SSTP: unexpected error: ${e.message}")
                onStateChanged("ERROR")
            }
        } finally {
            cleanup()
        }
    }

    /** Tears down the connection. Safe to call from any thread. */
    fun disconnect() {
        running = false
        try {
            sslSocket?.close()
        } catch (_: Exception) { /* ignored */ }
    }

    // -----------------------------------------------------------------
    // TLS
    // -----------------------------------------------------------------

    private fun connectTls() {
        // Use SocketChannel to ensure an fd is allocated before protect() is called.
        // A plain Socket() on modern Android has no underlying fd until connect(),
        // which causes vpnService.protect() to return false.
        val socketChannel = java.nio.channels.SocketChannel.open()
        val rawSocket = socketChannel.socket()
        if (!vpnService.protect(rawSocket)) {
            throw IOException("Failed to protect SSTP socket")
        }
        rawSocket.connect(InetSocketAddress(ip, port), CONNECT_TIMEOUT_MS)

        // VPN Gate servers use self-signed certs. We pin to the server's cert
        // taken from the signed-snapshot OpenVPN <ca> block (authenticated).
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf<TrustManager>(makePinningTrustManager()), random)
        val ssl = ctx.socketFactory.createSocket(rawSocket, host, port, true) as SSLSocket
        ssl.startHandshake()

        sslSocket = ssl
        input = BufferedInputStream(ssl.inputStream)
        output = ssl.outputStream
    }

    /**
     * TrustManager that validates the SSTP server's TLS chain against the
     * OpenVPN <ca> cert(s) carried in the Ed25519-signed snapshot (so the trust
     * anchor is authenticated, not system-wide). Verified on VPN Gate — e.g.
     * opengw.net's Let's Encrypt leaf chains to the root present in <ca>.
     * Enforced fail-closed; hostname is intentionally not checked because we
     * connect by IP and the snapshot <ca> is the server identity. This replaces
     * the previous trust-all path, which was MITM-exposed.
     */
    private fun makePinningTrustManager(): X509TrustManager {
        // Validate the server's chain against the OpenVPN <ca> cert(s) as trust
        // anchors (PKIX). Handles both self-signed servers (leaf == anchor) and
        // CA-issued servers like opengw.net's Let's Encrypt certs (leaf chains to
        // a root present in <ca>). Hostname is intentionally not checked: we
        // connect by IP and the snapshot-authenticated <ca> is the identity.
        val anchorTm: X509TrustManager? = try {
            caPem?.let { pem ->
                val certs = java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificates(java.io.ByteArrayInputStream(pem.toByteArray(Charsets.US_ASCII)))
                    .filterIsInstance<X509Certificate>()
                if (certs.isEmpty()) null else {
                    val ks = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType())
                    ks.load(null, null)
                    certs.forEachIndexed { i, c -> ks.setCertificateEntry("zat-ca-$i", c) }
                    val tmf = javax.net.ssl.TrustManagerFactory
                        .getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
                    tmf.init(ks)
                    tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "SSTP: could not build pinned trust anchors: ${e.javaClass.simpleName}")
            null
        }
        return object : X509TrustManager {
            override fun checkClientTrusted(c: Array<X509Certificate>?, t: String?) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>?, t: String?) {
                // Fail closed: reject if the server's chain does not validate
                // against the snapshot-authenticated <ca> anchors (MITM defense).
                val tm = anchorTm
                    ?: throw java.security.cert.CertificateException("SSTP: no pinned CA — refusing server")
                if (chain.isNullOrEmpty())
                    throw java.security.cert.CertificateException("SSTP: empty server chain")
                tm.checkServerTrusted(chain, if (t.isNullOrEmpty()) "RSA" else t)
                Log.i(TAG, "SSTP: cert chain validated against snapshot CA.")
            }
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
    }

    // -----------------------------------------------------------------
    // HTTP SSTP upgrade
    // -----------------------------------------------------------------

    private fun sendHttpUpgrade() {
        val req = "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n" +
            "Host: $host\r\n" +
            "Content-Length: 18446744073709551615\r\n" +
            "\r\n"
        output!!.write(req.toByteArray(Charsets.US_ASCII))
        output!!.flush()
    }

    private fun readHttpResponse() {
        val sb = StringBuilder()
        val stream = input!!
        var prev = 0
        while (true) {
            val b = stream.read()
            if (b == -1) throw IOException("Connection closed during HTTP upgrade")
            sb.append(b.toChar())
            if (b == '\n'.code && prev == '\n'.code) break
            if (b != '\r'.code) prev = b
        }
        val resp = sb.toString()
        if (!resp.startsWith("HTTP/1.1 200") && !resp.startsWith("HTTP/1.0 200")) {
            throw IOException("SSTP HTTP upgrade rejected: ${resp.take(80)}")
        }
    }

    // -----------------------------------------------------------------
    // SSTP control layer
    // -----------------------------------------------------------------

    /**
     * Sends an SSTP control message.
     * [attrs] is the raw serialized attribute(s). numAttrs is set to
     * 1 if [attrs] is non-empty, 0 otherwise (covers all ZAT use-cases).
     */
    private fun sendSstpControl(msgType: Int, attrs: ByteArray = ByteArray(0)) {
        val totalLen = SSTP_HEADER_LEN + 4 + attrs.size
        val numAttrs = if (attrs.isEmpty()) 0 else 1
        val buf = ByteBuffer.allocate(totalLen)
        buf.put(SSTP_VERSION.toByte())
        buf.put(SSTP_CONTROL_BIT.toByte())
        buf.putShort(totalLen.toShort())
        buf.putShort(msgType.toShort())
        buf.putShort(numAttrs.toShort())
        if (attrs.isNotEmpty()) buf.put(attrs)
        output!!.write(buf.array())
        output!!.flush()
    }

    /** Sends an SSTP data packet wrapping a PPP frame. */
    private fun sendSstpData(pppFrame: ByteArray) {
        val totalLen = SSTP_HEADER_LEN + pppFrame.size
        val buf = ByteBuffer.allocate(totalLen)
        buf.put(SSTP_VERSION.toByte())
        buf.put(0x00.toByte()) // C=0 → data
        buf.putShort(totalLen.toShort())
        buf.put(pppFrame)
        output!!.write(buf.array())
        output!!.flush()
    }

    /**
     * Reads one SSTP packet from the wire.
     * @return Pair(isControl, payload-after-header).
     */
    private fun readSstpPacket(): Pair<Boolean, ByteArray> {
        val hdr = readExact(input!!, SSTP_HEADER_LEN)
        val isCtrl = (hdr[1].toInt() and SSTP_CONTROL_BIT) != 0
        val length = ((hdr[2].toInt() and 0xFF) shl 8) or (hdr[3].toInt() and 0xFF)
        val payloadLen = length - SSTP_HEADER_LEN
        if (payloadLen < 0 || payloadLen > 65536) {
            throw IOException("Invalid SSTP packet length: $length")
        }
        val payload = if (payloadLen > 0) readExact(input!!, payloadLen) else ByteArray(0)
        return Pair(isCtrl, payload)
    }

    private fun sendCallConnectRequest() {
        // Attribute: ENCAPSULATED_PROTOCOL_ID = PPP (1)
        val attr = ByteBuffer.allocate(6)
        attr.put(0.toByte())                           // reserved
        attr.put(ATTR_ENCAPSULATED_PROTOCOL.toByte())  // attrId
        attr.putShort(6.toShort())                     // attr length
        attr.putShort(1.toShort())                     // PPP
        sendSstpControl(MSG_CALL_CONNECT_REQUEST, attr.array())
    }

    private fun readCallConnectAck() {
        val (isCtrl, payload) = readSstpPacket()
        if (!isCtrl) throw IOException("Expected SSTP control, got data")
        if (payload.size < 4) throw IOException("SSTP control too short")

        val msgType = ((payload[0].toInt() and 0xFF) shl 8) or (payload[1].toInt() and 0xFF)
        if (msgType == MSG_CALL_ABORT || msgType == MSG_CALL_DISCONNECT) {
            throw IOException("Server sent abort/disconnect ($msgType)")
        }
        if (msgType != MSG_CALL_CONNECT_ACK) {
            throw IOException("Expected CALL_CONNECT_ACK ($MSG_CALL_CONNECT_ACK), got $msgType")
        }

        // Try to extract the 32-byte nonce from CRYPTO_BINDING_REQ attribute.
        // Layout after control header: reserved(1) attrId(1) len(2) hashMask(1) reserved(3) nonce(32)
        if (payload.size >= 44) {
            val attrId = payload[5].toInt() and 0xFF
            if (attrId == ATTR_CRYPTO_BINDING_REQ) {
                nonce = payload.sliceArray(12..43)
            }
        }
        if (nonce == null) {
            nonce = ByteArray(32) // zeros if server omits it
            Log.i(TAG, "SSTP: no crypto binding nonce in ACK, using zeros")
        }
    }

    private fun sendCallConnected() {
        // CRYPTO_BINDING attribute (104 bytes)
        val attr = ByteBuffer.allocate(104)
        attr.put(0.toByte())                        // reserved
        attr.put(ATTR_CRYPTO_BINDING.toByte())      // attrId
        attr.putShort(104.toShort())                 // attr length
        attr.put(0.toByte())                         // reserved
        attr.put(0.toByte())                         // reserved
        attr.put(0.toByte())                         // reserved
        attr.put(0x03.toByte())                      // hash bitmask (SHA-1 + SHA-256)
        attr.put(nonce ?: ByteArray(32))             // echo nonce
        attr.put(ByteArray(32))                      // cert hash (simplified)
        attr.put(ByteArray(32))                      // compound MAC (simplified for PAP)
        sendSstpControl(MSG_CALL_CONNECTED, attr.array())
    }

    /** Handles incoming SSTP control messages during data phase. */
    private fun handleSstpControl(payload: ByteArray) {
        if (payload.size < 4) return
        val msgType = ((payload[0].toInt() and 0xFF) shl 8) or (payload[1].toInt() and 0xFF)
        when (msgType) {
            MSG_ECHO_REQUEST -> sendSstpControl(MSG_ECHO_RESPONSE)
            MSG_CALL_ABORT, MSG_CALL_DISCONNECT ->
                throw IOException("Server sent disconnect/abort ($msgType)")
        }
    }

    // -----------------------------------------------------------------
    // PPP negotiation
    // -----------------------------------------------------------------

    private fun negotiatePpp() {
        sendLcpConfigReq()

        var lcpOurAcked = false
        var lcpPeerAcked = false
        var papDone = false
        var ipcpOurAcked = false
        var ipcpPeerAcked = false
        var ipcpRetries = 0

        while (running && !(ipcpOurAcked && ipcpPeerAcked)) {
            val (isCtrl, payload) = readSstpPacket()
            if (isCtrl) { handleSstpControl(payload); continue }
            if (payload.size < 4) continue

            val (proto, data) = parsePppFrame(payload)
            if (data.isEmpty()) continue
            val code = data[0].toInt() and 0xFF

            when (proto) {
                PPP_LCP -> when (code) {
                    LCP_CONF_REQ -> {
                        handlePeerLcpConfigReq(data)
                        lcpPeerAcked = true
                        if (lcpOurAcked && !papDone) sendPapAuth()
                    }
                    LCP_CONF_ACK -> {
                        lcpOurAcked = true
                        if (lcpPeerAcked && !papDone) sendPapAuth()
                    }
                    LCP_CONF_NAK -> sendLcpConfigReq()
                    LCP_CONF_REJ -> sendLcpConfigReqMinimal()
                    LCP_ECHO_REQ -> {
                        if (data.size >= 4) {
                            val reply = data.copyOf()
                            reply[0] = LCP_ECHO_REPLY.toByte()
                            sendPppPacket(PPP_LCP, reply)
                        }
                    }
                }
                PPP_PAP -> when (code) {
                    PAP_AUTH_ACK -> {
                        papDone = true
                        Log.i(TAG, "SSTP: PAP authenticated")
                        sendIpcpConfigReq()
                    }
                    PAP_AUTH_NAK -> throw IOException("PAP authentication rejected")
                }
                PPP_IPCP -> when (code) {
                    IPCP_CONF_REQ -> {
                        val ack = data.copyOf()
                        ack[0] = IPCP_CONF_ACK.toByte()
                        sendPppPacket(PPP_IPCP, ack)
                        ipcpPeerAcked = true
                    }
                    IPCP_CONF_ACK -> ipcpOurAcked = true
                    IPCP_CONF_NAK -> {
                        extractAssignedIp(data)
                        sendIpcpConfigReqWithIp()
                        if (++ipcpRetries > 5) throw IOException("IPCP failed after $ipcpRetries retries")
                    }
                    IPCP_CONF_REJ -> {
                        sendIpcpConfigReqWithIp()
                        if (++ipcpRetries > 5) throw IOException("IPCP failed after $ipcpRetries retries")
                    }
                }
            }
        }
    }

    /**
     * Parses a PPP frame, handling both standard (FF 03 proto) and
     * ACFC-compressed (proto only) formats.
     * @return Pair(protocolNumber, payloadAfterProtocol)
     */
    private fun parsePppFrame(raw: ByteArray): Pair<Int, ByteArray> {
        if (raw.size < 2) return Pair(0, ByteArray(0))
        return if (raw[0].toInt() and 0xFF == PPP_ADDR &&
            raw[1].toInt() and 0xFF == PPP_CTRL && raw.size >= 4
        ) {
            val proto = ((raw[2].toInt() and 0xFF) shl 8) or (raw[3].toInt() and 0xFF)
            Pair(proto, raw.sliceArray(4 until raw.size))
        } else {
            val proto = ((raw[0].toInt() and 0xFF) shl 8) or (raw[1].toInt() and 0xFF)
            Pair(proto, raw.sliceArray(2 until raw.size))
        }
    }

    // -- LCP helpers --

    private fun sendLcpConfigReq() {
        val magic = ByteArray(4).also { random.nextBytes(it) }
        val opts = ByteBuffer.allocate(10)
        opts.put(LCP_OPT_MRU.toByte()); opts.put(4.toByte())
        opts.putShort(MTU.toShort())
        opts.put(LCP_OPT_MAGIC.toByte()); opts.put(6.toByte())
        opts.put(magic)
        sendLcpPkt(LCP_CONF_REQ, nextPppId(), opts.array())
    }

    private fun sendLcpConfigReqMinimal() {
        val opts = ByteBuffer.allocate(4)
        opts.put(LCP_OPT_MRU.toByte()); opts.put(4.toByte())
        opts.putShort(MTU.toShort())
        sendLcpPkt(LCP_CONF_REQ, nextPppId(), opts.array())
    }

    /**
     * Handles the peer's LCP Configure-Request. ACKs as-is unless the
     * requested auth protocol is not PAP, in which case we NAK with PAP.
     */
    private fun handlePeerLcpConfigReq(data: ByteArray) {
        if (data.size < 4) return
        val id = data[1]
        val opts = if (data.size > 4) data.sliceArray(4 until data.size) else ByteArray(0)

        // Scan options for a non-PAP auth request.
        var wantNakAuth = false
        var i = 0
        while (i < opts.size - 1) {
            val ot = opts[i].toInt() and 0xFF
            val ol = opts[i + 1].toInt() and 0xFF
            if (ol < 2 || i + ol > opts.size) break
            if (ot == LCP_OPT_AUTH && ol >= 4) {
                val ap = ((opts[i + 2].toInt() and 0xFF) shl 8) or (opts[i + 3].toInt() and 0xFF)
                if (ap != PPP_PAP) wantNakAuth = true
            }
            i += ol
        }

        if (wantNakAuth) {
            val nak = ByteBuffer.allocate(4)
            nak.put(LCP_OPT_AUTH.toByte()); nak.put(4.toByte())
            nak.putShort(PPP_PAP.toShort())
            sendLcpPkt(LCP_CONF_NAK, id.toInt(), nak.array())
        } else {
            sendLcpPkt(LCP_CONF_ACK, id.toInt(), opts)
        }
    }

    private fun sendLcpPkt(code: Int, id: Int, options: ByteArray) {
        val len = 4 + options.size
        val pkt = ByteBuffer.allocate(len)
        pkt.put(code.toByte()); pkt.put(id.toByte())
        pkt.putShort(len.toShort()); pkt.put(options)
        sendPppPacket(PPP_LCP, pkt.array())
    }

    // -- PAP --

    private fun sendPapAuth() {
        val u = VG_USER.toByteArray(Charsets.US_ASCII)
        val p = VG_PASS.toByteArray(Charsets.US_ASCII)
        val len = 4 + 1 + u.size + 1 + p.size
        val pkt = ByteBuffer.allocate(len)
        pkt.put(PAP_AUTH_REQ.toByte()); pkt.put(nextPppId().toByte())
        pkt.putShort(len.toShort())
        pkt.put(u.size.toByte()); pkt.put(u)
        pkt.put(p.size.toByte()); pkt.put(p)
        sendPppPacket(PPP_PAP, pkt.array())
    }

    // -- IPCP --

    private fun sendIpcpConfigReq() {
        val opts = ByteBuffer.allocate(6)
        opts.put(IPCP_OPT_IP.toByte()); opts.put(6.toByte())
        opts.put(byteArrayOf(0, 0, 0, 0)) // request 0.0.0.0 → server will NAK with assigned IP
        sendIpcpPkt(IPCP_CONF_REQ, nextPppId(), opts.array())
    }

    private fun sendIpcpConfigReqWithIp() {
        val opts = ByteBuffer.allocate(6)
        opts.put(IPCP_OPT_IP.toByte()); opts.put(6.toByte())
        opts.put(assignedIp)
        sendIpcpPkt(IPCP_CONF_REQ, nextPppId(), opts.array())
    }

    private fun extractAssignedIp(data: ByteArray) {
        if (data.size <= 4) return
        val opts = data.sliceArray(4 until data.size)
        var i = 0
        while (i < opts.size - 1) {
            val ot = opts[i].toInt() and 0xFF
            val ol = opts[i + 1].toInt() and 0xFF
            if (ol < 2 || i + ol > opts.size) break
            if (ot == IPCP_OPT_IP && ol == 6) {
                assignedIp = opts.sliceArray(i + 2 until i + 6)
                Log.i(TAG, "SSTP: assigned IP ${fmtIp(assignedIp)}")
            }
            i += ol
        }
    }

    private fun sendIpcpPkt(code: Int, id: Int, options: ByteArray) {
        val len = 4 + options.size
        val pkt = ByteBuffer.allocate(len)
        pkt.put(code.toByte()); pkt.put(id.toByte())
        pkt.putShort(len.toShort()); pkt.put(options)
        sendPppPacket(PPP_IPCP, pkt.array())
    }

    // -- PPP framing --

    /** Wraps [data] in a PPP frame (FF 03 proto) and sends via SSTP data packet. */
    private fun sendPppPacket(protocol: Int, data: ByteArray) {
        val frame = ByteBuffer.allocate(4 + data.size)
        frame.put(PPP_ADDR.toByte()); frame.put(PPP_CTRL.toByte())
        frame.putShort(protocol.toShort()); frame.put(data)
        sendSstpData(frame.array())
    }

    // -----------------------------------------------------------------
    // Data forwarding
    // -----------------------------------------------------------------

    private fun forwardData() {
        val pfd = tunPfd
        if (pfd == null) {
            Log.w(TAG, "SSTP: no tun descriptor available; cannot forward data.")
            return
        }
        // FileInputStream/FileOutputStream on the tun PFD do proper blocking I/O
        // (retrying EINTR/EAGAIN internally), unlike a raw Os.read on a wrapped
        // fd which surfaced immediately as "TUN read ended". The fd itself is
        // owned by ZatVpnService, so these streams are NOT closed here.
        val tunIn = java.io.FileInputStream(pfd.fileDescriptor)
        val tunOut = java.io.FileOutputStream(pfd.fileDescriptor)

        // TUN → SSTP (background thread)
        val tunReader = Thread({
            val buf = ByteArray(MTU)
            try {
                while (running) {
                    val n = tunIn.read(buf)
                    if (n > 0) sendPppPacket(PPP_IP, buf.copyOf(n))
                    else if (n < 0) break
                }
            } catch (e: Exception) {
                if (running) Log.w(TAG, "SSTP: TUN→SSTP read ended: ${e.message}")
            }
        }, "ZAT-SSTP-T2S")
        tunReader.isDaemon = true
        tunReader.start()

        // SSTP → TUN (this thread)
        try {
            while (running) {
                val (isCtrl, payload) = readSstpPacket()
                if (isCtrl) { handleSstpControl(payload); continue }
                if (payload.size < 4) continue

                val (proto, ipData) = parsePppFrame(payload)
                when (proto) {
                    PPP_IP -> if (ipData.isNotEmpty()) tunOut.write(ipData)
                    PPP_LCP -> {
                        if (ipData.isNotEmpty() && (ipData[0].toInt() and 0xFF) == LCP_ECHO_REQ && ipData.size >= 4) {
                            val reply = ipData.copyOf()
                            reply[0] = LCP_ECHO_REPLY.toByte()
                            sendPppPacket(PPP_LCP, reply)
                        }
                    }
                }
            }
        } finally {
            running = false
            tunReader.interrupt()
            // tunIn/tunOut intentionally not closed: ZatVpnService owns the tun fd.
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun nextPppId(): Int {
        val id = pppId.toInt() and 0xFF
        pppId++
        return id
    }

    /** Reads exactly [n] bytes from [stream], throwing on premature EOF. */
    private fun readExact(stream: InputStream, n: Int): ByteArray {
        val buf = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = stream.read(buf, off, n - off)
            if (r == -1) throw IOException("Unexpected EOF (needed $n, got $off)")
            off += r
        }
        return buf
    }

    private fun fmtIp(b: ByteArray): String =
        b.joinToString(".") { (it.toInt() and 0xFF).toString() }

    private fun cleanup() {
        running = false
        try { sslSocket?.close() } catch (_: Exception) {}
        sslSocket = null
        input = null
        output = null
    }
}
