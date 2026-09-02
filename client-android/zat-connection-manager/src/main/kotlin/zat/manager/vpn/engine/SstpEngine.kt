package zat.manager.vpn.engine

import android.util.Log
import zat.manager.models.VpnRoute

/**
 * SstpEngine — Step 8.3
 *
 * [VpnProtocolEngine] implementation for SSTP (Secure Socket Tunneling Protocol).
 *
 * SSTP tunnels PPP frames over HTTPS on port 443, making it the hardest
 * VPN protocol to detect and block. It is the last fallback in the
 * protocol fallback chain: OpenVPN UDP → OpenVPN TCP → SSTP.
 *
 * This engine delegates to [SstpClient] for the actual SSTP + PPP
 * protocol handling. The connection runs on a daemon background thread
 * and reports state changes via the volatile [state] field, which the
 * [ProtocolFallbackEngine] polls.
 *
 * Privacy:
 *   - Only host, IP, and operational state are logged.
 *   - Full configuration data is never logged or written to disk.
 *   - No user identity, Telegram data, or end-user information is accessed.
 */
class SstpEngine(
    private val onTunReady: ((assignedIpv4: String) -> android.os.ParcelFileDescriptor?)? = null,
) : VpnProtocolEngine {

    companion object {
        private const val TAG = "ZAT"
        private const val DEFAULT_SSTP_PORT = 443
    }

    @Volatile
    private var state: String = "IDLE"

    private var client: SstpClient? = null
    private var connectionThread: Thread? = null

    /**
     * Starts the SSTP engine with the given VPN Gate route profile.
     *
     * Launches a background thread that performs TLS + SSTP handshake +
     * PPP negotiation + data forwarding. State can be queried at any
     * time via [getState].
     *
     * The OpenVPN config data from [profile] is not used for SSTP;
     * the engine connects using the server IP and port directly.
     *
     * @param profile The [VpnRoute] containing server host and IP.
     * @param vpnService The active VpnService for socket protection.
     * @param tunFd The TUN file descriptor.
     */
    override fun start(profile: VpnRoute, vpnService: android.net.VpnService, tunFd: Int) {
        state = "CONNECTING"
        // VPN Gate exposes SSTP on the standard HTTPS port 443 (multiplexed by
        // SoftEther), independent of the per-server OpenVPN port in the profile.
        val port = DEFAULT_SSTP_PORT

        Log.i(TAG, "SSTP engine: starting connection to ${profile.host} (${profile.ip}:$port)")

        // Pin the SSTP TLS cert to the server's OpenVPN <ca> — the broker pre-extracts it into
        // `ca_pem` in the signed snapshot (SoftEther serves one self-signed cert for all its SSL
        // protocols), so no client-side extraction is needed.
        val caPem = profile.caPem

        val sstpClient = SstpClient(
            host = profile.host,
            ip = profile.ip,
            port = port,
            caPem = caPem,
            vpnService = vpnService,
            tunFd = tunFd,
            onTunReady = onTunReady,
            onStateChanged = { newState -> state = newState },
        )
        client = sstpClient

        connectionThread = Thread({
            sstpClient.connect()
        }, "ZAT-SSTP").apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Stops the SSTP engine and tears down the active connection.
     * Clears the background thread reference.
     */
    override fun stop() {
        Log.i(TAG, "SSTP engine: stopping (state: $state)...")
        client?.disconnect()
        connectionThread?.interrupt()
        connectionThread = null
        client = null
        state = "IDLE"
        Log.i(TAG, "SSTP engine: stopped.")
    }

    /**
     * Returns the current engine state.
     *
     * @return One of: "IDLE", "CONNECTING", "CONNECTED", "ERROR"
     */
    override fun getState(): String = state
}
