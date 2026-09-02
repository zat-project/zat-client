package zat.manager.vpn

import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.util.Log
import zat.manager.models.VpnRoute
import zat.manager.vpn.engine.SstpEngine
import zat.manager.vpn.engine.VpnProtocolEngine

/**
 * ProtocolFallbackEngine — Step 8.4
 *
 * Implements the protocol fallback state machine for ZAT VPN connections.
 *
 * Attempt sequence:
 *   1. OpenVPN UDP (fastest, best for media)
 *   2. OpenVPN TCP (more resilient against DPI)
 *   3. SSTP (mimics HTTPS on port 443, hardest to detect/block)
 *
 * For each protocol, the engine:
 *   1. Instantiates the appropriate [VpnProtocolEngine].
 *   2. Calls [VpnProtocolEngine.start] with the route profile.
 *   3. Polls [VpnProtocolEngine.getState] at 500ms intervals.
 *   4. If state reaches "CONNECTED" within [PROTOCOL_TIMEOUT_MS], the
 *      protocol is accepted and the engine stays connected.
 *   5. If the timeout expires or state reaches "ERROR", the engine stops
 *      the current protocol and falls through to the next one.
 *   6. If all protocols fail, [onAllFailed] callback is invoked.
 *
 * Sticky routing:
 *   Once a Route + Protocol combination successfully connects, the engine
 *   retains the active engine. The caller can query [activeProtocol] and
 *   [isConnected] to check the current state.
 *
 * Thread safety:
 *   All state transitions happen on the main thread via [Handler].
 *   Native engine callbacks may arrive on background threads, but the
 *   polling mechanism reads [getState] from the main thread.
 *
 * Privacy:
 *   - Only protocol names and connection states are logged.
 *   - No user identity, Telegram data, or config content is logged.
 */
class ProtocolFallbackEngine(
    private val vpnService: VpnService,
    private val tunFd: Int,
    private val onConnected: (protocol: String) -> Unit,
    private val onAllFailed: () -> Unit,
    private val onSstpTunReady: ((assignedIpv4: String) -> android.os.ParcelFileDescriptor?)? = null,
) {

    companion object {
        private const val TAG = "ZAT"

        /** Timeout per protocol attempt in milliseconds. */
        private const val PROTOCOL_TIMEOUT_MS = 10_000L

        /** Polling interval to check engine state. */
        private const val POLL_INTERVAL_MS = 500L

        /**
         * Protocols to attempt. SSTP only: it is the path that works against VPN
         * Gate (SoftEther). The OpenVPN3/mbedTLS native stack was removed — it
         * could not run VPN Gate's legacy AES-128-CBC data channel (see D9).
         */
        val PROTOCOL_ORDER = listOf("sstp")
    }

    private val handler = Handler(Looper.getMainLooper())

    /** The currently active protocol engine, null if nothing is running. */
    private var currentEngine: VpnProtocolEngine? = null

    /** The protocol name currently being attempted or connected. */
    var activeProtocol: String? = null
        private set

    /** Index into [PROTOCOL_ORDER] for the current attempt. */
    private var currentProtocolIndex = 0

    /** Timestamp (SystemClock) when the current attempt started. */
    private var attemptStartTime = 0L

    /** Whether the engine has successfully connected with any protocol. */
    val isConnected: Boolean
        get() = currentEngine?.getState() == "CONNECTED"

    /** Whether a fallback attempt is in progress. */
    private var isRunning = false

    /**
     * True once the current protocol attempt has reached [CONNECTED] state.
     * Remains true for the lifetime of that session so that post-connection
     * state drops (e.g. ERROR or DISCONNECTED) are handled as a route failure
     * rather than a protocol-level fallback.
     */
    private var wasConnected = false

    /**
     * Starts the fallback sequence for the given VPN route.
     *
     * Attempts each protocol in [PROTOCOL_ORDER] until one connects
     * or all fail.
     *
     * @param route The [VpnRoute] to connect to.
     */
    fun start(route: VpnRoute) {
        if (isRunning) {
            Log.w(TAG, "ProtocolFallbackEngine: already running, stopping first.")
            stop()
        }

        isRunning = true
        currentProtocolIndex = 0
        Log.i(TAG, "ProtocolFallbackEngine: starting fallback sequence for ${route.host}")
        attemptProtocol(route)
    }

    /**
     * Stops the current engine and cancels any pending fallback attempts.
     */
    fun stop() {
        isRunning = false
        handler.removeCallbacksAndMessages(null)
        currentEngine?.let { engine ->
            Log.i(TAG, "ProtocolFallbackEngine: stopping engine (protocol=$activeProtocol, state=${engine.getState()})")
            engine.stop()
        }
        currentEngine = null
        activeProtocol = null
    }

    /**
     * Attempts the protocol at [currentProtocolIndex].
     */
    private fun attemptProtocol(route: VpnRoute) {
        if (!isRunning) return

        if (currentProtocolIndex >= PROTOCOL_ORDER.size) {
            Log.w(TAG, "ProtocolFallbackEngine: all protocols exhausted.")
            isRunning = false
            onAllFailed()
            return
        }

        val protocol = PROTOCOL_ORDER[currentProtocolIndex]
        activeProtocol = protocol
        Log.i(TAG, "ProtocolFallbackEngine: attempting protocol '$protocol' (${currentProtocolIndex + 1}/${PROTOCOL_ORDER.size})")

        // Stop any previous engine
        currentEngine?.stop()
        currentEngine = null

        // Create the appropriate engine
        val engine: VpnProtocolEngine = when (protocol) {
            "sstp" -> SstpEngine(onSstpTunReady)
            else -> {
                Log.w(TAG, "ProtocolFallbackEngine: unknown protocol '$protocol', skipping.")
                currentProtocolIndex++
                attemptProtocol(route)
                return
            }
        }

        currentEngine = engine
        wasConnected = false
        attemptStartTime = System.currentTimeMillis()

        try {
            engine.start(route, vpnService, tunFd)
        } catch (e: Exception) {
            Log.w(TAG, "ProtocolFallbackEngine: engine.start() threw: ${e.message}")
            currentProtocolIndex++
            attemptProtocol(route)
            return
        }

        // Start polling for connection state
        schedulePoll(route)
    }

    /**
     * Polls the current engine's state at [POLL_INTERVAL_MS] intervals.
     *
     * **Before first connection:**
     *   - `CONNECTED` → fire [onConnected], set [wasConnected], keep polling.
     *   - `ERROR` → fall through to the next protocol.
     *   - timeout → fall through to the next protocol.
     *
     * **After first connection (wasConnected == true):**
     *   - `CONNECTED` → healthy; keep polling.
     *   - `ERROR` or `DISCONNECTED` → route is dead; invoke [onAllFailed].
     *   - timeout with non-CONNECTED state → stalled; invoke [onAllFailed].
     *
     * This keeps the engine alive as a health monitor for the life of the
     * session, allowing [ZatVpnService] to detect and recover from post-connect
     * failures such as server-side disconnects or stalled ping-restart cycles.
     */
    private fun schedulePoll(route: VpnRoute) {
        handler.postDelayed({
            if (!isRunning) return@postDelayed

            val engine = currentEngine ?: return@postDelayed
            val state = engine.getState()
            val elapsed = System.currentTimeMillis() - attemptStartTime

            when {
                state == "CONNECTED" -> {
                    if (!wasConnected) {
                        Log.i(TAG, "ProtocolFallbackEngine: '$activeProtocol' connected in ${elapsed}ms!")
                        onConnected(activeProtocol ?: "unknown")
                        wasConnected = true
                    }
                    // Continue polling to monitor connection health.
                    schedulePoll(route)
                }
                state == "ERROR" || state == "DISCONNECTED" -> {
                    if (wasConnected) {
                        // A previously live connection has died — route is unusable.
                        Log.w(TAG, "ProtocolFallbackEngine: '$activeProtocol' connection died (state=$state). Aborting route.")
                        isRunning = false
                        onAllFailed()
                    } else {
                        // Connection attempt failed before ever reaching CONNECTED.
                        Log.w(TAG, "ProtocolFallbackEngine: '$activeProtocol' reported $state after ${elapsed}ms. Falling back.")
                        engine.stop()
                        currentEngine = null
                        currentProtocolIndex++
                        attemptProtocol(route)
                    }
                }
                elapsed >= PROTOCOL_TIMEOUT_MS -> {
                    if (wasConnected) {
                        // State dropped below CONNECTED (e.g. soft restart) and
                        // the recovery is taking longer than the timeout budget.
                        // Treat as a stalled route rather than a protocol failure.
                        Log.w(TAG, "ProtocolFallbackEngine: '$activeProtocol' connection stalled (state=$state, elapsed=${elapsed}ms). Aborting route.")
                        isRunning = false
                        onAllFailed()
                    } else {
                        // Timed out waiting for the initial connection.
                        Log.w(TAG, "ProtocolFallbackEngine: '$activeProtocol' timed out after ${elapsed}ms (state=$state). Falling back.")
                        engine.stop()
                        currentEngine = null
                        currentProtocolIndex++
                        attemptProtocol(route)
                    }
                }
                else -> {
                    // Still in initial connection phase — poll again.
                    schedulePoll(route)
                }
            }
        }, POLL_INTERVAL_MS)
    }
}
