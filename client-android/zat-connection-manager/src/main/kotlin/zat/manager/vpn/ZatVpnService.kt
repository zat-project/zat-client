package zat.manager.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.serialization.json.Json
import io.nekohasekai.libbox.TunOptions
import zat.manager.models.RealityServer
import zat.manager.models.VpnRoute
import zat.manager.vpn.engine.reality.RealityEngine
import zat.manager.vpn.engine.reality.RealityRoute
import zat.manager.vpn.engine.reality.RealitySingBoxConfig
import zat.manager.vpn.engine.reality.TwoHopRoute
import zat.manager.vpn.engine.reality.SingBoxPlatformInterface
import java.io.File

/**
 * ZatVpnService — Step 8.4
 *
 * Core Android VpnService subclass for ZAT app-only split tunneling.
 *
 * Architectural pillars enforced:
 *   1. **App-Only Split Tunneling:** Uses [Builder.addAllowedApplication] with
 *      the host app's package name so that ONLY traffic from the ZAT app is
 *      routed through the VPN tunnel. All other device apps use the normal
 *      network path, completely unaffected.
 *   2. **Transparent Routing:** Telegram's internal ConnectionsManager uses
 *      Direct Connection (no proxy). This VpnService silently intercepts and
 *      routes all ZAT app traffic through the selected VPN Gate server at the
 *      OS network level.
 *   3. **Protocol Fallback Engine:** Uses [ProtocolFallbackEngine] to
 *      automatically try OpenVPN UDP → OpenVPN TCP → SSTP until one
 *      protocol succeeds or all fail.
 *   4. **Sticky Routing:** Once a Route + Protocol connects, it stays active
 *      until failure or TTL expiry (subject to VoIP/Media locks from
 *      [ProxyRotationController]).
 *
 * Privacy rules:
 *   - No user identity, Telegram data, or end-user information is accessed.
 *   - No destination logs, user IP history, or persistent user identity.
 *   - Logging is limited to operational VPN state (connecting/connected/error).
 *   - VPN configuration data is held in memory only — never written to disk.
 */
/** What the two-hop supervisor needs to re-match autonomously (see [VpnManager.startTwoHop]). */
data class ReMatchContext(val introducerUrl: String, val country: String)

class ZatVpnService : VpnService(), SingBoxPlatformInterface.Host {

    companion object {
        private const val TAG = "ZAT"

        /** B1a.1: run the libmeshoprf.so on-device smoke test on service create. Validated
         *  on-device 2026-07-01 (arm64: ristretto255 round + DLEQ verified, coexists with
         *  libbox in the :vpn process) — left OFF; flip on to re-diagnose the native lib. */
        private const val MESH_SELF_TEST = false
        private const val NOTIFICATION_CHANNEL_ID = "zat_vpn_channel"
        private const val NOTIFICATION_ID = 1

        /**
         * Intent extra key for the serialized [VpnRoute] JSON string.
         * The caller must serialize the VPN route using kotlinx.serialization
         * before passing it via this extra.
         */
        const val EXTRA_VPN_ROUTE_JSON = "zat.vpn.VPN_ROUTE_JSON"

        /**
         * Intent extra key for the protocol identifier string.
         * Valid values: "openvpn_udp", "openvpn_tcp", "sstp".
         * If absent, the fallback engine tries all protocols in order.
         */
        const val EXTRA_PROTOCOL = "zat.vpn.PROTOCOL"

        /**
         * Boolean Intent extra: when true, the service connects using the routes
         * staged in [pendingRoutes] (server failover). The list is passed
         * in-process via [pendingRoutes] rather than an Intent extra, because
         * ~20 full OpenVPN configs exceed the Binder transaction limit and would
         * silently break startForegroundService() on the service side.
         */
        const val EXTRA_USE_PENDING_ROUTES = "zat.vpn.USE_PENDING_ROUTES"

        /**
         * Boolean Intent extra: when true, connect via the sing-box / VLESS-Reality
         * engine to the server staged in [pendingRealityServer] (the anti-DPI
         * transport), instead of the SSTP failover path.
         */
        const val EXTRA_USE_REALITY = "zat.vpn.USE_REALITY"

        /**
         * Boolean Intent extra: when true, connect via the two-hop BLIND chain
         * staged in [pendingTwoHop] (client → outer Reality volunteer → inner
         * Reality exit), instead of the single-hop Reality path.
         */
        const val EXTRA_USE_TWO_HOP = "zat.vpn.USE_TWO_HOP"

        /**
         * Boolean Intent extra: when true, bootstrap the rendezvous match OVER REALITY
         * (MESH Stage 1) — a local SOCKS proxy dialed through the Reality entry staged
         * in [pendingRendezvousEntry] — then hand off to the two-hop blind data path on
         * the matched volunteer + [pendingRendezvousExit].
         */
        const val EXTRA_USE_RENDEZVOUS = "zat.vpn.USE_RENDEZVOUS"

        /**
         * Boolean Intent extra: tear the tunnel down and stop the service (toggle OFF).
         * Delivered as a start command because a VpnService holding an established tun is
         * BOUND by the system — an external stopService() alone will not destroy it; the
         * service must close the tun from within (releasing that binding) and stopSelf().
         */
        const val EXTRA_STOP = "zat.vpn.STOP"

        /** Maximum number of candidate servers to try before giving up. */
        private const val MAX_ROUTES_TO_TRY = 6

        /**
         * Battery saver: how long the screen must stay *continuously* off before
         * the tunnel is actually paused. Short screen-offs (a glance, a quick
         * pickup) must NOT tear the tunnel down — otherwise every pickup would
         * pay a multi-second reconnect that costs more than the sliver of idle
         * it saved. Only a genuinely idle device (pocket, overnight) crosses
         * this threshold, where the delay is negligible against the hours of
         * saved radio wake-ups.
         */
        private const val BATTERY_PAUSE_DELAY_MS = 90_000L

        /**
         * In-process handoff for the candidate route list, set by [VpnManager]
         * immediately before startForegroundService(). Held in memory only,
         * consumed and cleared on the next onStartCommand. Volatile for
         * cross-thread visibility (written on a worker thread, read on main).
         */
        @Volatile
        var pendingRoutes: List<VpnRoute>? = null

        /**
         * In-process handoff for the selected Reality server, set by [VpnManager]
         * immediately before startForegroundService(). Memory-only; consumed and
         * cleared on the next onStartCommand.
         */
        @Volatile
        var pendingRealityServer: RealityServer? = null

        /**
         * In-process handoff for the two-hop selection (volunteer + exit), set by
         * [VpnManager] before startForegroundService(). Memory-only; consumed and
         * cleared on the next onStartCommand.
         */
        @Volatile
        var pendingTwoHop: TwoHopRoute? = null

        /**
         * In-process handoff for the re-match context (introducer URL + country) the
         * two-hop supervisor needs to obtain a fresh volunteer autonomously. Set by
         * [VpnManager] alongside [pendingTwoHop]; memory-only.
         */
        @Volatile
        var pendingReMatch: ReMatchContext? = null

        /**
         * In-process handoffs for the reach-over-Reality bootstrap (MESH Stage 1): the
         * Reality [pendingRendezvousEntry] the match is dialed through, and the
         * [pendingRendezvousExit] the data path tunnels to. Set by [VpnManager] before
         * startForegroundService(); memory-only, consumed on the next onStartCommand.
         */
        @Volatile
        var pendingRendezvousEntry: RealityRoute? = null

        @Volatile
        var pendingRendezvousExit: RealityRoute? = null

        // Two-hop supervisor timing: a grace period before the first liveness probe
        // (let the handshake establish), the probe cadence, and the connect timeout.
        private const val PROBE_GRACE_MS = 8_000L
        private const val PROBE_INTERVAL_MS = 5_000L
        private const val PROBE_TIMEOUT_MS = 4_000

        // Liveness = a REAL data-path check: an unprotected TCP connect that rides the tun out to a
        // guaranteed-up internet anycast host, so it validates the WHOLE two-hop
        // (client→volunteer→exit→internet). Stable IP literals (no DNS) keep it from flapping; two
        // hosts (either responding = alive) so no single anycast being down false-negatives a
        // healthy tunnel. NOT the old hairpin to the volunteer's own Reality port, which was fragile
        // and killed healthy tunnels (see the two-hop exit-leg diagnosis).
        private val DATA_PATH_PROBE_HOSTS = listOf("1.1.1.1", "8.8.8.8")
        private const val DATA_PATH_PROBE_PORT = 443

        /**
         * Loopback port for the reach-over-Reality bootstrap proxy's `mixed` (SOCKS)
         * inbound. Loopback-only, so a fixed high port is fine; if it is busy the proxy
         * fails to start and the bootstrap degrades to single-hop Reality.
         */
        private const val RENDEZVOUS_SOCKS_PORT = 18964
        /** How long to wait for that SOCKS inbound to start listening before matching. */
        private const val SOCKS_READY_TIMEOUT_MS = 6_000L

        /**
         * The bootstrap proxy's SOCKS inbound accepts immediately, but its Reality
         * OUTBOUND can only egress once sing-box's default-interface monitor has bound
         * the physical network (observed ~tens of ms after start). The first match can
         * race that and fail fast (SocketException), so match with a short delay BEFORE
         * each attempt and retry a few times — the common case wins on attempt 2.
         */
        private const val RENDEZVOUS_MATCH_ATTEMPTS = 5
        private const val RENDEZVOUS_MATCH_RETRY_MS = 500L
    }

    /** The active tun interface file descriptor; null when VPN is not established. */
    private var tunInterface: ParcelFileDescriptor? = null

    /**
     * The libbox (sing-box) tun the engine builds via [openTun]. We KEEP the PFD (rather than
     * `detachFd()`ing it to the engine) so `teardown()` can close it: the engine does NOT close this
     * tun on stop, so detaching it leaked the tun across a disconnect → the next reconnect's bootstrap
     * fetch was fail-closed/DNS-blocked (UnknownHostException). Held here, we drop it on teardown.
     */
    private var realityTun: ParcelFileDescriptor? = null

    /**
     * Kill-switch tun: a fail-closed tun (captures the app but forwards nothing)
     * kept up whenever no engine is connected, so the app's traffic is DROPPED
     * rather than leaking directly. The engine's real tun replaces it on connect.
     */
    private var killSwitchTun: ParcelFileDescriptor? = null

    /** The active protocol fallback engine; null when no connection attempt is running. */
    private var fallbackEngine: ProtocolFallbackEngine? = null

    /** The active sing-box/Reality engine (libbox), when on the Reality path. */
    private var realityEngine: RealityEngine? = null

    /** Two-hop supervisor: alive while the blind two-hop path is being kept up. */
    @Volatile private var twoHopRunning = false

    /** Set by the engine's serviceStop (the box exited) so the supervisor re-matches. */
    @Volatile private var engineExited = false

    /** The background thread running [twoHopLoop] (probe → re-match), if any. */
    private var twoHopSupervisor: Thread? = null

    /** Pure decision policy for the supervisor (failure thresholds + backoff). */
    private val rematchPolicy = ReMatchPolicy()

    /** The protocol that successfully connected (for sticky routing). */
    private var stickyProtocol: String? = null

    /** The route that successfully connected (for sticky routing). */
    private var stickyRoute: VpnRoute? = null

    /** Candidate routes for server-level failover (from the signed snapshot). */
    private var routes: List<VpnRoute> = emptyList()

    /** Index into [routes] of the route currently being attempted. */
    private var currentRouteIndex = 0

    /** Lenient JSON parser for deserializing route data from Intent extras. */
    private val json = Json { ignoreUnknownKeys = true }

    /** True while the tunnel is paused by the opt-in battery saver (screen off). */
    private var pausedForBattery = false

    /** Main-thread handler that defers the battery-saver pause (see below). */
    private val pauseHandler = android.os.Handler(android.os.Looper.getMainLooper())

    /**
     * Deferred pause: fires [BATTERY_PAUSE_DELAY_MS] after the screen went off
     * and only if it is *still* off (a screen-on cancels it first). The flag and
     * engine are re-checked at fire time so a battery-saver toggle or a teardown
     * in the meantime is honoured.
     */
    private val pauseRunnable = Runnable {
        if (VpnManager.isBatterySaver(this@ZatVpnService) && fallbackEngine != null) {
            Log.i(TAG, "Battery saver: screen off ${BATTERY_PAUSE_DELAY_MS / 1000}s — pausing tunnel.")
            stopFallbackEngine()
            pausedForBattery = true
        }
    }

    /**
     * Battery saver (opt-in): tear the tunnel down while the screen is off and
     * re-establish it when the screen turns back on. The foreground service
     * itself stays alive so it can still receive the screen-on broadcast.
     *
     * The pause is *deferred* (not immediate): a brief screen-off followed by a
     * quick pickup must not churn the tunnel — only a sustained idle period is
     * worth pausing for. The reconnect, by contrast, is immediate so the user
     * is back online the instant they return.
     */
    private val screenReceiver = object : android.content.BroadcastReceiver() {
        override fun onReceive(context: android.content.Context?, intent: Intent?) {
            if (!VpnManager.isBatterySaver(this@ZatVpnService)) return
            when (intent?.action) {
                Intent.ACTION_SCREEN_OFF -> if (fallbackEngine != null) {
                    // Defer: a pickup within the grace window cancels this.
                    pauseHandler.removeCallbacks(pauseRunnable)
                    pauseHandler.postDelayed(pauseRunnable, BATTERY_PAUSE_DELAY_MS)
                }
                Intent.ACTION_SCREEN_ON -> {
                    // Cancel any pending pause, then reconnect if already paused.
                    pauseHandler.removeCallbacks(pauseRunnable)
                    if (pausedForBattery && routes.isNotEmpty()) {
                        Log.i(TAG, "Battery saver: screen on — reconnecting tunnel.")
                        pausedForBattery = false
                        startRouteFailover(routes)
                    }
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        val filter = android.content.IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
        }
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            registerReceiver(screenReceiver, filter, android.content.Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(screenReceiver, filter)
        }
        // TEMP (B1a.1 device smoke test): confirm libmeshoprf.so loads + the Rust VOPRF
        // round works on this ABI, in the :vpn process alongside libbox's Go runtime (the
        // whole reason for Rust). Flip MESH_SELF_TEST off / remove after validation.
        if (MESH_SELF_TEST) {
            try {
                android.util.Log.i(TAG, "mesh " + cloud.zat.meshoprf.MeshOprf.selfTest())
            } catch (e: Throwable) {
                android.util.Log.e(TAG, "mesh self-test FAILED: ${e.javaClass.simpleName}: ${e.message}")
            }
        }
    }

    /**
     * Called when the service is started via an Intent.
     *
     * Extracts the route profile from Intent extras, establishes the VPN
     * tun interface with app-only split tunneling, and starts the protocol
     * fallback engine.
     */
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Explicit stop (toggle OFF). Handle BEFORE startForeground: close the tun from
        // within so the system releases its VpnService binding, then stop. Returns
        // NOT_STICKY so the system does not resurrect us.
        if (intent?.getBooleanExtra(EXTRA_STOP, false) == true) {
            Log.i(TAG, "Stop requested — closing the tunnel and stopping the service.")
            teardownAndStop()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, buildNotification())
        // Live state for the UI: a start was requested (resolve/match/engine-up follows).
        ZatConnectionState.set(ConnectionState.CONNECTING)

        // Reality (sing-box) path: libbox builds + owns the tun via openTun().
        // STICKY is safe — a null-intent restart is caught by the always-on /
        // restart branch below (fail closed + reconnect), not a dead tun.
        if (intent?.getBooleanExtra(EXTRA_USE_REALITY, false) == true) {
            startReality()
            return START_STICKY
        }

        // Two-hop blind Model-B path: the same libbox engine, a chained config.
        if (intent?.getBooleanExtra(EXTRA_USE_TWO_HOP, false) == true) {
            startTwoHop()
            return START_STICKY
        }

        // Reach-over-Reality (MESH Stage 1): bootstrap the match through a Reality entry,
        // then hand off to the two-hop blind data path.
        if (intent?.getBooleanExtra(EXTRA_USE_RENDEZVOUS, false) == true) {
            startRendezvousBootstrap()
            return START_STICKY
        }

        // Explicit SSTP route sources, staged in-process by VpnManager.
        val usePending = intent?.getBooleanExtra(EXTRA_USE_PENDING_ROUTES, false) ?: false
        val routeJson = intent?.getStringExtra(EXTRA_VPN_ROUTE_JSON)

        // Always-on VPN, or a STICKY restart (null intent): the system started us
        // with no route. Fail CLOSED at once (kill-switch), then resolve a route
        // and reconnect through the normal path — never leak directly meanwhile.
        if (!usePending && routeJson == null) {
            // A routeless start means always-on, or a START_STICKY re-delivery. If the rendezvous
            // supervisor is ALREADY up, this is a duplicate delivery rather than a cold start, and
            // re-running the whole resolve → start cycle costs a second snapshot fetch and would
            // drop a kill-switch tun over a live tunnel. The supervisor owns reconnection; leave it.
            //
            // Observed live: one tap produced TWO full bootstrap resolutions. It was invisible until
            // the resolver got fast — at ~5 s per resolve the second landed after the first had
            // settled, and only `startRendezvousBootstrap`'s own duplicate guard showed it. Two
            // fetches per connect is not just waste: on a censored network every extra fetch is
            // another sample of the same request pattern for a classifier to work with.
            if (twoHopRunning) {
                Log.i(TAG, "Routeless restart while the two-hop supervisor is live — keeping the existing session.")
                return START_STICKY
            }
            establishBlockTun()
            // Protect the bootstrap fetch so it survives an always-on lockdown.
            VpnManager.fetchRouteAndStartVpn(this, { sock -> protect(sock) }, "routeless-restart")
            return START_STICKY
        }

        killSwitchTun?.let { runCatching { it.close() } }
        killSwitchTun = null
        establishTunInterface()
        when {
            usePending -> {
                val staged = pendingRoutes
                pendingRoutes = null
                if (!staged.isNullOrEmpty()) {
                    startRouteFailover(staged)
                } else {
                    Log.w(TAG, "USE_PENDING_ROUTES set but no staged routes — nothing to connect.")
                }
            }
            routeJson != null -> startFallbackEngine(routeJson)
        }
        return START_STICKY
    }

    override fun onDestroy() {
        try { unregisterReceiver(screenReceiver) } catch (e: Exception) { /* not registered */ }
        pauseHandler.removeCallbacks(pauseRunnable)
        teardown()
        super.onDestroy()
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked by user or system.")
        teardown()
        stopSelf()
    }

    /** Stop the supervisor + engines and close all tuns (idempotent across callers). */
    private fun teardown() {
        // Only real stops reach here (toggle-off / destroy / revoke), never the re-match path.
        ZatConnectionState.set(ConnectionState.DISCONNECTED)
        stopTwoHopSupervisor()
        realityEngine?.stop()
        realityEngine = null
        stopFallbackEngine()
        closeTunInterface()
        killSwitchTun?.let { runCatching { it.close() } }
        killSwitchTun = null
        // Drop the engine's tun (it doesn't close it on stop) so no fail-closed tun lingers to
        // DNS-block the next reconnect's bootstrap fetch (the disconnect→reconnect bug).
        realityTun?.let { runCatching { it.close() } }
        realityTun = null
    }

    /**
     * Explicit stop (EXTRA_STOP from [VpnManager.stopVpn], i.e. toggle OFF): close the
     * tunnel from WITHIN so the system's VpnService binding is released, then stop. A
     * VpnService with an established tun is BOUND by the system, so an external
     * stopService() alone never destroys it — closing the tun + stopSelf() does.
     */
    private fun teardownAndStop() {
        teardown()
        @Suppress("DEPRECATION") stopForeground(true)
        stopSelf()
    }

    // -------------------------------------------------------------------------
    // Reality (sing-box / libbox) integration  [P0.3]
    // -------------------------------------------------------------------------

    /** Connect via single-hop VLESS/Reality to the server staged in [pendingRealityServer]. */
    private fun startReality() {
        val server = pendingRealityServer
        pendingRealityServer = null
        if (server == null) {
            Log.e(TAG, "Reality: no server staged — stopping.")
            stopSelf()
            return
        }
        val route = RealityRoute(
            serverAddress = server.address,
            serverPort = server.port,
            uuid = server.uuid,
            realityPublicKey = server.publicKey,
            shortId = server.shortId,
            serverName = server.serverName,
            fingerprint = server.fingerprint,
            flow = server.flow,
        )
        val config = RealitySingBoxConfig.build(
            route,
            includePackages = listOf(packageName),
            logLevel = "warn",
        )
        startRealityEngine(config, "single-hop")
    }

    /**
     * Connect via the two-hop BLIND Model-B chain staged in [pendingTwoHop]:
     * client → outer Reality (volunteer) → inner Reality (our exit) → Telegram.
     * The volunteer relays opaque ciphertext and never sees the destination.
     *
     * Runs under a SUPERVISOR thread ([twoHopLoop]) so the tunnel follows pool churn:
     * when the matched volunteer goes away (it paused on its schedule, hit its volume
     * cap, or went offline), the supervisor re-matches a fresh one and reconnects
     * instead of wedging on the dead config.
     */
    private fun startTwoHop() {
        val sel = pendingTwoHop
        pendingTwoHop = null
        val ctx = pendingReMatch
        pendingReMatch = null
        if (sel == null || ctx == null) {
            Log.e(TAG, "Reality two-hop: nothing staged — stopping.")
            stopSelf()
            return
        }
        // Guard against a double-start: the host can fire onStartCommand twice in
        // quick succession (observed on device). onStartCommand is main-thread
        // serialized, so this flag check keeps it to ONE supervisor — otherwise two
        // would fight over the tun + engine.
        if (twoHopRunning) {
            Log.i(TAG, "Reality two-hop: already supervised — ignoring duplicate start.")
            return
        }
        establishBlockTun() // fail-closed until the engine's tun replaces it
        twoHopRunning = true
        twoHopSupervisor = Thread(
            // No rendezvous entry on the direct two-hop path → re-match stays direct.
            { twoHopLoop(sel.volunteer, sel.exit, null, ctx.introducerUrl, ctx.country) },
            "zat-twohop-supervisor",
        ).also { it.start() }
    }

    // -------------------------------------------------------------------------
    // Reach-over-Reality bootstrap (MESH Stage 1)
    // -------------------------------------------------------------------------

    /**
     * Reach-over-Reality entry point: bring up a bootstrap libbox (a local SOCKS proxy
     * dialed through the Reality entry), run the rendezvous match THROUGH it — so the
     * broker's SNI/IP/DNS never appear on the wire — then hand off to the existing
     * two-hop blind supervisor on the matched volunteer + exit. The supervisor thread
     * itself runs the bootstrap (it BECOMES the supervisor after the match), reusing the
     * churn/re-match/fallback machinery unchanged. Mirrors [startTwoHop]'s double-start
     * guard + fail-closed kill-switch.
     */
    private fun startRendezvousBootstrap() {
        // Guard duplicate starts FIRST — before consuming the staged handoff. The host
        // can fire onStartCommand twice in quick succession; a second pass that re-read
        // the now-cleared pending* would otherwise hit "nothing staged" and stopSelf(),
        // tearing down the live supervisor. onStartCommand is main-thread serialized, so
        // by the time a duplicate runs, the first has already set twoHopRunning.
        if (twoHopRunning) {
            Log.i(TAG, "Reach-over-Reality: already supervised — ignoring duplicate start.")
            return
        }
        val entry = pendingRendezvousEntry
        pendingRendezvousEntry = null
        val exit = pendingRendezvousExit
        pendingRendezvousExit = null
        val ctx = pendingReMatch
        pendingReMatch = null
        if (entry == null || exit == null || ctx == null) {
            Log.e(TAG, "Reach-over-Reality: nothing staged — stopping.")
            stopSelf()
            return
        }
        establishBlockTun() // fail-closed until the data-path engine's tun replaces it
        twoHopRunning = true
        twoHopSupervisor = Thread(
            { rendezvousBootstrapAndSupervise(entry, exit, ctx.introducerUrl, ctx.country) },
            "zat-rdv-supervisor",
        ).also { it.start() }
    }

    /**
     * Match over Reality, then run the blind two-hop supervisor. On a successful match
     * the existing [twoHopLoop] takes the matched volunteer + [exit]; on failure we
     * degrade to single-hop Reality on the exit so the user is never offline.
     */
    private fun rendezvousBootstrapAndSupervise(
        entry: RealityRoute,
        exit: RealityRoute,
        introducerUrl: String,
        country: String,
    ) {
        val volunteer = bootstrapMatchOverReality(entry, introducerUrl, country)
        if (!twoHopRunning) return // stopped during bootstrap
        if (volunteer == null) {
            Log.w(TAG, "Reach-over-Reality: no live volunteer — degrading to single-hop Reality.")
            twoHopRunning = false
            fallbackSingleHop(exit)
            return
        }
        Log.i(TAG, "Reach-over-Reality: matched a live volunteer — starting two-hop.")
        twoHopLoop(volunteer, exit, entry, introducerUrl, country)
    }

    /**
     * Bring up the bootstrap proxy ([RealitySingBoxConfig.buildRendezvousProxy]: a local
     * SOCKS `mixed` inbound dialed through the Reality [entry], NO tun) and run the match
     * through it. Returns the OUTER-hop (volunteer) route, or null on failure. The proxy
     * engine is stopped before returning (the data path uses a fresh engine); the
     * fail-closed kill-switch tun stays up throughout (the proxy opens no tun, and its
     * own Reality outbound is protected off-tunnel by the platform interface).
     */
    private fun bootstrapMatchOverReality(
        entry: RealityRoute,
        introducerUrl: String,
        country: String,
    ): RealityRoute? {
        val config = RealitySingBoxConfig.buildRendezvousProxy(
            entry, RENDEZVOUS_SOCKS_PORT, logLevel = "warn",
        )
        val engine = RealityEngine(
            platform = SingBoxPlatformInterface(this, this),
            baseDir = File(filesDir, "singbox").absolutePath,
            onServiceStop = { /* the bootstrap proxy is transient; ignore its own stop */ },
        )
        realityEngine = engine
        try {
            engine.start(config)
            Log.i(TAG, "Reach-over-Reality: bootstrap proxy started (SOCKS :$RENDEZVOUS_SOCKS_PORT).")
        } catch (e: Exception) {
            Log.e(TAG, "Reach-over-Reality: bootstrap proxy start failed: ${e.message}", e)
            if (realityEngine === engine) realityEngine = null
            return null
        }
        val volunteer = if (awaitSocksReady(RENDEZVOUS_SOCKS_PORT, SOCKS_READY_TIMEOUT_MS)) {
            val v = matchViaSocksWithRetry(entry, engine, introducerUrl, country)
            // The SOCKS is up — flush any queued Trace-1 reports so they ride Reality too.
            RendezvousClient.flushReportsViaSocks(
                introducerUrl.trimEnd('/') + "/v1/rendezvous/report", RENDEZVOUS_SOCKS_PORT,
            )
            v
        } else {
            Log.w(TAG, "Reach-over-Reality: SOCKS proxy did not start in time.")
            null
        }
        // Done with the bootstrap proxy — the data path uses a fresh engine.
        engine.stop()
        if (realityEngine === engine) realityEngine = null
        return volunteer
    }

    /**
     * Polls a loopback connect to the bootstrap proxy's SOCKS [port] until it accepts
     * (the `mixed` inbound is listening) or [timeoutMs] elapses. Loopback is never
     * tunnelled, so this works while the kill-switch tun holds the app fail-closed.
     */
    private fun awaitSocksReady(port: Int, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (twoHopRunning && System.currentTimeMillis() < deadline) {
            try {
                java.net.Socket().use { s ->
                    s.connect(java.net.InetSocketAddress("127.0.0.1", port), 500)
                    return true
                }
            } catch (e: Exception) {
                if (!sleepInterruptible(150)) return false
            }
        }
        return false
    }

    /**
     * Match through the bootstrap SOCKS proxy, retrying briefly. The proxy's Reality
     * outbound can only egress once sing-box has bound the physical interface (a few
     * tens of ms after start), so the first attempt can race it and fail fast. A short
     * delay BEFORE each attempt lets the interface settle; return on the first hit.
     */
    private fun matchViaSocksWithRetry(
        entry: RealityRoute,
        engine: RealityEngine,
        introducerUrl: String,
        country: String,
    ): RealityRoute? {
        repeat(RENDEZVOUS_MATCH_ATTEMPTS) { attempt ->
            if (!sleepInterruptible(RENDEZVOUS_MATCH_RETRY_MS) || !twoHopRunning) return null
            val v = VpnManager.matchVolunteerViaSocks(
                introducerUrl, country, RENDEZVOUS_SOCKS_PORT, entry, engine,
            )
            if (v != null) {
                if (attempt > 0) Log.i(TAG, "Reach-over-Reality: match succeeded on attempt ${attempt + 1}.")
                return v
            }
            Log.w(TAG, "Reach-over-Reality: match attempt ${attempt + 1}/$RENDEZVOUS_MATCH_ATTEMPTS failed.")
        }
        return null
    }

    /**
     * Supervises the blind two-hop: run sing-box on the current volunteer, watch its
     * liveness, and on death obtain a FRESH volunteer (with backoff) and reconnect —
     * never wedged on a stale config. While searching it stays FAIL-CLOSED and does
     * NOT bounce through the dead volunteer; after the re-match budget is spent it
     * degrades to single-hop Reality on the known exit so the user is never offline.
     *
     * The whole loop is blocking I/O (probes, /match) and runs off the main thread.
     */
    private fun twoHopLoop(
        initialVolunteer: RealityRoute,
        exit: RealityRoute,
        entry: RealityRoute?,
        introducerUrl: String,
        country: String,
    ) {
        var volunteer = initialVolunteer
        while (twoHopRunning) {
            // Connect, emit the Trace-1 reachability signal for this volunteer, then watch
            // for churn; a clean stop (false) ends the loop.
            val started = startTwoHopEngine(volunteer, exit)
            if (!started) {
                // Engine failed to come up → report the miss, then find a fresh volunteer.
                VpnManager.reportConnect(volunteer.volunteerId, volunteer.handleId, false)
            } else if (!monitorUntilDead(volunteer)) {
                // A clean stop (not a death) ends the loop. monitorUntilDead emits the Trace-1
                // connect signal from its first real data-path probe (after the grace), so the
                // signal reflects whether traffic actually flowed — not a premature pre-handshake poke.
                return
            }
            // Volunteer dead (or failed to start) → hold fail-closed and find a fresh
            // one WITHOUT reconnecting the dead two-hop (that just wastes a detect cycle).
            stopEngineFailClosed()
            // Re-match over Reality when we have a rendezvous entry (so churn re-matches
            // also hide the broker SNI, robust under SNI-block); else the direct path with
            // backoff. The transient bootstrap proxy is reused — it already retries.
            val next = if (entry != null) {
                bootstrapMatchOverReality(entry, introducerUrl, country)
            } else {
                reMatchWithBackoff(introducerUrl, country)
            }
            if (next == null) {
                // Budget spent (not a shutdown) → degrade to single-hop to stay online.
                if (twoHopRunning) {
                    twoHopRunning = false
                    fallbackSingleHop(exit)
                }
                return
            }
            volunteer = next
        }
    }

    /**
     * Ask the introducer for a fresh live volunteer, retrying with backoff up to the
     * budget. Returns the new outer-hop route, or null when we should stop (shutdown)
     * or the budget is spent (→ caller falls back to single-hop). Stays fail-closed
     * throughout — no traffic flows until a volunteer is found.
     */
    private fun reMatchWithBackoff(introducerUrl: String, country: String): RealityRoute? {
        // The live volunteer churned — we're re-establishing without user action. The UI shows this;
        // a successful re-match/single-hop fallback returns to CONNECTED at the next "engine started".
        ZatConnectionState.set(ConnectionState.RECONNECTING)
        var attempt = 0
        while (twoHopRunning) {
            attempt++
            val backoff = rematchPolicy.backoffMs(attempt)
            if (backoff > 0) sleepInterruptible(backoff)
            if (!twoHopRunning) return null
            val next = VpnManager.rematchVolunteer(introducerUrl, country) { s -> protect(s) }
            if (next != null) {
                Log.i(TAG, "Two-hop: re-matched a fresh volunteer — reconnecting.")
                return next
            }
            if (rematchPolicy.shouldFallBack(attempt)) {
                Log.w(TAG, "Two-hop: re-match budget spent — falling back to single-hop Reality.")
                return null
            }
            Log.w(TAG, "Two-hop: re-match attempt $attempt found no live volunteer.")
        }
        return null
    }

    /** Build + start sing-box for [volunteer]→[exit]; returns false if start failed. */
    private fun startTwoHopEngine(volunteer: RealityRoute, exit: RealityRoute): Boolean {
        engineExited = false
        val config = RealitySingBoxConfig.buildTwoHop(
            volunteer = volunteer,
            exit = exit,
            includePackages = listOf(packageName),
            logLevel = "warn",
        )
        val engine = RealityEngine(
            platform = SingBoxPlatformInterface(this, this),
            baseDir = File(filesDir, "singbox").absolutePath,
            // The box exiting on its own is another "volunteer dead" signal: wake the
            // supervisor so it re-matches rather than tearing the whole service down.
            onServiceStop = {
                engineExited = true
                twoHopSupervisor?.interrupt()
            },
        )
        realityEngine = engine
        return try {
            engine.start(config)
            Log.i(TAG, "Reality: engine started (two-hop).")
            // #46: the report must say the run CONNECTED, not stop at "bootstrap" — the first live
            // test showed `stage=bootstrap` beside a working tunnel, which reads as a failure.
            RunDiagnostics.finished("two_hop_up", System.currentTimeMillis())
            android.util.Log.i("ZAT", "Dissolution scoreboard: ${BrokerReliance.oneLine()}")
            ZatConnectionState.set(ConnectionState.CONNECTED)
            true
        } catch (e: Exception) {
            Log.e(TAG, "Reality two-hop: start failed: ${e.message}", e)
            false
        }
    }

    /**
     * Watch the current two-hop until its DATA PATH is dead (→ re-match) or the supervisor is
     * stopped. Returns true if it died, false if we are shutting down. Liveness = a real data-path
     * probe (a connect out to the internet THROUGH the tunnel); a run of
     * [ReMatchPolicy.maxProbeFailures] misses (or a sing-box exit) means the path is gone. It also
     * emits the Trace-1 connect signal on the first post-grace probe (whether traffic actually flowed).
     */
    private fun monitorUntilDead(volunteer: RealityRoute): Boolean {
        sleepInterruptible(PROBE_GRACE_MS) // let the two-hop establish before probing
        var failures = 0
        var reported = false
        while (twoHopRunning) {
            if (engineExited) {
                Log.w(TAG, "Two-hop: sing-box exited — re-matching.")
                return true
            }
            val dataPathOk = probeDataPath()
            if (!reported) {
                // First post-grace probe = the Trace-1 connect signal (did traffic actually flow?).
                VpnManager.reportConnect(volunteer.volunteerId, volunteer.handleId, dataPathOk)
                reported = true
            }
            failures = if (dataPathOk) 0 else failures + 1
            if (rematchPolicy.isDead(failures)) {
                Log.w(TAG, "Two-hop: data path down (no internet through the tunnel) — re-matching.")
                return true
            }
            sleepInterruptible(PROBE_INTERVAL_MS)
        }
        return false
    }

    /**
     * The two-hop liveness signal: an UNPROTECTED TCP connect that RIDES THE TUN out to a
     * guaranteed-up internet host ([DATA_PATH_PROBE_HOST]:[DATA_PATH_PROBE_PORT]), so it tests the
     * WHOLE path (client→volunteer→exit→internet). This replaces the old hairpin (a raw connect back
     * to the volunteer's own Reality port through the tunnel), which was fragile and tore down
     * healthy tunnels on transient blips. Deliberately NOT protected: it must ride the tun — a
     * protected/off-tunnel probe would pass on a dead tunnel, and in-country a direct connect says
     * more about the censor than about the volunteer.
     */
    private fun probeDataPath(): Boolean =
        DATA_PATH_PROBE_HOSTS.any { host ->
            try {
                java.net.Socket().use { s ->
                    s.connect(
                        java.net.InetSocketAddress(host, DATA_PATH_PROBE_PORT),
                        PROBE_TIMEOUT_MS,
                    )
                    true
                }
            } catch (e: Exception) {
                false
            }
        }

    /** Stop the current engine and hold the app fail-closed during the gap. */
    private fun stopEngineFailClosed() {
        establishBlockTun()
        realityEngine?.stop()
        realityEngine = null
    }

    /** Degrade to single-hop Reality on the known exit (the existing graceful path). */
    private fun fallbackSingleHop(exit: RealityRoute) {
        realityEngine?.stop()
        realityEngine = null
        val config = RealitySingBoxConfig.build(
            exit,
            includePackages = listOf(packageName),
            logLevel = "warn",
        )
        startRealityEngine(config, "single-hop (two-hop fallback)")
    }

    /** Sleep, returning false if interrupted (a stop or a sing-box exit woke us). */
    private fun sleepInterruptible(ms: Long): Boolean =
        try {
            Thread.sleep(ms)
            true
        } catch (e: InterruptedException) {
            false
        }

    /** Stop the two-hop supervisor thread, if running. */
    private fun stopTwoHopSupervisor() {
        twoHopRunning = false
        twoHopSupervisor?.interrupt()
        twoHopSupervisor = null
    }

    /** Shared: fail closed, then start the libbox / sing-box engine on [config]. */
    private fun startRealityEngine(config: String, mode: String) {
        establishBlockTun() // fail-closed until the engine's tun replaces it
        val baseDir = File(filesDir, "singbox").absolutePath
        val engine = RealityEngine(
            platform = SingBoxPlatformInterface(this, this),
            baseDir = baseDir,
            onServiceStop = { stopSelf() },
        )
        realityEngine = engine
        try {
            engine.start(config)
            Log.i(TAG, "Reality: engine started ($mode).")
            // #46: the report must say the run CONNECTED, not stop at "bootstrap" — the first live
            // test showed `stage=bootstrap` beside a working tunnel, which reads as a failure.
            RunDiagnostics.finished("engine_up", System.currentTimeMillis())
            android.util.Log.i("ZAT", "Dissolution scoreboard: ${BrokerReliance.oneLine()}")
            ZatConnectionState.set(ConnectionState.CONNECTED)
        } catch (e: Exception) {
            Log.e(TAG, "Reality: start failed: ${e.message}", e)
            ZatConnectionState.set(ConnectionState.ERROR)
            stopSelf()
        }
    }

    // --- SingBoxPlatformInterface.Host (libbox builds the tun through us) ------

    override fun openTun(options: TunOptions): Int {
        val builder = Builder().setSession("ZAT-Reality").setMtu(options.mtu)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        val inet4 = options.inet4Address
        while (inet4.hasNext()) {
            val a = inet4.next()
            builder.addAddress(a.address(), a.prefix())
        }
        if (options.autoRoute) {
            try { builder.addDnsServer(options.dnsServerAddress.value) } catch (e: Exception) { /* no DNS configured */ }
            builder.addRoute("0.0.0.0", 0) // the config routes everything to reality-out
            val include = options.includePackage
            while (include.hasNext()) {
                val pkg = include.next()
                try {
                    builder.addAllowedApplication(pkg)
                } catch (e: Exception) {
                    Log.w(TAG, "addAllowedApplication($pkg): ${e.message}")
                }
            }
        }
        val pfd = builder.establish() ?: error("VpnService.Builder.establish() returned null")
        // The engine's real tun has replaced any kill-switch tun.
        killSwitchTun?.let { runCatching { it.close() } }
        killSwitchTun = null
        // KEEP ownership of the PFD (was `detachFd()`): the engine never closes this tun on stop, so
        // detaching leaked it across a disconnect. Close any stale one first (a re-match reopens a
        // fresh tun within a session), hold the new one, and hand the engine only the raw fd number.
        realityTun?.let { runCatching { it.close() } }
        realityTun = pfd
        Log.i(TAG, "Reality: tun established (mtu=${options.mtu}).")
        return pfd.fd
    }

    override fun protectSocket(fd: Int): Boolean = protect(fd)

    /**
     * Kill-switch: bring up a tun that captures the app but forwards nothing, so
     * packets are DROPPED (fail-closed) rather than leaking directly while no
     * engine is connected — the resolve window, an engine restart, or always-on
     * before the tunnel is up. The engine's real tun replaces it on connect.
     */
    private fun establishBlockTun() {
        try {
            val pfd = Builder()
                .setSession("ZAT")
                .setMtu(1400)
                .addAddress("10.111.222.1", 32)
                .addRoute("0.0.0.0", 0)
                .addAllowedApplication(packageName)
                .establish()
            if (pfd != null) {
                killSwitchTun?.let { runCatching { it.close() } }
                killSwitchTun = pfd
                Log.i(TAG, "Kill-switch tun up (fail-closed).")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Kill-switch tun failed: ${e.message}")
        }
    }

    // -------------------------------------------------------------------------
    // Protocol Fallback Engine integration
    // -------------------------------------------------------------------------

    /**
     * Deserializes the route and starts the [ProtocolFallbackEngine].
     *
     * The engine will attempt protocols in order: openvpn_udp → openvpn_tcp → sstp.
     * On success, [stickyProtocol] and [stickyRoute] are set for sticky routing.
     *
     * @param routeJson JSON-serialized [VpnRoute] string.
     */
    private fun startFallbackEngine(routeJson: String) {
        stopFallbackEngine()

        val route: VpnRoute
        try {
            route = json.decodeFromString<VpnRoute>(routeJson)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to deserialize route JSON: ${e.message}")
            return
        }

        val tunFd = tunInterface?.fd ?: -1
        Log.i(TAG, "Starting protocol fallback for ${route.host} (${route.ip}), tunFd=$tunFd")

        val engine = ProtocolFallbackEngine(
            vpnService = this,
            tunFd = tunFd,
            onConnected = { protocol ->
                Log.i(TAG, "Protocol '$protocol' connected successfully. Sticky routing active.")
                stickyProtocol = protocol
                stickyRoute = route
            },
            onAllFailed = {
                Log.w(TAG, "All protocols failed for ${route.host}. VPN not connected.")
                stickyProtocol = null
                stickyRoute = null
                // The tun interface stays up — the service remains in foreground
                // so the user sees the disconnected state. A retry or new route
                // can be triggered by restarting the service.
            },
            onSstpTunReady = { ip -> reestablishTun(ip) },
        )

        fallbackEngine = engine
        engine.start(route)
    }

    /**
     * Stops the active fallback engine, if any.
     */
    private fun stopFallbackEngine() {
        fallbackEngine?.let { engine ->
            Log.i(TAG, "Stopping fallback engine...")
            engine.stop()
        }
        fallbackEngine = null
        stickyProtocol = null
        stickyRoute = null
    }

    /**
     * Starts a server-level failover sequence over a JSON array of [VpnRoute]s.
     *
     * Each candidate is handed to a fresh [ProtocolFallbackEngine] (which itself
     * tries openvpn_udp → openvpn_tcp → sstp). When a route exhausts all
     * protocols, the next route is tried, up to [MAX_ROUTES_TO_TRY]. The first
     * route to connect wins and becomes sticky; the rest are not tried.
     *
     * This closes the "one dead route fails the whole connection" gap: the
     * signed snapshot carries many quality-ordered servers and the top-scored
     * VPN Gate node is frequently unhealthy.
     */
    private fun startRouteFailover(candidateRoutes: List<VpnRoute>) {
        stopFallbackEngine()

        if (candidateRoutes.isEmpty()) {
            Log.w(TAG, "Route list is empty — nothing to connect.")
            return
        }

        routes = candidateRoutes.take(MAX_ROUTES_TO_TRY)
        currentRouteIndex = 0
        Log.i(TAG, "Server failover: ${routes.size} candidate route(s) (of ${candidateRoutes.size} in snapshot).")
        attemptCurrentRoute()
    }

    /**
     * Attempts the route at [currentRouteIndex] with a fresh fallback engine.
     * On total protocol failure it advances to the next candidate; when the
     * list is exhausted it gives up, leaving the tun interface up.
     *
     * The shared tun fd is reused across attempts — each OpenVPN session takes
     * its own dup() of it (see ZatOpenVPNClient::tun_builder_establish), so
     * repeated engine start/stop across servers is fd-safe.
     */
    private fun attemptCurrentRoute() {
        if (currentRouteIndex >= routes.size) {
            Log.w(TAG, "Server failover: all ${routes.size} route(s) exhausted. VPN not connected.")
            stickyProtocol = null
            stickyRoute = null
            return
        }

        val route = routes[currentRouteIndex]
        val tunFd = tunInterface?.fd ?: -1
        Log.i(TAG, "Server failover: trying route ${currentRouteIndex + 1}/${routes.size} — ${route.host} (${route.ip}), tunFd=$tunFd")

        val engine = ProtocolFallbackEngine(
            vpnService = this,
            tunFd = tunFd,
            onConnected = { protocol ->
                Log.i(TAG, "Protocol '$protocol' connected on ${route.host}. Sticky routing active.")
                stickyProtocol = protocol
                stickyRoute = route
            },
            onAllFailed = {
                Log.w(TAG, "All protocols failed for ${route.host} (route ${currentRouteIndex + 1}/${routes.size}). Failing over.")
                currentRouteIndex++
                attemptCurrentRoute()
            },
            onSstpTunReady = { ip -> reestablishTun(ip) },
        )

        fallbackEngine = engine
        engine.start(route)
    }

    // -------------------------------------------------------------------------
    // Tun interface management
    // -------------------------------------------------------------------------

    /**
     * Establishes a dummy tun interface with strict app-only split tunneling.
     *
     * CRITICAL: [Builder.addAllowedApplication] restricts the VPN tunnel to
     * ONLY the ZAT app package. No other app on the device is affected.
     *
     * The tun interface uses a dummy address/route so the OS accepts the VPN
     * and shows the key icon. The actual tunnel is managed by the protocol
     * engine (OpenVPN or SSTP) which receives the TUN fd.
     */
    private fun establishTunInterface() {
        closeTunInterface()

        try {
            val builder = Builder()
                .setSession("ZAT Secure Connection")
                .addAddress("10.0.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .setMtu(1500)

            // CRITICAL: App-only split tunneling — only this app's traffic
            // passes through the VPN tunnel.
            builder.addAllowedApplication(packageName)

            tunInterface = builder.establish()

            if (tunInterface != null) {
                Log.i(TAG, "VPN tun interface established (app-only: $packageName).")
            } else {
                Log.w(TAG, "VPN tun interface could not be established (permission missing?).")
                stopSelf()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to establish VPN tun interface: ${e.message}")
            stopSelf()
        }
    }

    /**
     * Safely closes the tun interface file descriptor.
     */
    private fun closeTunInterface() {
        try {
            tunInterface?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing tun interface: ${e.message}")
        }
        tunInterface = null
    }

    /**
     * Re-establishes the tun with the PPP-assigned address (used by SSTP after
     * IPCP). The initial tun is created with a placeholder address before the
     * protocol negotiates the real one; for traffic to route with the correct
     * source IP, the tun must carry the assigned address. Returns the new PFD
     * (whose FileDescriptor SstpClient uses for forwarding); this service
     * retains ownership and tears it down.
     */
    @Synchronized
    fun reestablishTun(assignedIpv4: String): ParcelFileDescriptor? {
        return try {
            closeTunInterface()
            val builder = Builder()
                .setSession("ZAT Secure Connection")
                .addAddress(assignedIpv4, 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
                .setMtu(1350)
            builder.addAllowedApplication(packageName)
            val pfd = builder.establish()
            tunInterface = pfd
            if (pfd != null) {
                Log.i(TAG, "VPN tun re-established with the assigned address (app-only).")
            } else {
                Log.w(TAG, "VPN tun re-establish returned null (permission missing?).")
            }
            pfd
        } catch (e: Exception) {
            Log.w(TAG, "Failed to re-establish tun: ${e.message}")
            null
        }
    }

    // -------------------------------------------------------------------------
    // Notification helpers
    // -------------------------------------------------------------------------

    /**
     * Creates the notification channel for Android O+ (API 26+).
     */
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "ZAT VPN",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Shows when ZAT secure connection is active"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    /**
     * Builds a minimal foreground notification for the VPN service.
     * Uses native Notification.Builder (no AndroidX dependency needed).
     * The small icon is ZAT's monochrome status-bar shield (`ic_stat_zat`).
     */
    private fun buildNotification(): Notification =
        Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("ZAT")
            .setContentText("Secure connection active")
            .setSmallIcon(zat.manager.R.drawable.ic_stat_zat)
            .setOngoing(true)
            .build()
}
