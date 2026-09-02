package zat.manager.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import zat.manager.models.RealityServer
import zat.manager.models.VolunteerHandle
import zat.manager.models.VpnRoute
import zat.manager.vpn.engine.reality.RealityEngine
import zat.manager.vpn.engine.reality.RealityRoute
import zat.manager.vpn.engine.reality.RealitySingBoxConfig
import zat.manager.vpn.engine.reality.TwoHopRoute
import java.io.IOException

/**
 * VpnManager — Phase 8.5 / Updated Phase 11.3
 *
 * Utility object for managing the ZAT VPN lifecycle from the host application.
 *
 * Entry points:
 *   1. [prepareVpn] — Checks whether the OS VPN permission has been granted.
 *      If not, returns an Intent that the caller must launch with
 *      `startActivityForResult` to show the system VPN consent dialog.
 *   2. [startVpn] — Starts the [ZatVpnService] foreground service with an
 *      optional serialized [VpnRoute] JSON string.
 *   3. [stopVpn] — Stops the [ZatVpnService].
 *   4. [fetchRouteAndStartVpn] — Uses [BootstrapResolver] to discover a
 *      VPN route via the multi-channel fallback chain, then starts the VPN.
 *   5. [setVpnEnabled] / [isVpnEnabled] — Persists the user's VPN toggle
 *      state in SharedPreferences so the VPN can be auto-started on app launch.
 *
 * Phase 11.3 changes:
 *   - Removed hardcoded `BROKER_VPN_ROUTES_URL` constant.
 *   - Route discovery is now delegated to [BootstrapResolver], which tries
 *     multiple independent channels (Direct Broker, GitHub, GitLab,
 *     Cloudflare R2) in order until one succeeds.
 *   - Removed `parseFirstRoute()` — parsing is now handled by
 *     [BootstrapResolver].
 *
 * Privacy rules:
 *   - No user identity, Telegram data, or end-user information is accessed.
 *   - No logs beyond operational VPN state transitions.
 *   - Route data is held in memory only.
 *   - SharedPreferences stores only a boolean toggle — no route data or IPs.
 */
object VpnManager {

    private const val TAG = "ZAT"
    private const val PREFS_NAME = "zat_vpn_prefs"
    private const val KEY_VPN_ENABLED = "vpn_enabled"

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Checks whether the Android VPN permission is already granted.
     *
     * @param context Application or Activity context.
     * @return `null` if the VPN permission is already granted and the service
     *         can be started immediately. Otherwise, returns an [Intent] that
     *         the caller must launch with `startActivityForResult` to show
     *         the system VPN consent dialog. The result should be checked
     *         for [android.app.Activity.RESULT_OK] before calling [startVpn].
     */
    fun prepareVpn(context: Context): Intent? {
        return VpnService.prepare(context)
    }

    /**
     * Starts the [ZatVpnService] foreground service.
     *
     * The caller MUST ensure [prepareVpn] returned `null` (permission granted)
     * before calling this method. Starting without permission will cause the
     * VPN establishment to fail silently.
     *
     * @param context Application or Activity context.
     * @param routeJson Optional serialized [VpnRoute] JSON string. If provided,
     *                  the service will start the protocol fallback engine with
     *                  this route. If null, the tun interface is established but
     *                  no connection attempt is made.
     */
    fun startVpn(context: Context, routeJson: String? = null) {
        Log.i(TAG, "Starting ZAT VPN service...")
        val intent = Intent(context, ZatVpnService::class.java)
        if (routeJson != null) {
            intent.putExtra(ZatVpnService.EXTRA_VPN_ROUTE_JSON, routeJson)
        }
        context.startForegroundService(intent)
    }

    /**
     * Starts [ZatVpnService] with a JSON array of candidate routes. The service
     * tries them in order, failing over to the next when a server's protocols
     * are all exhausted (server-level failover).
     *
     * @param context Application or Activity context.
     * @param routesJson Serialized JSON array of [VpnRoute].
     */
    fun startVpnWithRoutes(context: Context, routes: List<VpnRoute>) {
        Log.i(TAG, "Starting ZAT VPN service (multi-route failover, ${routes.size} routes)...")
        // Hand the (potentially large) route list to the service in-process via a
        // static holder rather than an Intent extra: ~20 full OpenVPN configs blow
        // past the Binder transaction limit and silently break the service start.
        ZatVpnService.pendingRoutes = routes
        val intent = Intent(context, ZatVpnService::class.java)
        intent.putExtra(ZatVpnService.EXTRA_USE_PENDING_ROUTES, true)
        context.startForegroundService(intent)
    }

    /**
     * Starts [ZatVpnService] on the sing-box / VLESS-Reality path for [server].
     *
     * The Reality server is handed to the service in-process (a [RealityServer]
     * holder) rather than as an Intent extra, mirroring [startVpnWithRoutes].
     */
    fun startReality(context: Context, server: RealityServer) {
        Log.i(TAG, "Starting ZAT VPN service (Reality)...")
        ZatVpnService.pendingRealityServer = server
        val intent = Intent(context, ZatVpnService::class.java)
        intent.putExtra(ZatVpnService.EXTRA_USE_REALITY, true)
        context.startForegroundService(intent)
    }

    /**
     * Starts [ZatVpnService] on the two-hop BLIND Model-B path: the client dials
     * the [exit] (inner Reality) THROUGH the matched [volunteer] (outer Reality).
     * The selection is staged in-process (a [TwoHopRoute] holder), mirroring
     * [startReality].
     */
    fun startTwoHop(
        context: Context,
        volunteer: RealityRoute,
        exit: RealityRoute,
        introducerUrl: String,
        country: String,
    ) {
        Log.i(TAG, "Starting ZAT VPN service (Reality two-hop)...")
        ZatVpnService.pendingTwoHop = TwoHopRoute(volunteer, exit)
        // The introducer URL + country let the service re-match a fresh volunteer on
        // its own when this one churns out of the pool (auto-re-match).
        ZatVpnService.pendingReMatch = ReMatchContext(introducerUrl, country)
        val intent = Intent(context, ZatVpnService::class.java)
        intent.putExtra(ZatVpnService.EXTRA_USE_TWO_HOP, true)
        context.startForegroundService(intent)
    }

    /**
     * Starts [ZatVpnService] on the reach-over-Reality path (MESH Stage 1): the service
     * brings up a bootstrap libbox (a local SOCKS proxy dialed through the Reality
     * [entry]), runs the rendezvous match THROUGH it (broker SNI/IP/DNS never on the
     * wire), then hands off to the two-hop blind data path on the matched volunteer +
     * [exit]. The selection is staged in-process (mirroring [startTwoHop]).
     */
    fun startRendezvousOverReality(
        context: Context,
        entry: RealityRoute,
        exit: RealityRoute,
        introducerUrl: String,
        country: String,
    ) {
        Log.i(TAG, "Starting ZAT VPN service (reach-over-Reality rendezvous)...")
        ZatVpnService.pendingRendezvousEntry = entry
        ZatVpnService.pendingRendezvousExit = exit
        ZatVpnService.pendingReMatch = ReMatchContext(introducerUrl, country)
        val intent = Intent(context, ZatVpnService::class.java)
        intent.putExtra(ZatVpnService.EXTRA_USE_RENDEZVOUS, true)
        context.startForegroundService(intent)
    }

    /**
     * Stops the [ZatVpnService].
     *
     * @param context Application or Activity context.
     */
    fun stopVpn(context: Context) {
        Log.i(TAG, "Stopping ZAT VPN service...")
        // A VpnService holding an established tun is BOUND by the system, so stopService()
        // alone will NOT destroy it (the binding keeps it alive). Deliver an explicit stop
        // command instead, so the service closes the tun from within — releasing that
        // binding — and stopSelf()s.
        val intent = Intent(context, ZatVpnService::class.java)
            .putExtra(ZatVpnService.EXTRA_STOP, true)
        try {
            context.startService(intent)
        } catch (e: Exception) {
            Log.w(TAG, "startService(stop) failed (${e.javaClass.simpleName}); falling back to stopService.")
            context.stopService(Intent(context, ZatVpnService::class.java))
        }
    }

    /**
     * Persists the user's VPN enabled/disabled preference.
     *
     * This is a simple boolean toggle. No route data, IP addresses, or
     * user identifiers are stored.
     *
     * @param context Application or Activity context.
     * @param enabled Whether the VPN toggle is on.
     */
    fun setVpnEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_VPN_ENABLED, enabled)
            .apply()
    }

    /**
     * Returns whether the user has the VPN toggle enabled.
     *
     * @param context Application or Activity context.
     */
    fun isVpnEnabled(context: Context): Boolean {
        return prefs(context).getBoolean(KEY_VPN_ENABLED, false)
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // --- First-run onboarding flag (shown once). ---
    private const val KEY_ONBOARDING_DONE = "onboarding_done"

    fun isOnboardingDone(context: Context): Boolean =
        prefs(context).getBoolean(KEY_ONBOARDING_DONE, false)

    fun setOnboardingDone(context: Context, done: Boolean) {
        prefs(context).edit().putBoolean(KEY_ONBOARDING_DONE, done).apply()
    }

    // --- Battery saver: pause the tunnel while the screen is off (opt-in). ---
    private const val KEY_BATTERY_SAVER = "battery_saver"

    fun isBatterySaver(context: Context): Boolean =
        prefs(context).getBoolean(KEY_BATTERY_SAVER, false)

    fun setBatterySaver(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_BATTERY_SAVER, enabled).apply()
    }

    // --- UI language for the ZAT screens: "fa" or "en". Defaults to the
    //     device locale (Persian → fa, otherwise en). ---
    private const val KEY_LANG = "ui_lang"

    fun getLang(context: Context): String {
        val def = if (java.util.Locale.getDefault().language == "fa") "fa" else "en"
        return prefs(context).getString(KEY_LANG, def) ?: def
    }

    fun setLang(context: Context, lang: String) {
        prefs(context).edit().putString(KEY_LANG, lang).apply()
    }

    // --- Invite-graph tier credential (INVITE_GRAPH_v0.1 §9 / REMAINING_ITEMS P3.1): the capability an
    //     inviter hands the user (a signed tier credential). Presented on match to earn its tier — a
    //     bigger slice + a lower PoW. Null/blank = no credential = tier T0 (default). Persisted so the
    //     user keeps their tier across sessions. Opaque to us; the broker verifies it, never stores it. ---
    private const val KEY_INVITE_CREDENTIAL = "invite_credential"

    /** The stored invite-graph tier credential, or null if none (→ tier T0). */
    fun inviteCredential(context: Context): String? =
        prefs(context).getString(KEY_INVITE_CREDENTIAL, null)?.ifBlank { null }

    /** Store (or, with null/blank, clear) the user's invite-graph tier credential. */
    fun setInviteCredential(context: Context, credential: String?) {
        prefs(context).edit().apply {
            if (credential.isNullOrBlank()) remove(KEY_INVITE_CREDENTIAL)
            else putString(KEY_INVITE_CREDENTIAL, credential.trim())
        }.apply()
    }

    /**
     * Invite-graph I2 (P3.1): mint a CHILD invitation from the user's OWN stored credential, to hand to
     * someone they invite. Resolves the introducer from the signed snapshot, then mints via /invite.
     * Returns the child credential string, or null (no stored credential / invitations disabled /
     * fan-out budget exhausted / transport).
     *
     * Do this while DISCONNECTED: once the two-hop tun is up the app's own DNS is captured by the exit,
     * so the snapshot fetch can't reach its channels. (The SOCKS reach-over-Reality mint —
     * `RendezvousClient.mintInvitationViaSocks` — is the connected-path variant, wired later.)
     * Blocking I/O — call from a background thread.
     */
    fun mintInvitation(context: Context, protect: ((java.net.Socket) -> Boolean)? = null): String? {
        val parent = inviteCredential(context) ?: return null
        return try {
            val introducerUrl = BootstrapResolver.resolve(protect).introducerUrl
            if (introducerUrl.isBlank()) return null
            val inviteUrl = introducerUrl.trimEnd('/') + "/v1/rendezvous/invite"
            RendezvousClient.mintInvitation(inviteUrl, parent, protect)
        } catch (e: Exception) {
            Log.w(TAG, "VpnManager: mint invitation failed: ${e.javaClass.simpleName}")
            null
        }
    }

    /**
     * Uses [BootstrapResolver] to discover a VPN route via the multi-channel
     * fallback chain, then starts [ZatVpnService] with the resolved route.
     *
     * This method returns immediately. The route resolution and VPN start
     * happen asynchronously on a new thread.
     *
     * The [BootstrapResolver] tries channels in order (Direct Broker →
     * GitHub → GitLab → Cloudflare R2), each with a 5-second timeout.
     * If all channels fail, the VPN is not started and an error is logged.
     *
     * Privacy: No user data is sent. Soft app identity headers are only
     * sent to the Direct Broker channel, never to public platforms.
     *
     * @param context Application or Activity context.
     */
    @JvmOverloads
    fun fetchRouteAndStartVpn(
        context: Context,
        protect: ((java.net.Socket) -> Boolean)? = null,
        /**
         * WHO asked for a connect. Added because a live capture showed TWO full bootstrap resolutions
         * for a single tap and the log could not say where the second came from.
         *
         * The note that used to sit here said "this function has two callers (the UI and the service's
         * routeless-restart path)" and, having ruled the service path out, concluded no source could be
         * identified. **That was wrong, and it was wrong in the way that mattered: there were SEVEN
         * call sites**, five of them in the Telegram fork passing no trigger at all. The investigation
         * eliminated the wrong candidate set and then trusted the elimination.
         *
         * The likely pair is now plain: `ApplicationLoader` auto-starts the VPN on launch when the
         * toggle is on, so opening the app and tapping Connect fires two resolutions moments apart —
         * the first from a caller the user never invoked and the log could not name.
         *
         * Every call site names itself now, and [resolveInFlight] means a second one cannot run
         * concurrently regardless. Kept as a required-by-convention argument rather than defaulted, so
         * a NEW caller has to decide what it is called instead of inheriting "unknown".
         */
        trigger: String = "unknown",
    ) {
        val appContext = context.applicationContext

        // #19: only ONE bootstrap resolution at a time.
        //
        // Every call spawned a thread that swept all six bootstrap channels, with nothing stopping two
        // from running at once — and two do run at once, routinely. `ApplicationLoader` auto-starts the
        // VPN on app launch when the toggle is on, so opening the app and then tapping Connect fires
        // two independent resolutions moments apart. That is what a live capture saw and what the log
        // could not explain.
        //
        // It is not merely wasteful. A resolution is a full sweep of six channels, so two concurrent
        // ones DOUBLE the network fingerprint at the exact moment a censored user is most exposed —
        // and both threads then race to start the VPN.
        //
        // The loser returns instead of queueing: a second connect request while one is already
        // resolving wants the same outcome the first is already producing, and waiting for a turn
        // would only run the redundant sweep later.
        if (!resolveInFlight.compareAndSet(false, true)) {
            Log.i(TAG, "Bootstrap resolution already in flight (trigger=$trigger) — not starting a second.")
            return
        }
        Thread {
            try {
                // A4: mint a fresh per-session allocation token — a distinct, burnable, unlinkable
                // client identity for the gate (meter/slice/Trace-1), stable across this session's
                // matches + re-matches, gone at the next.
                sessionToken = newSessionToken()
                // The dissolution scoreboard for this attempt starts at zero; every reach for the
                // broker from here on is recorded with why (`BrokerReliance`).
                BrokerReliance.beginAttempt()
                // Invite-graph I1: present the stored tier credential (if any) on every match this
                // session — a bigger slice + a lower PoW. Null = tier T0 (today's behaviour).
                RendezvousClient.presentedCredential = inviteCredential(appContext)
                Log.i(TAG, "Resolving bootstrap snapshot via BootstrapResolver (trigger=$trigger)...")
                val resolved = BootstrapResolver.resolve(protect)

                // Prefer the anti-DPI Reality transport when the signed snapshot
                // offers one; otherwise fall back to SSTP server-failover.
                val realityServers = resolved.realityServers
                val introducerUrl = resolved.introducerUrl
                when {
                    // MESH Stage 1 (reach-over-Reality): a rendezvous-entry is published,
                    // so route the match THROUGH it over Reality — the censor sees only an
                    // indistinguishable Reality handshake, never the broker's SNI/IP/DNS.
                    // The match itself runs INSIDE the service (it needs the bootstrap
                    // libbox + VpnService.protect), so we only stage + start here.
                    realityServers.isNotEmpty() && introducerUrl.isNotBlank() &&
                        resolved.rendezvousEntries.isNotEmpty() -> {
                        val entry = toEntryRoute(resolved.rendezvousEntries.first())
                        val exit = toExitRoute(realityServers.first())
                        Log.i(TAG, "reach-over-Reality: routing the match through a Reality entry...")
                        startRendezvousOverReality(
                            appContext, entry, exit, introducerUrl, deviceCountry(appContext),
                        )
                    }
                    // Model B: a live introducer + a thin exit → match a CURRENTLY-LIVE
                    // volunteer and tunnel through it (two-hop blind). Falls back to
                    // single-hop Reality if no live volunteer has capacity.
                    realityServers.isNotEmpty() && introducerUrl.isNotBlank() -> {
                        val exit = realityServers.first()
                        val matchUrl = introducerUrl.trimEnd('/') + "/v1/rendezvous/match"
                        // The heaviest reliance of all: the mesh did not produce a volunteer, so the
                        // broker is picking one. R19 was months of exactly this, invisible because the
                        // connection still succeeded.
                        BrokerReliance.note(BrokerReliance.Reason.MATCH)
                        val handle = RendezvousClient.requestMatch(
                            matchUrl, sessionToken, deviceCountry(appContext), protect,
                        )
                        if (handle != null) {
                            Log.i(TAG, "Live volunteer matched (tier ${handle.volunteer.tier}). Starting two-hop VPN...")
                            startTwoHop(
                                appContext,
                                toVolunteerRoute(handle),
                                toExitRoute(exit),
                                introducerUrl,
                                deviceCountry(appContext),
                            )
                        } else {
                            Log.i(TAG, "No live volunteer with capacity; falling back to single-hop Reality.")
                            startReality(appContext, exit)
                        }
                    }
                    realityServers.isNotEmpty() -> {
                        val server = realityServers.first()
                        Log.i(TAG, "Reality server selected (${server.countryShort.ifEmpty { "??" }}). Starting VPN...")
                        startReality(appContext, server)
                    }
                    resolved.sstpRoutes.isNotEmpty() -> {
                        val top = resolved.sstpRoutes.first()
                        Log.i(TAG, "${resolved.sstpRoutes.size} SSTP route(s) resolved (top: ${top.host} / ${top.countryShort}). Starting VPN...")
                        startVpnWithRoutes(appContext, resolved.sstpRoutes)
                    }
                    else -> Log.e(TAG, "All bootstrap channels failed. VPN not started.")
                }
            } catch (e: IOException) {
                Log.w(TAG, "Network error during bootstrap resolution: ${e.message}")
            } catch (e: Exception) {
                Log.w(TAG, "Error during bootstrap resolution: ${e.message}")
            } finally {
                // Released on EVERY path, including the failure ones. A guard that leaks on error
                // would turn one bad bootstrap into a client that can never try again — trading a
                // duplicate resolve for a permanent outage, which is the worse of the two.
                resolveInFlight.set(false)
            }
        }.start()
    }

    /**
     * #19: whether a bootstrap resolution is currently running. See [fetchRouteAndStartVpn].
     *
     * Guards the WHOLE resolve-and-start body rather than just the fetch, because the duplicate that
     * matters is two threads both reaching the VPN start, not two HTTP calls.
     */
    private val resolveInFlight = java.util.concurrent.atomic.AtomicBoolean(false)

    /**
     * A4 (GATE §5/§7): the per-session allocation token. A fresh cryptographically-random value each
     * VPN session, STABLE across that session's matches + re-matches so the gate can meter, slice, and
     * Trace-1-score it, then BURNED at the next session — the "anonymous, burnable" tier. IP-free +
     * unlinkable across sessions (nothing persisted). The per-match PoW (`RendezvousClient.obtainPow`)
     * is the anti-flood cost; this token is the per-client identity that PoW is bound to. Replaces the
     * shared "prototype" placeholder so per-client metering is real once `ZAT_POW_REQUIRED` flips on.
     */
    @Volatile
    private var sessionToken: String = newSessionToken()

    /** A cryptographically-random 128-bit token as 32 lowercase hex chars — opaque to the gate, pure
     *  JVM (no `android.util.Base64`, which forces an API level; `java.util.Base64` needs API 26). */
    private fun newSessionToken(): String {
        val bytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * B1a.1: route volunteer discovery through the oblivious mesh directory instead of `/match`, so
     * no single party learns which volunteers a token reads.
     *
     * **ON since 2026-07-28.** It was `false` from the day it was written, waiting for "a
     * `ZAT_MESH_ENABLED` broker" — and because it is a compile-time constant, R8 was eliminating the
     * whole branch as dead code and dropping `MeshRendezvousClient` from the APK entirely. So the
     * decentralized directory that the removability of the broker rests on had never been in a build
     * anyone could install; every shipped client matched through `/match`, i.e. through us. Found by
     * reading the shipped dex rather than the source.
     *
     * Two things had to be true before turning it on, and now both are: the broker runs a live mesh,
     * and — since `mesh_entry` landed in the signed snapshot — a client no longer has to call us even
     * to ENTER the mesh.
     *
     * Still safe by construction: `meshMatchViaSocks` returning null falls through to `/match`, so a
     * mesh that is off, empty or unreachable costs a connection attempt, never connectivity.
     */
    private const val MESH_ENABLED = true

    /**
     * A2 shard-read host: a placeholder DOMAIN (never resolved by the client) used as the shard-read
     * target so OkHttp routes it THROUGH the per-shard SOCKS (remote DNS) instead of bypassing the
     * proxy for an IP literal. The volunteer's egress rule (`singbox.rs`) domain-matches this EXACT
     * string and rewrites it to `127.0.0.1:shardPort` — so it MUST stay in sync with `singbox.rs`.
     */
    private const val SHARD_READ_HOST = "shard.zat"

    /** The matched volunteer becomes the OUTER (no-flow) Reality hop. */
    private fun toVolunteerRoute(handle: VolunteerHandle): RealityRoute {
        val v = handle.volunteer
        return RealityRoute(
            serverAddress = v.host,
            serverPort = v.port,
            uuid = v.reality.uuid,
            realityPublicKey = v.reality.publicKey,
            shortId = v.reality.shortId,
            serverName = v.reality.serverName,
            fingerprint = v.reality.fingerprint,
            flow = "", // the volunteer bridge is a no-flow Reality inbound (proven pattern)
            volunteerId = v.volunteerId, // carried for the /report Trace-1 signal
            handleId = handle.handleId, // R5: the trace counters only accept a handle-proven report
        )
    }

    /**
     * Trace-1 client signal (GATE §B.2): QUEUE whether the client could reach [volunteerId]
     * in-country (ok=false on a still-heartbeating volunteer = the "blocked" signal; ok=true
     * = a clean connect). IP-free. The queue is flushed over the bootstrap SOCKS on the next
     * connect / re-match, so reports ride Reality (a direct send can't even resolve the
     * broker once the Telegram-only tun is up — UnknownHostException).
     */
    internal fun reportConnect(volunteerId: String, handleId: String, ok: Boolean) {
        RendezvousClient.enqueueReport(volunteerId, handleId, ok)
    }

    /** Our thin exit becomes the INNER Reality hop; it declares its own flow. */
    private fun toExitRoute(exit: RealityServer): RealityRoute =
        RealityRoute(
            serverAddress = exit.address,
            serverPort = exit.port,
            uuid = exit.uuid,
            realityPublicKey = exit.publicKey,
            shortId = exit.shortId,
            serverName = exit.serverName,
            fingerprint = exit.fingerprint,
            flow = exit.flow,
        )

    /**
     * A rendezvous-entry (snapshot `rendezvous_entries[]`) → its Reality route. The
     * entry is a plain vless+reality inbound, so [RealityServer.flow] is published as
     * "" (no vision) — matching RealitySingBoxConfig.buildRendezvousProxy.
     */
    private fun toEntryRoute(entry: RealityServer): RealityRoute =
        RealityRoute(
            serverAddress = entry.address,
            serverPort = entry.port,
            uuid = entry.uuid,
            realityPublicKey = entry.publicKey,
            shortId = entry.shortId,
            serverName = entry.serverName,
            fingerprint = entry.fingerprint,
            flow = entry.flow,
        )

    /**
     * Re-match: ask the introducer for a FRESH live volunteer when the current one
     * has churned out of the pool. Returns the new OUTER-hop route, or null if no
     * live volunteer has capacity / the introducer is unreachable. Blocking I/O —
     * the [ZatVpnService] supervisor calls it off the main thread.
     */
    internal fun rematchVolunteer(
        introducerUrl: String,
        country: String,
        protect: ((java.net.Socket) -> Boolean)?,
    ): RealityRoute? {
        val matchUrl = introducerUrl.trimEnd('/') + "/v1/rendezvous/match"
        BrokerReliance.note(BrokerReliance.Reason.MATCH)
        val handle = RendezvousClient.requestMatch(matchUrl, sessionToken, country, protect)
            ?: return null
        return toVolunteerRoute(handle)
    }

    /**
     * Reach-over-Reality match (MESH Stage 1): ask the introducer for a live volunteer
     * THROUGH the local SOCKS proxy at `127.0.0.1:[socksPort]` (the bootstrap libbox),
     * so the broker's SNI/IP/DNS never appear on the wire. Returns the OUTER-hop route,
     * or null if no live volunteer has capacity / the introducer is unreachable. Blocking
     * I/O — the [ZatVpnService] bootstrap calls it off the main thread.
     */
    internal fun matchVolunteerViaSocks(
        introducerUrl: String,
        country: String,
        socksPort: Int,
        entry: RealityRoute,
        engine: RealityEngine,
    ): RealityRoute? {
        // B1a.1: when enabled, discover via the oblivious mesh directory (the broker never
        // learns which volunteers this token reads). Falls back to /match if the mesh is
        // off/empty on the broker, so enabling it never breaks connectivity.
        if (MESH_ENABLED) {
            meshMatchViaSocks(introducerUrl, socksPort, entry, engine)?.let { return it }
        }
        val matchUrl = introducerUrl.trimEnd('/') + "/v1/rendezvous/match"
        val handle = RendezvousClient.requestMatchViaSocks(matchUrl, sessionToken, country, socksPort)
            ?: return null
        return toVolunteerRoute(handle)
    }

    /**
     * Mesh discovery over the bootstrap SOCKS (B1a.1): fetch this token's volunteer slice
     * from the broker's `/mesh` (oblivious VOPRF + PoW-walled reads), pick one, and return
     * its outer-hop route. The mesh base URL is derived from the introducer (same broker).
     */
    private fun meshMatchViaSocks(
        introducerUrl: String,
        socksPort: Int,
        entry: RealityRoute,
        engine: RealityEngine,
    ): RealityRoute? {
        val meshBaseUrl = introducerUrl.trimEnd('/') + "/v1/rendezvous/mesh"
        // B1b shard transport: read shards over a Reality tunnel per shard-volunteer (one
        // engine hot-reload), keeping the broker SOCKS for the VOPRF.
        val shardTunnels = ShardTunnels { seeds ->
            openShardTunnels(entry, engine, socksPort, seeds)
        }
        val volunteers = MeshRendezvousClient.discover(
            meshBaseUrl, sessionToken, ProtectedHttp.socksClient(socksPort), shardTunnels,
        )
        val v = pickMeshVolunteer(volunteers) ?: return null
        android.util.Log.i(TAG, "Mesh: matched a volunteer from a slice of ${volunteers.size}.")
        return RealityRoute(
            serverAddress = v.host,
            serverPort = v.port,
            uuid = v.reality.uuid,
            realityPublicKey = v.reality.publicKey,
            shortId = v.reality.shortId,
            serverName = v.reality.serverName,
            fingerprint = v.reality.fingerprint,
            flow = "",
            volunteerId = v.volunteerId,
        )
    }

    /**
     * B1b shard transport (`docs/MESH_SHARD_TRANSPORT_v0.1.md`): open one Reality tunnel per
     * shard-volunteer in a SINGLE engine hot-reload (keeping the bootstrap SOCKS on [socksPort]
     * so the broker VOPRF keeps flowing), and return how to read each shard's loopback HTTP over
     * its own tunnel. `[]` on any failure → the client reads the broker's mirror store instead.
     */
    private fun openShardTunnels(
        entry: RealityRoute,
        engine: RealityEngine,
        socksPort: Int,
        seeds: List<MeshShardSeed>,
    ): List<ShardRead> {
        val usable = seeds.filter { it.reality != null && it.shardPort != null }
        if (usable.isEmpty()) return emptyList()
        val tunnels = usable.mapIndexed { i, s ->
            val r = s.reality!!
            RealitySingBoxConfig.ShardTunnel(
                RealityRoute(
                    serverAddress = r.host,
                    serverPort = r.port,
                    uuid = r.uuid,
                    realityPublicKey = r.publicKey,
                    shortId = r.shortId,
                    serverName = r.serverName,
                    fingerprint = r.fingerprint,
                    flow = "",
                ),
                socksPort = socksPort + 1 + i,
            )
        }
        return runCatching {
            engine.start(RealitySingBoxConfig.buildShardReadProxy(entry, socksPort, tunnels))
            usable.mapIndexed { i, s ->
                ShardRead(
                    // A2 device-fix: read the shard over a placeholder DOMAIN, not an IP —
                    // OkHttp/JVM bypasses the SOCKS proxy for an IP-literal target (loopback OR public),
                    // connecting directly; only a DOMAIN is sent THROUGH the SOCKS (remote DNS). The
                    // volunteer's P1 egress rule (singbox.rs) domain-matches SHARD_READ_HOST + rewrites
                    // it to 127.0.0.1:shardPort, so it's still that volunteer's own shard only.
                    baseUrl = "http://$SHARD_READ_HOST:${s.shardPort}",
                    client = ProtectedHttp.socksClient(socksPort + 1 + i),
                    // B2a: carry the committee slot so the same tunnel serves this shard's
                    // /threshold/* endpoints (the committee IS the reachable shard set).
                    committeeId = s.committeeId,
                )
            }
        }.getOrElse {
            android.util.Log.w(TAG, "Mesh: shard tunnels failed (${it.javaClass.simpleName}); broker fallback.")
            emptyList()
        }
    }

    /** Pick from the slice: best reachability tier first, then random for load spread. */
    private fun pickMeshVolunteer(vs: List<MeshVolunteer>): MeshVolunteer? {
        if (vs.isEmpty()) return null
        val best = vs.minOf { tierRank(it.tier) }
        return vs.filter { tierRank(it.tier) == best }.random()
    }

    private fun tierRank(tier: String): Int = when (tier) {
        "tier1a" -> 0
        "tier1b" -> 1
        "tier2" -> 2
        else -> 3
    }

    /**
     * The client's country (ISO-2) for geo-aware matching. Prototype: the device's
     * network / SIM / locale country. Production should derive it server-side from
     * the connection IP's GeoIP, so a client cannot self-report a country to reach
     * a volunteer that excluded it.
     */
    private fun deviceCountry(context: Context): String {
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? android.telephony.TelephonyManager
        val candidates = listOf(
            tm?.networkCountryIso.orEmpty().uppercase(),
            tm?.simCountryIso.orEmpty().uppercase(),
            java.util.Locale.getDefault().country.uppercase(),
        )
        return candidates.firstOrNull { it.length == 2 } ?: "ZZ"
    }
}
