package zat.manager.vpn

import android.util.Log
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import okhttp3.OkHttpClient
import okhttp3.Request
import zat.manager.models.RealityServer
import zat.manager.models.VpnRoute
import javax.net.ssl.SSLPeerUnverifiedException

/** Both transport families parsed from one Ed25519-verified bootstrap snapshot. */
data class ResolvedBootstrap(
    val sstpRoutes: List<VpnRoute>,
    val realityServers: List<RealityServer>,
    /** The live introducer base URL (Model B); empty → single-hop Reality / SSTP. */
    val introducerUrl: String = "",
    /**
     * Rendezvous-entries (MESH Stage 1): broker-locked Reality inbounds. When present,
     * the client routes its match control traffic THROUGH one over Reality so the
     * broker's SNI/IP/DNS never appear on the wire. Empty → match goes direct.
     */
    val rendezvousEntries: List<RealityServer> = emptyList(),
)

/**
 * BootstrapResolver — Phase 13 (Anti-Censorship Hardened)
 *
 * Implements a censorship-resilient fallback chain for discovering VPN routes.
 * The resolver tries multiple independent channels in priority order:
 *
 *   1. Direct HTTPS to Broker (via Cloudflare)
 *   2. GitHub Raw Content
 *   3. GitLab Raw Content
 *   4. Cloudflare R2 public bucket
 *   5. jsDelivr CDN (auto-mirrors GitHub)
 *   6. Bitbucket Raw Content
 *
 * Anti-censorship hardening (Phase 13):
 *   - All channel URLs are encrypted in StealthConfig (3-layer encryption).
 *   - HTTP requests mimic real browser fingerprints (Chrome/Samsung/Firefox).
 *   - Gaussian timing jitter between channel attempts prevents traffic fingerprinting.
 *   - Logs are sanitized: no URLs, domains, or IPs are logged.
 *
 * Privacy rules:
 *   - No user identity, Telegram data, or device info is sent.
 *   - No app-specific headers are sent to any channel.
 *   - Logs contain only channel numbers and error types.
 */
object BootstrapResolver {

    private const val TAG = "ZAT"

    /**
     * Browser fingerprint profile — mimics a real mobile browser's full
     * HTTP header set to make requests indistinguishable from normal
     * browsing traffic.
     */
    private data class BrowserProfile(
        val headers: List<Pair<String, String>>
    )

    /** Chrome 125 on Android 14 (Pixel 8) — most common Android browser. */
    private val profileChrome = BrowserProfile(
        listOf(
            "User-Agent" to "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36",
            "Accept" to "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language" to "en-US,en;q=0.9",
            "Accept-Encoding" to "gzip, deflate, br",
            "Sec-Fetch-Dest" to "document",
            "Sec-Fetch-Mode" to "navigate",
            "Sec-Fetch-Site" to "none",
            "Sec-Fetch-User" to "?1",
            "Upgrade-Insecure-Requests" to "1",
            "Sec-CH-UA" to "\"Google Chrome\";v=\"125\", \"Chromium\";v=\"125\", \"Not.A/Brand\";v=\"24\"",
            "Sec-CH-UA-Mobile" to "?1",
            "Sec-CH-UA-Platform" to "\"Android\""
        )
    )

    /** Samsung Internet 25 on Galaxy S24 Ultra. */
    private val profileSamsung = BrowserProfile(
        listOf(
            "User-Agent" to "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.6167.178 Mobile Safari/537.36",
            "Accept" to "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language" to "en-US,en;q=0.9",
            "Accept-Encoding" to "gzip, deflate, br",
            "Sec-Fetch-Dest" to "document",
            "Sec-Fetch-Mode" to "navigate",
            "Sec-Fetch-Site" to "none",
            "Upgrade-Insecure-Requests" to "1"
        )
    )

    /** Firefox 126 on Android 14. */
    private val profileFirefox = BrowserProfile(
        listOf(
            "User-Agent" to "Mozilla/5.0 (Android 14; Mobile; rv:126.0) Gecko/126.0 Firefox/126.0",
            "Accept" to "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language" to "en-US,en;q=0.5",
            "Accept-Encoding" to "gzip, deflate, br",
            "Sec-Fetch-Dest" to "document",
            "Sec-Fetch-Mode" to "navigate",
            "Sec-Fetch-Site" to "none",
            "Sec-Fetch-User" to "?1",
            "Upgrade-Insecure-Requests" to "1"
        )
    )

    private val profiles = listOf(profileChrome, profileSamsung, profileFirefox)

    // HTTP clients (plain + lockdown-`protect()`'d) come from [ProtectedHttp],
    // which is shared with RendezvousClient. Endpoint authenticity is enforced by
    // the Ed25519 signature this resolver verifies before accepting any snapshot;
    // the VPN server's TLS is still pinned separately against the snapshot <ca>.

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * A9: where the freshness high-water mark lives across app restarts.
     *
     * Injected rather than taken as a `Context` parameter so this resolver stays a pure object with no
     * Android dependency — the same shape as `StealthConfig`, and the reason it is unit-testable at
     * all. The app installs a real store once at startup, where a `Context` is in scope.
     *
     * With NO store installed the mark is in-memory only: still useful (a stale channel cannot beat a
     * fresh one within a session), but a restart forgets, which is exactly the window a freeze attack
     * wants. Installing one is not optional in production.
     */
    interface FreshnessStore {
        /** Newest `generated_at` ever accepted, epoch ms; 0 when nothing has been. */
        fun read(): Long
        fun write(value: Long)

        /**
         * The last snapshot BODY this device verified, so a client that has connected before survives
         * every channel being blocked at once.
         *
         * This does NOT breach the standing rule that route data stays in memory (`VpnManager`). That
         * rule is about the user's connection history — which bridge THIS person used. A snapshot is
         * the opposite: it is published on six public channels, identical for everyone, and holding a
         * copy says no more than having the app installed. Default no-op so a store that does not want
         * to keep it simply does not.
         */
        fun readSnapshot(): String? = null
        fun writeSnapshot(body: String) {}
    }

    @Volatile private var freshnessStore: FreshnessStore? = null
    @Volatile private var inMemoryHighWater: Long = 0L

    /** Install persistence for the freshness mark. Call once, at startup, before the first resolve. */
    @JvmStatic
    fun installFreshnessStore(store: FreshnessStore) {
        freshnessStore = store
        inMemoryHighWater = maxOf(inMemoryHighWater, runCatching { store.read() }.getOrDefault(0L))
    }

    private fun highWaterMark(): Long = inMemoryHighWater

    private fun rememberHighWaterMark(value: Long) {
        inMemoryHighWater = value
        // A write failure must never cost us the connection — the mark degrades to in-memory, which is
        // weaker but still correct for this session.
        runCatching { freshnessStore?.write(value) }
            .onFailure { Log.w(TAG, "BootstrapResolver: could not persist the freshness mark: ${it.javaClass.simpleName}") }
    }

    /**
     * A9: is this snapshot fresh enough to accept? Records it as the newest when it is.
     *
     * MONOTONIC, deliberately not an expiry. Enforcing `ttl_seconds` would reject a snapshot for a
     * client that had been offline a week, and would turn any publishing gap into an outage —
     * including the gap the broker's own refuse-to-publish guard creates by design. Comparing
     * snapshots only against EACH OTHER also means a wrong device clock cannot lock a user out.
     *
     * A missing or unparseable stamp is REFUSED rather than waved through: our signer always emits
     * one, so its absence is not a case worth being lenient about, and leniency here would be a way
     * around the whole rule.
     *
     * Equal stamps pass — that is simply the same snapshot arriving again, from another channel or
     * another poll.
     */
    internal fun acceptFreshness(stamp: String?, channelLabel: String): Boolean {
        val stampMs = stamp?.let {
            try { java.time.Instant.parse(it).toEpochMilli() } catch (e: Exception) { null }
        }
        if (stampMs == null) {
            Log.w(TAG, "BootstrapResolver: $channelLabel has no readable generated_at, rejecting.")
            return false
        }
        val seen = highWaterMark()
        if (stampMs < seen) {
            Log.w(
                TAG,
                "BootstrapResolver: $channelLabel is OLDER than one already accepted " +
                    "($stampMs < $seen) — refusing a rollback, trying another channel.",
            )
            return false
        }
        if (stampMs > seen) rememberHighWaterMark(stampMs)
        return true
    }

    /** Test seam: forget the mark (and any store), so ordering between tests cannot leak. */
    @JvmStatic
    internal fun resetFreshnessForTest() {
        freshnessStore = null
        inMemoryHighWater = 0L
        inMemorySnapshot = null
    }

    @Volatile private var inMemorySnapshot: String? = null

    private fun rememberLastGoodSnapshot(body: String) {
        inMemorySnapshot = body
        runCatching { freshnessStore?.writeSnapshot(body) }
            .onFailure { Log.w(TAG, "BootstrapResolver: could not persist the last-good snapshot: ${it.javaClass.simpleName}") }
    }

    private fun lastGoodSnapshot(): String? =
        inMemorySnapshot ?: runCatching { freshnessStore?.readSnapshot() }.getOrNull()

    /**
     * #33 — adopt a snapshot served by a PEER, over the mesh, with no channel and no broker involved.
     *
     * This is the step that changes what the six public channels ARE. Today they are the only way a
     * snapshot reaches anyone: block the set and every client is frozen on whatever it last stored,
     * however long ago that was. `docs/DISSOLUTION_ENDGAME_v0.1.md` §1 names that as the residual
     * central dependency no amount of threshold signing removes — switch the publisher off and the
     * document stops moving, because nobody else can write those repos. A volunteer can SERVE it, so
     * the channels demote from "the only source" to "how you find your very first node".
     *
     * Nothing new is trusted. The body goes through exactly the same [parseSnapshot] a channel's does
     * — canonicalised, verified under the pinned committee key, and held to A9's monotonic rule — so
     * a peer cannot forge one and cannot walk this device backwards onto an older one. A peer that
     * lies is caught by the signature; a peer that withholds is merely useless, and we keep what we
     * have. That is the whole reason a signed snapshot does not need a TRUSTED carrier, only a
     * reachable one.
     *
     * Adopting is deliberately quiet: it updates the stored copy that the next cold start falls back
     * to. The improvement lands on the run AFTER this one, which is the run where the channels might
     * be gone.
     *
     * A10 is why this is only shipping now. Until a member could tell an entry somebody stands behind
     * from one nobody does (#37/#38/#40), peer-served snapshots would have spread bad entry points
     * faster than the channels did — the opposite of the point (`docs/A10_EXIT_IDENTITY_v0.1.md` §5).
     *
     * @return true when the peer's snapshot verified AND was fresher than what this device holds.
     */
    fun adoptFromPeer(body: String): Boolean {
        if (body.isBlank()) return false
        val parsed = parseSnapshot(body, "peer snapshot") ?: return false
        if (parsed.sstpRoutes.isEmpty() && parsed.realityServers.isEmpty()) {
            // Verified and fresh, but carrying nothing to connect through. Storing it would let a
            // valid empty document displace a usable one — the same displacement A9 exists to stop,
            // arriving through content rather than through age.
            Log.w(TAG, "BootstrapResolver: a peer's snapshot verified but had no routes — not adopting.")
            return false
        }
        rememberLastGoodSnapshot(body)
        // Both, and they are not the same claim: PEER is only taken if nothing has yet supplied this
        // attempt's snapshot (snapshotFrom is first-writer-wins), while the refresh flag records that
        // a peer served something newer — which today always happens over an already-open tunnel.
        RunDiagnostics.snapshotFrom(RunDiagnostics.Source.PEER)
        RunDiagnostics.peerRefresh()
        Log.i(
            TAG,
            "BootstrapResolver: adopted a snapshot from a PEER — no channel, no broker " +
                "(${parsed.sstpRoutes.size} SSTP + ${parsed.realityServers.size} Reality).",
        )
        return true
    }

    /**
     * Returns a random delay (ms) following a Gaussian distribution to
     * prevent traffic-pattern fingerprinting between channel attempts.
     * Mean: 2000ms, StdDev: 800ms, clamped to [500, 5000].
     */
    private fun randomJitterMs(): Long {
        val gaussian = java.util.Random().nextGaussian() * 800 + 2000
        return gaussian.toLong().coerceIn(500, 5000)
    }

    /**
     * Tries each bootstrap channel in order and returns ALL [VpnRoute]s from
     * the first channel that responds with a valid, signed `BootstrapSnapshot`.
     *
     * Returning the full list (not just the top server) lets the caller fail
     * over across servers when individual VPN Gate nodes are dead — the snapshot
     * routinely carries ~20 quality-ordered candidates, of which the best-scored
     * one may still be unhealthy.
     *
     * Channels are resolved from [StealthConfig] (encrypted). A random browser
     * profile is selected for the entire session. Gaussian timing jitter is
     * inserted between channel attempts.
     *
     * This method performs blocking network I/O — call it from a background
     * thread only.
     *
     * @return All [VpnRoute]s from the snapshot (quality-ordered), or an empty
     *         list if every channel fails.
     */
    fun resolve(protect: ((java.net.Socket) -> Boolean)? = null): ResolvedBootstrap {
        // Select one browser profile for this entire session.
        val profile = profiles.random()
        val channels = StealthConfig.getChannelUrls()
        // Under an always-on VPN with "Block connections without VPN" (lockdown),
        // before any tunnel is up the app's OWN bootstrap fetch is also blocked —
        // so protect() its sockets when a protector is supplied (else deadlock).
        val client = ProtectedHttp.client(protect)
        // #46: record the run so a tester can report WHAT failed, not just that something did.
        RunDiagnostics.beginAttempt(System.currentTimeMillis())

        for ((index, url) in channels.withIndex()) {
            val channelLabel = "Channel ${index + 1}"

            // Insert jitter before retrying (not before the first attempt).
            if (index > 0) {
                try {
                    Thread.sleep(randomJitterMs())
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return ResolvedBootstrap(emptyList(), emptyList())
                }
            }

            try {
                Log.i(TAG, "BootstrapResolver: Trying $channelLabel...")

                val requestBuilder = Request.Builder()
                    .url(url)
                    .get()

                // Apply all headers from the selected browser profile.
                for ((name, value) in profile.headers) {
                    requestBuilder.addHeader(name, value)
                }

                val response = client.newCall(requestBuilder.build()).execute()
                response.use { resp ->
                    if (!resp.isSuccessful) {
                        Log.w(TAG, "BootstrapResolver: $channelLabel returned HTTP ${resp.code}, skipping.")
                        RunDiagnostics.channel(index, false, "http_${resp.code}")
                        return@use
                    }

                    val body = decodeBody(resp, channelLabel)
                    if (body.isNullOrBlank()) {
                        Log.w(TAG, "BootstrapResolver: $channelLabel returned empty body, skipping.")
                        RunDiagnostics.channel(index, false, "empty_body")
                        return@use
                    }

                    val parsed = parseSnapshot(body, channelLabel)
                    if (parsed != null && (parsed.sstpRoutes.isNotEmpty() || parsed.realityServers.isNotEmpty())) {
                        Log.i(TAG, "BootstrapResolver: $channelLabel succeeded. ${parsed.sstpRoutes.size} SSTP + ${parsed.realityServers.size} Reality server(s).")
                        // Remember the SIGNED body only. The unsigned hints are deliberately not
                        // persisted: a stored snapshot is re-verified on load, and mixing an unverifiable
                        // list into it would give the cache an authority the live path never grants.
                        RunDiagnostics.channel(index, true, "ok")
                        rememberLastGoodSnapshot(body)
                        // #31: the third-party SSTP list is fetched separately now, and unsigned. Done
                        // AFTER the snapshot is accepted, so a slow or blocked hint fetch can never
                        // delay or fail a bootstrap that already has everything that matters.
                        val resolved = withFallbackHints(parsed, fetchFallbackHints(parsed.introducerUrl, client))
                        return resolved
                    } else {
                        val resolved = parsed
                        RunDiagnostics.channel(index, false, if (parsed == null) "bad_signature" else "no_routes")
                        Log.w(TAG, "BootstrapResolver: $channelLabel returned no valid routes, skipping.")
                    }
                }
            } catch (e: SSLPeerUnverifiedException) {
                // System TLS rejected the channel cert (untrusted CA or hostname
                // mismatch). Snapshot authenticity is enforced separately by the
                // Ed25519 signature, so we simply skip this channel.
                RunDiagnostics.channel(index, false, "tls")
                Log.w(TAG, "BootstrapResolver: $channelLabel TLS verification failed, skipping.")
            } catch (e: Exception) {
                // Sanitized log: only error type, no URLs/domains/IPs.
                RunDiagnostics.channel(index, false, e.javaClass.simpleName)
                Log.w(TAG, "BootstrapResolver: $channelLabel failed: ${e.javaClass.simpleName}")
            }
        }

        // Every channel is blocked. A client that has connected before should not be finished.
        //
        // All six channels are OUR accounts on public platforms, and a censor that blocks the set
        // blocks every client at once — including one that has worked a hundred times. The last
        // snapshot this device verified is public data it already holds, so falling back to it costs
        // nothing and keeps that user online.
        //
        // Safe because the stored body goes through `parseSnapshot` again: the signature is re-checked
        // against the pinned keys, and A9's freshness rule still applies. Nothing is trusted here that
        // would not be trusted arriving over the wire.
        val stored = lastGoodSnapshot()
        if (stored != null) {
            val resolved = parseSnapshot(stored, "stored snapshot")
            if (resolved != null && (resolved.sstpRoutes.isNotEmpty() || resolved.realityServers.isNotEmpty())) {
                Log.w(
                    TAG,
                    "BootstrapResolver: every channel failed — falling back to the last snapshot this " +
                        "device verified (${resolved.sstpRoutes.size} SSTP + ${resolved.realityServers.size} Reality).",
                )
                RunDiagnostics.snapshotFrom(RunDiagnostics.Source.STORED)
                return resolved
            }
        }

        RunDiagnostics.stage("bootstrap_failed")
        Log.e(TAG, "BootstrapResolver: All bootstrap channels failed.")
        return ResolvedBootstrap(emptyList(), emptyList())
    }

    /** Backward-compatible: just the SSTP routes from the resolved snapshot. */
    fun resolveRoutes(): List<VpnRoute> = resolve().sstpRoutes

    /**
     * Backward-compatible helper: resolves the snapshot and returns only the
     * top [VpnRoute], or `null` if every channel fails.
     */
    fun resolveFirstRoute(): VpnRoute? = resolveRoutes().firstOrNull()

    /**
     * Produces a deterministic JSON string with all object keys sorted
     * recursively at every nesting level, matching the Broker's
     * sortedStringify() implementation exactly. Arrays preserve element
     * order (order is meaningful); only object keys are sorted.
     */
    internal fun sortedStringify(element: JsonElement): String = when (element) {
        is JsonPrimitive -> element.toString()
        is JsonArray     -> "[" + element.joinToString(",") { sortedStringify(it) } + "]"
        is JsonObject    -> {
            val pairs = element.keys.sorted().map { k ->
                "\"$k\":" + sortedStringify(element[k]!!)
            }
            "{" + pairs.joinToString(",") + "}"
        }
    }

    /**
     * #31 — fetch the UNSIGNED fallback list from the introducer, or `null` on any failure.
     *
     * Deliberately best-effort and deliberately last. Everything that matters — the Reality exits, the
     * rendezvous entries, the mesh entry — is already in hand and signed by the time this runs, so a
     * blocked, slow or hostile response costs the user nothing but this list. Returning `null` on every
     * failure rather than throwing keeps that promise structural instead of a matter of care.
     *
     * The URL comes from the snapshot's own `introducer_url`, which is signed — so a censor cannot
     * redirect this fetch by tampering, only block it. Empty introducer (a dissolved deployment, or a
     * snapshot that never carried one) means no fetch at all, which is the correct end state: the
     * fallback is a transitional convenience that disappears with the broker.
     */
    private fun fetchFallbackHints(introducerUrl: String, client: OkHttpClient): String? {
        if (introducerUrl.isBlank()) return null
        return try {
            val url = introducerUrl.trimEnd('/') + "/v1/fallback-servers"
            client.newCall(Request.Builder().url(url).get().build()).execute().use { resp ->
                if (!resp.isSuccessful) null else resp.body?.string()
            }
        } catch (e: Exception) {
            // Sanitized: type only, no URL — the same rule the channel loop follows.
            Log.i(TAG, "BootstrapResolver: no unsigned fallback list (${e.javaClass.simpleName}) — continuing.")
            null
        }
    }

    /**
     * #31 — merge the UNSIGNED third-party fallback list into a resolved bootstrap.
     *
     * The SSTP list is a scrape of VPN Gate: public servers run by strangers, which the committee has
     * no way to verify. It used to ride inside the signed snapshot, where the signature said "the
     * committee vouches for these" — a claim nobody had checked, and the one field a member could
     * never re-derive. It is fetched separately now, and unsigned, which is the honest shape.
     *
     * These are HINTS. The safety argument is not the transport but the destination: connecting to a
     * hostile entry here is exactly the exposure a user had before ZAT existed, because these carry no
     * ZAT secret and no claim from us. Everything that IS ZAT — the Reality exits, the rendezvous
     * entries, the mesh entry — stays inside the signed snapshot and is unaffected by this.
     *
     * Failure is deliberately silent and total: no hints, and the client falls back to Reality and the
     * mesh, both of which are signed. A fallback transport that cannot be reached is a smaller problem
     * than one that is trusted because it answered.
     */
    internal fun withFallbackHints(
        resolved: ResolvedBootstrap,
        hintsBody: String?,
    ): ResolvedBootstrap {
        if (hintsBody.isNullOrBlank()) return resolved
        val hints = try {
            val root = json.parseToJsonElement(hintsBody).jsonObject
            (root["servers"] as? JsonArray).orEmpty().mapNotNull { element ->
                try {
                    json.decodeFromJsonElement(VpnRoute.serializer(), element)
                } catch (e: Exception) {
                    null
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "BootstrapResolver: unsigned fallback list unreadable — continuing without it.")
            return resolved
        }
        if (hints.isEmpty()) return resolved

        // The snapshot's own list comes first when an older broker still supplies one: it is the copy
        // the committee actually signed, so it outranks a hint even though both end up in the same
        // list. De-duplicated by host:port so a transitional overlap does not dial the same server
        // twice and read that as two independent options.
        val seen = resolved.sstpRoutes.map { "${it.host}:${it.port}" }.toMutableSet()
        val merged = resolved.sstpRoutes + hints.filter { seen.add("${it.host}:${it.port}") }
        Log.i(TAG, "BootstrapResolver: ${merged.size - resolved.sstpRoutes.size} unsigned fallback hint(s) merged.")
        return resolved.copy(sstpRoutes = merged)
    }

    /**
     * Verify a raw Ed25519 (RFC 8032) [signature] over [message] against a raw 32-byte [pubKeyBytes].
     * ONE_SHOT_MODE + no MessageDigest = pure Ed25519 (not the Ed25519ph pre-hash). Returns false on
     * ANY failure (bad key length, bad signature), so callers can safely try several pinned keys.
     */
    internal fun verifyEd25519(
        message: ByteArray,
        signature: ByteArray,
        pubKeyBytes: ByteArray,
    ): Boolean = try {
        val curveSpec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
        val pubKey = EdDSAPublicKey(EdDSAPublicKeySpec(pubKeyBytes, curveSpec))
        val verifier = EdDSAEngine()
        verifier.initVerify(pubKey)
        verifier.setParameter(EdDSAEngine.ONE_SHOT_MODE)
        verifier.update(message)
        verifier.verify(signature)
    } catch (e: Exception) {
        false
    }

    /**
     * Parses a signed BootstrapSnapshot and returns ALL servers from the
     * `servers` array (quality-ordered, as the Broker emitted them).
     *
     * The Ed25519 signature is verified once over the whole snapshot before any
     * route is returned; an unsigned or tampered snapshot yields an empty list.
     *
     * Expected format:
     * ```json
     * {
     *   "schema_version": 1,
     *   "signature": "base64...",
     *   "servers": [ { ...VpnRoute fields... }, ... ]
     * }
     * ```
     *
     * @param responseBody Raw JSON string from any bootstrap channel.
     * @param channelLabel Human-readable channel identifier for logs.
     * @return a [ResolvedBootstrap] (SSTP routes + Reality servers), or null if
     *         signature verification or parsing fails.
     */
    /**
     * Read the response as text, decompressing it ourselves when the server used `Content-Encoding`.
     *
     * This has to be explicit because the browser profiles set `Accept-Encoding` by hand, and OkHttp
     * only decompresses transparently for the header IT adds — set it yourself and you own the
     * decoding. We did not, so compressed bodies were read as UTF-8 garbage, failed the `startsWith("{")`
     * check, and were logged as "channel may be challenged/blocked". FOUR of the six bootstrap channels
     * were dead that way (Cloudflare, jsDelivr and Bitbucket serve `br`; raw.githubusercontent serves
     * `gzip`), and the only reason bootstrap worked at all is that GitLab and R2 happened to send
     * identity. The whole point of six channels is that a censor must block all of them — we were
     * running on two, and the log blamed the censor for our own bug.
     *
     * The profiles advertise only what this can decode — advertising an encoding we cannot read is
     * precisely the bug above. `br` is back now that the Brotli decoder is bundled, which restores the
     * exact header Firefox and Samsung Internet send. Chrome 123+ also offers `zstd`; we deliberately
     * do NOT claim it, because a zstd decoder needs per-ABI native libraries and claiming it without
     * one would re-open this exact hole. That leaves a one-token delta on the Chrome profile — a
     * server-visible detail only (headers reach the server or a TLS-terminating middlebox, never a
     * passive censor), and the far smaller risk of the two.
     */
    internal fun decodeBody(resp: okhttp3.Response, channelLabel: String): String? {
        val encoding = resp.header("Content-Encoding")?.trim()?.lowercase()
        val source = resp.body?.byteStream() ?: return null
        return try {
            when (encoding) {
                null, "", "identity" -> source.bufferedReader().readText()
                "gzip" -> java.util.zip.GZIPInputStream(source).bufferedReader().readText()
                "br" -> org.brotli.dec.BrotliInputStream(source).bufferedReader().readText()
                // Raw-deflate and zlib-wrapped deflate both occur in the wild; try zlib, then raw.
                "deflate" -> {
                    val bytes = source.readBytes()
                    try {
                        java.util.zip.InflaterInputStream(bytes.inputStream())
                            .bufferedReader().readText()
                    } catch (_: Exception) {
                        java.util.zip.InflaterInputStream(
                            bytes.inputStream(), java.util.zip.Inflater(true)
                        ).bufferedReader().readText()
                    }
                }
                else -> {
                    // Say what actually happened. Reporting an encoding we cannot read as "blocked"
                    // is worse than a plain failure: in a real censorship event it sends us chasing
                    // a phantom while the true cause is on our side.
                    Log.w(TAG, "BootstrapResolver: $channelLabel used unsupported Content-Encoding '$encoding' — skipping (NOT a blocking signal).")
                    null
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "BootstrapResolver: $channelLabel body could not be decoded (${e.javaClass.simpleName}), skipping.")
            null
        }
    }

    private fun parseSnapshot(responseBody: String, channelLabel: String): ResolvedBootstrap? {
        // A non-JSON 200 body — e.g. a Cloudflare/CDN bot-challenge or an error/interstitial page —
        // would otherwise surface as a confusing "parse error". Detect it up front so the log is
        // diagnostic and failover is immediate: a real snapshot is a JSON object.
        if (!responseBody.trimStart().startsWith("{")) {
            Log.w(TAG, "BootstrapResolver: $channelLabel returned a non-JSON body (channel may be challenged/blocked), skipping.")
            return null
        }
        return try {
            val root = json.parseToJsonElement(responseBody).jsonObject

            // --- Ed25519 signature verification ---
            val signatureField = root["signature"]
            if (signatureField == null) {
                Log.w(TAG, "BootstrapResolver: $channelLabel missing signature, rejecting.")
                return null
            }

            val signatureBase64 = signatureField.jsonPrimitive.content
            val signatureBytes = android.util.Base64.decode(signatureBase64, android.util.Base64.NO_WRAP)

            // Rebuild canonical JSON without the signature field.
            // sortedStringify() sorts all object keys recursively, matching
            // the Broker's sortedStringify() implementation exactly.
            val dataFields = JsonObject(root.filterKeys { it != "signature" })
            val canonicalJson = sortedStringify(dataFields)

            // A3 rung 5 (2026-07-28): verified ONLY against the committee's group key `P_snap`. The
            // broker's own signing key used to be accepted first and has been retired — no key we
            // hold can produce a snapshot this client will take. That is the trust anchor dissolved.
            //
            // `P_snap` null would mean nothing verifies at all, so it is a hard failure with its own
            // message rather than a silent rejection that looks identical to a bad signature.
            val canonicalBytes = canonicalJson.toByteArray(Charsets.UTF_8)
            val anchor = StealthConfig.getSnapshotThresholdPublicKey()
            if (anchor == null) {
                Log.e(TAG, "BootstrapResolver: no pinned committee key in this build — every snapshot will be rejected. This build is broken, not the network.")
                return null
            }
            val accepted = verifyEd25519(canonicalBytes, signatureBytes, anchor)
            if (!accepted) {
                Log.w(TAG, "BootstrapResolver: $channelLabel signature invalid, skipping.")
                return null
            }
            // --- End signature verification ---

            // A9: reject a snapshot OLDER than the newest we have already accepted.
            //
            // A valid signature says "we produced this", not "this is current". Without a freshness
            // rule, anyone who can control one channel or poison a CDN cache pins a client to an old
            // bridge list forever — bridges rotate and get revoked, and that client stays in a world
            // the network has moved past. The signature stays intact throughout, so nothing looks wrong.
            //
            // MONOTONIC, deliberately not an expiry. Enforcing `ttl_seconds` would break a client that
            // has been offline a week and would turn any publishing gap into an outage — including the
            // gap our own refuse-to-publish guard creates by design. Comparing snapshots only against
            // EACH OTHER also means a wrong device clock cannot lock a user out.
            //
            // A snapshot with no readable `generated_at` is refused rather than waved through: our
            // signer always emits it, so its absence is not a case worth being lenient about.
            if (!acceptFreshness(root["generated_at"]?.jsonPrimitive?.contentOrNull, channelLabel)) {
                return null
            }

            // Dissolution: hand the mesh ENTRY to the rendezvous client, so it need not ask the
            // broker for `mesh/params` / `mesh/shards`. Safe to take from here and nowhere else: this
            // object was just verified under the committee's key a few lines above, so a hostile
            // channel cannot inject one. Absent on an older snapshot → the broker is asked as before.
            MeshRendezvousClient.snapshotMeshEntry =
                (root["mesh_entry"] as? JsonObject)?.let {
                    runCatching { json.decodeFromJsonElement(MeshEntry.serializer(), it) }.getOrNull()
                }

            // Decode each entry independently so one malformed item does not
            // discard the whole list.
            //
            // #31: `servers` is a scrape of third-party VPN Gate endpoints and no longer rides inside
            // the signed snapshot — the committee cannot verify a stranger's server list, so signing
            // it asserted something nobody had checked. It now arrives from a separate UNSIGNED fetch
            // and is merged in by the caller ([withFallbackHints]), which keeps this function pure and
            // free of any ordering constraint between a parse and a network round-trip.
            //
            // The field is still read here on purpose: a snapshot published before the split still
            // carries it, and ignoring it would drop the fallback transport for every client that had
            // not yet seen a new snapshot — a self-inflicted outage in the name of tidiness.
            val sstpRoutes = (root["servers"] as? JsonArray).orEmpty().mapNotNull { element ->
                try {
                    json.decodeFromJsonElement(VpnRoute.serializer(), element)
                } catch (e: Exception) {
                    null
                }
            }
            val realityServers = (root["reality_servers"] as? JsonArray).orEmpty().mapNotNull { element ->
                try {
                    json.decodeFromJsonElement(RealityServer.serializer(), element)
                } catch (e: Exception) {
                    null
                }
            }
            val introducerUrl = (root["introducer_url"] as? JsonPrimitive)?.content ?: ""
            val rendezvousEntries = (root["rendezvous_entries"] as? JsonArray).orEmpty().mapNotNull { element ->
                try {
                    json.decodeFromJsonElement(RealityServer.serializer(), element)
                } catch (e: Exception) {
                    null
                }
            }
            ResolvedBootstrap(sstpRoutes, realityServers, introducerUrl, rendezvousEntries)
        } catch (e: Exception) {
            Log.w(TAG, "BootstrapResolver: $channelLabel parse error: ${e.javaClass.simpleName}")
            null
        }
    }
}
