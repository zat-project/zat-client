package zat.manager.vpn

import android.util.Log
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import zat.manager.models.VolunteerHandle

/**
 * RendezvousClient — the client side of the live introducer (L2 of
 * `RENDEZVOUS_DESIGN_v0.1.md`). Asks the introducer for a CURRENTLY-LIVE volunteer
 * and parses the single-use handle. The data path then dials the volunteer (outer
 * Reality) and, through it, our exit (inner Reality) — see
 * [zat.manager.vpn.engine.reality.RealitySingBoxConfig.buildTwoHop].
 *
 * Privacy: sends only `{token, country}` — no identity, no IP. Logs only a status
 * line with no addresses. Nothing is persisted.
 */
object RendezvousClient {

    private const val TAG = "ZAT"
    /** Wall-clock budget for solving a PoW challenge (well inside the 60s challenge TTL). */
    private const val MAX_SOLVE_MS = 30_000L
    /** Cap the queued Trace-1 reports so a long-lived session can't grow it unbounded. */
    private const val MAX_PENDING_REPORTS = 50
    private val json = Json { ignoreUnknownKeys = true }
    private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()

    /**
     * Invite-graph I1 (INVITE_GRAPH_v0.1 §9): the tier credential to PRESENT on the gate. [VpnManager]
     * sets it once per VPN session from prefs (stable across the session's matches + re-matches, like
     * the session token). Null = present nothing = tier T0 (today's default). When set, it rides EVERY
     * /pow-challenge + /match on all paths (direct, reach-over-Reality, re-match), so the gate lifts the
     * token's tier: a bigger slice + a lower PoW. Nothing is persisted here — the credential lives in
     * prefs; the broker never stores it (verify-only), and it carries no user IP.
     */
    @Volatile
    var presentedCredential: String? = null

    /** The /pow-challenge request body (pure, JVM-testable). Carries the tier [credential] when set. */
    internal fun powChallengeBody(token: String, credential: String?): String =
        buildJsonObject {
            put("token", token)
            credential?.let { put("credential", it) }
        }.toString()

    /** The /match request body (pure, JVM-testable). Echoes the PoW when present, and the tier
     *  [credential] when set (matchSchema). */
    internal fun matchBody(
        token: String,
        country: String,
        pow: Pair<PowChallenge, String>?,
        credential: String?,
    ): String =
        buildJsonObject {
            put("token", token)
            put("country", country)
            credential?.let { put("credential", it) }
            if (pow != null) {
                // Echo the challenge back verbatim + the solution (matchSchema).
                putJsonObject("challenge") {
                    put("nonce", pow.first.nonce)
                    put("difficulty", pow.first.difficulty)
                    put("tokenId", pow.first.tokenId)
                    put("exp", pow.first.exp)
                    put("mac", pow.first.mac)
                }
                put("powSolution", pow.second)
            }
        }.toString()

    /**
     * Requests a live volunteer match. [matchUrl] is the introducer's
     * `/v1/rendezvous/match` endpoint (discovered from the signed snapshot).
     * [protect] protects the socket under VPN lockdown (as the bootstrap fetch
     * does). Returns null if the introducer is unreachable or no volunteer has
     * capacity for this country.
     *
     * Blocking I/O — call from a background thread only.
     */
    fun requestMatch(
        matchUrl: String,
        token: String,
        country: String,
        protect: ((java.net.Socket) -> Boolean)? = null,
    ): VolunteerHandle? {
        val client = ProtectedHttp.client(protect)
        return doMatch(matchUrl, token, country, obtainPow(matchUrl, token, client), client)
    }

    /**
     * Reach-over-Reality variant (MESH Stage 1): runs the match (and its PoW challenge)
     * THROUGH the local SOCKS proxy at `127.0.0.1:[socksPort]` (the bootstrap libbox's
     * `mixed` inbound), so they ride a Reality handshake to the rendezvous-entry and the
     * broker's SNI/IP/DNS never appear on the wire. No `protect` is needed (loopback hop).
     *
     * Blocking I/O — call from a background thread only.
     */
    fun requestMatchViaSocks(
        matchUrl: String,
        token: String,
        country: String,
        socksPort: Int,
    ): VolunteerHandle? {
        val client = ProtectedHttp.socksClient(socksPort)
        return doMatch(matchUrl, token, country, obtainPow(matchUrl, token, client), client)
    }

    /**
     * Invite-graph I2 (INVITE_GRAPH_v0.1 §9 / P3.1): mint a bounded CHILD invitation from
     * [parentCredential] via the broker's `/invite`, to hand to someone the user invites. Returns the
     * child credential string, or null on any failure — fan-out budget exhausted / invalid-or-expired
     * parent / max depth (→ 403), or transport. [inviteUrl] is the introducer base + `.../invite`.
     *
     * Blocking I/O — call from a background thread only.
     */
    fun mintInvitation(
        inviteUrl: String,
        parentCredential: String,
        protect: ((java.net.Socket) -> Boolean)? = null,
    ): String? = doMint(inviteUrl, parentCredential, ProtectedHttp.client(protect))

    /** Reach-over-Reality variant: mints THROUGH the local SOCKS at `127.0.0.1:[socksPort]`, so the
     *  broker's SNI/IP/DNS never appear on the wire (use while connected). Blocking I/O. */
    fun mintInvitationViaSocks(inviteUrl: String, parentCredential: String, socksPort: Int): String? =
        doMint(inviteUrl, parentCredential, ProtectedHttp.socksClient(socksPort))

    /** The /invite request body (pure, JVM-testable). */
    internal fun inviteBody(parentCredential: String): String =
        buildJsonObject { put("credential", parentCredential) }.toString()

    /** Parse the minted child credential from the /invite response (pure). Null if absent/malformed. */
    internal fun parseMintedCredential(body: String): String? =
        if (body.isBlank()) null
        else try {
            json.decodeFromString(MintResponse.serializer(), body).credential
        } catch (e: Exception) {
            null
        }

    private fun doMint(inviteUrl: String, parentCredential: String, client: okhttp3.OkHttpClient): String? {
        return try {
            val req = Request.Builder()
                .url(inviteUrl)
                .post(inviteBody(parentCredential).toRequestBody(JSON_MEDIA))
                .build()
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) {
                    Log.w(TAG, "RendezvousClient: invite HTTP ${resp.code}")
                    return null
                }
                parseMintedCredential(resp.body?.string().orEmpty())
            }
        } catch (e: Exception) {
            Log.w(TAG, "RendezvousClient: invite failed: ${e.javaClass.simpleName}")
            null
        }
    }

    @Serializable
    private data class MintResponse(val credential: String? = null)

    /**
     * Best-effort PoW (GATE §A.2): fetch a token-bound challenge from /pow-challenge and
     * solve it, over the SAME [client] (so on the SOCKS path the challenge also rides
     * Reality). Returns null when the broker has no PoW endpoint or the solve times out —
     * the match then carries no PoW (accepted while `ZAT_POW_REQUIRED` is off; rejected
     * 428 once it is on). The challenge URL is the match URL with `match`→`pow-challenge`.
     */
    private fun obtainPow(
        matchUrl: String,
        token: String,
        client: okhttp3.OkHttpClient,
    ): Pair<PowChallenge, String>? {
        return try {
            val challengeUrl = matchUrl.removeSuffix("match") + "pow-challenge"
            val body = powChallengeBody(token, presentedCredential)
            val req = Request.Builder().url(challengeUrl).post(body.toRequestBody(JSON_MEDIA)).build()
            val challenge = client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return null
                json.decodeFromString(PowChallenge.serializer(), resp.body?.string().orEmpty())
            }
            val deadline = minOf(challenge.exp, System.currentTimeMillis() + MAX_SOLVE_MS)
            val solution = RendezvousPow.solve(challenge, deadline)
            if (solution == null) {
                Log.w(TAG, "RendezvousClient: PoW unsolved at difficulty ${challenge.difficulty}.")
                return null
            }
            challenge to solution
        } catch (e: Exception) {
            Log.w(TAG, "RendezvousClient: PoW skipped: ${e.javaClass.simpleName}")
            null
        }
    }

    /** Shared match-request body + parse, over a caller-chosen [client] (direct or SOCKS). */
    private fun doMatch(
        matchUrl: String,
        token: String,
        country: String,
        pow: Pair<PowChallenge, String>?,
        client: okhttp3.OkHttpClient,
    ): VolunteerHandle? {
        return try {
            val body = matchBody(token, country, pow, presentedCredential)
            val req = Request.Builder()
                .url(matchUrl)
                .post(body.toRequestBody(JSON_MEDIA))
                .build()
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) {
                    Log.w(TAG, "RendezvousClient: match HTTP ${resp.code}")
                    return null
                }
                parseHandle(resp.body?.string().orEmpty())
            }
        } catch (e: Exception) {
            Log.w(TAG, "RendezvousClient: match failed: ${e.javaClass.simpleName}")
            null
        }
    }

    // Trace-1 reports are QUEUED, not sent inline. Once the two-hop tun is up, the app's
    // own traffic — including a direct broker call's DNS resolution — is captured by the
    // Telegram-only exit and cannot resolve the broker (UnknownHostException). So queued
    // reports are flushed over the bootstrap SOCKS proxy on the NEXT connect / re-match:
    // they ride Reality and resolve at the entry. Soft signal — a dropped one is fine; the
    // important ok=false (blocked) flushes promptly because a block triggers a re-match.
    // (volunteerId, handleId, ok) — R5: the broker's trace counters are HANDLE-GATED, so the report
    // must carry the single-use handle this client was matched with or it is accepted-and-ignored.
    private val pendingReports =
        java.util.concurrent.ConcurrentLinkedQueue<Triple<String, String, Boolean>>()

    /** Queue an IP-free Trace-1 signal (volunteerId, its match handle, reachable) for the next flush. */
    fun enqueueReport(volunteerId: String, handleId: String, ok: Boolean) {
        if (volunteerId.isNotBlank() && pendingReports.size < MAX_PENDING_REPORTS) {
            pendingReports.add(Triple(volunteerId, handleId, ok))
        }
    }

    /**
     * Flush queued Trace-1 reports through the bootstrap SOCKS proxy at
     * `127.0.0.1:[socksPort]` — they ride Reality to the entry (no broker DNS/SNI on the
     * censored client). Best-effort; a failed send is dropped. Call while the SOCKS is up.
     */
    fun flushReportsViaSocks(reportUrl: String, socksPort: Int) {
        if (pendingReports.isEmpty()) return
        val client = ProtectedHttp.socksClient(socksPort)
        var sent = 0
        var r = pendingReports.poll()
        while (r != null) {
            doReport(reportUrl, r.first, r.second, r.third, client)
            sent++
            r = pendingReports.poll()
        }
        Log.i(TAG, "Trace-1: flushed $sent report(s) over Reality.")
    }

    private fun doReport(
        reportUrl: String,
        volunteerId: String,
        handleId: String,
        ok: Boolean,
        client: okhttp3.OkHttpClient,
    ): Boolean {
        return try {
            val body = buildJsonObject {
                put("volunteerId", volunteerId)
                put("ok", ok)
                // R5: proves this report came from a real match on THIS volunteer (counted once).
                if (handleId.isNotBlank()) put("handleId", handleId)
            }.toString()
            val req = Request.Builder().url(reportUrl).post(body.toRequestBody(JSON_MEDIA)).build()
            client.newCall(req).execute().use { it.isSuccessful }
        } catch (e: Exception) {
            Log.w(TAG, "RendezvousClient: report send failed: ${e.javaClass.simpleName}")
            false
        }
    }

    /**
     * Parses the introducer's match response into a [VolunteerHandle]. Pure (no
     * Android dependencies) so it is unit-testable on the JVM.
     */
    fun parseHandle(body: String): VolunteerHandle? =
        if (body.isBlank()) {
            null
        } else {
            try {
                json.decodeFromString(VolunteerHandle.serializer(), body)
            } catch (e: Exception) {
                null
            }
        }
}
