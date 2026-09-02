package zat.manager.vpn

import android.util.Base64
import android.util.Log
import cloud.zat.meshoprf.MeshOprf
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * `mesh_entry` from the SIGNED bootstrap snapshot: everything needed to enter the mesh, carried by
 * the artifact the committee signs rather than fetched from the broker.
 *
 * This is what makes the mesh path independent of us. Before it, a client asked the broker for
 * `mesh/params` and `mesh/shards` and only then talked to nodes — so the "decentralized" path still
 * died when the broker did. Absent on an older snapshot, in which case the broker is asked exactly
 * as before.
 */
@Serializable
data class MeshEntry(
    val suite: String,
    val publicKey: String,
    val N: Int,
    val r: Int,
    val s: Int,
    val epochMs: Long,
    val thresholdT: Int = 0,
    val thresholdN: Int = 0,
    val shards: List<MeshShardSeed> = emptyList(),
)

/** Broker `/mesh/params` — the mesh public key + bucket parameters. */
@Serializable
data class MeshParams(
    val suite: String,
    val publicKey: String, // base64 (standard) of the 32-byte compressed ristretto point
    val N: Int,
    val r: Int,
    val s: Int,
    val epochMs: Long,
    /** B2a: read-first threshold committee size; 0 on an old broker → threshold path off. */
    val thresholdT: Int = 0,
    val thresholdN: Int = 0,
)

/** Outer-hop Reality params inside a mesh record (mirrors the broker's realityParamsSchema). */
@Serializable
data class MeshReality(
    val uuid: String,
    val publicKey: String,
    val shortId: String = "",
    val serverName: String,
    val fingerprint: String = "chrome",
)

/** A volunteer discovered through the mesh (the decrypted `MeshRecordPayload`). */
@Serializable
data class MeshVolunteer(
    val volunteerId: String,
    val host: String,
    val port: Int,
    val reality: MeshReality,
    val tier: String,
)

@Serializable private data class BlindEvaluateResponse(val evaluation: String)
@Serializable private data class ReadResponse(val records: List<String> = emptyList())
@Serializable private data class ThrCommitResponse(val nodeId: Long, val session: Long, val round1: String)
@Serializable private data class ThrRespondResponse(val round2: String)

/** Broker `/mesh/shards` — the volunteer-run Dir shards, each reachable over its OWN
 *  volunteer's egress-locked Reality (`docs/MESH_SHARD_TRANSPORT_v0.1.md`). */
@Serializable private data class ShardsResponse(val shards: List<MeshShardSeed> = emptyList())
@Serializable private data class TrustRevokedResponse(val deltas: List<String> = emptyList())
@Serializable
data class MeshShardSeed(
    val httpEndpoint: String,
    val dhtMultiaddr: String? = null,
    /** How to reach this shard's HTTP over the volunteer's Reality; null on an old broker. */
    val reality: ShardReality? = null,
    /** The shard's loopback HTTP port, read as `127.0.0.1:shardPort` over that Reality tunnel. */
    val shardPort: Int? = null,
    /** B2a: this shard's committee slot (Lagrange id), if it holds a threshold share of `k`. */
    val committeeId: Long? = null,
)

/** The volunteer-bridge Reality a client tunnels through to reach a shard's loopback HTTP. */
@Serializable
data class ShardReality(
    val host: String,
    val port: Int,
    val uuid: String,
    val publicKey: String,
    val shortId: String = "",
    val serverName: String,
    val fingerprint: String = "chrome",
)

/** A per-shard read source: the loopback base URL to read over [client] (a SOCKS client
 *  bound to that shard's Reality tunnel). [committeeId] is set when this shard also holds a
 *  B2a threshold share, so the same tunnel serves its `/threshold/commit|respond` endpoints. */
data class ShardRead(
    val baseUrl: String,
    val client: OkHttpClient,
    val committeeId: Long? = null,
)

/** Opens a Reality tunnel per shard (one engine hot-reload) and returns how to read each;
 *  `[]` if it couldn't (→ the broker mirror is the fallback). Supplied by the caller
 *  (VpnManager), which owns the Reality engine. */
fun interface ShardTunnels {
    fun open(shards: List<MeshShardSeed>): List<ShardRead>
}

/**
 * MeshRendezvousClient — the client side of the DORMANT decentralizable directory (B1a.1).
 * Discovers volunteers by a 2-round VOPRF with the broker + a PoW-walled bucket read +
 * AES-256-GCM open — the decentralizable successor to `/match`.
 *
 * R33 (2026-08-11): this comment used to say the evaluation is OBLIVIOUS and that "the broker never
 * learns which buckets a token reads". BOTH HALVES ARE FALSE AS IMPLEMENTED, and the second one is
 * the reason the first is worth stating carefully. Blinding hides a tag from an evaluator that does
 * not KNOW the tag. Here the tag is `rbkt ‖ token ‖ epoch ‖ j` — a pure function of the token — and
 * the same request hands the broker that token (`mesh.controller.ts:63-68`
 * `blindEvaluate(input.token, input.request)`). The broker also holds `k`
 * (`mesh-service.ts:176`), and `mesh-buckets.ts:89` already ships `readBuckets(evalFn, token,
 * epoch, s, N)` — the recovery takes exactly the two values the broker is given.
 * Not deleted, per the decision record's append-only rule. See R33.
 *
 * All crypto is byte-compatible with the broker (`@cloudflare/voprf-ts`, ristretto255-
 * SHA512): the VOPRF is `MeshOprf` (Rust `.so`), the framing/derivations are [MeshWire].
 * Privacy: sends only `{token}` + opaque blinded elements; no identity, no IP; logs no
 * addresses. Blocking I/O — call from a background thread.
 */
object MeshRendezvousClient {

    private const val TAG = "ZAT"
    private const val MAX_SOLVE_MS = 30_000L
    private val json = Json { ignoreUnknownKeys = true }
    private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()

    /**
     * Discover the token's slice of live volunteers via the mesh. [meshBaseUrl] is the
     * broker's `…/v1/rendezvous/mesh` prefix (from the signed snapshot). Returns the
     * decrypted volunteers (possibly empty); never throws.
     */
    fun discover(
        meshBaseUrl: String,
        token: String,
        client: OkHttpClient,
        shardTunnels: ShardTunnels? = null,
    ): List<MeshVolunteer> {
        return try {
            val base = meshBaseUrl.trimEnd('/')
            val params = getParams(base, client)
                ?: run { Log.i(TAG, "Mesh: params unavailable — mesh off or bootstrap not ready; using /match."); return emptyList() }
            val pubKey = Base64.decode(params.publicKey, Base64.NO_WRAP)
            val epoch = System.currentTimeMillis() / params.epochMs
            val sr = MeshWire.sharedRandomFor(epoch)

            // Open the shard tunnels FIRST (one engine hot-reload). They carry BOTH the record
            // reads AND — B2a — the threshold committee eval, so when a committee is reachable the
            // broker is OUT of the oblivious VOPRF (and its blind budget). `[]` if none → the
            // broker is the fallback for both the eval and the reads.
            val seeds = getShardSeeds(base, client)
            val shardReads = shardTunnels?.open(seeds).orEmpty()
            Log.i(TAG, "Mesh: ${seeds.size} shard seed(s) → ${shardReads.size} shard tunnel(s) open.")

            // #33: while we have tunnels open anyway, take a snapshot from a PEER. Placed here and
            // not on the bootstrap path because that path runs BEFORE the Reality engine exists —
            // there is no tunnel to ask through yet. So the refresh rides a session that is already
            // working, and what it improves is the NEXT cold start, which is the one that may find
            // every channel blocked.
            refreshSnapshotFromPeers(shardReads)
            val committee = shardReads.filter { it.committeeId != null }
            val useThreshold = params.thresholdT in 1..committee.size
            if (useThreshold) {
                Log.i(TAG, "Mesh: threshold eval via ${committee.size} committee shard(s) (t=${params.thresholdT}).")
            }

            // eval-A: the token's s read-bucket indices. DISTINCT — with a small N the s indices
            // collide (birthday); each duplicate would otherwise cost another eval + a redundant
            // read for zero new volunteers. Dedup keeps eval-B minimal.
            val rbktTags = (0 until params.s).map { MeshWire.meshTag("rbkt", token, epoch, it) }
            val out1 = evalTags(base, token, pubKey, rbktTags, client, if (useThreshold) committee else null, params.thresholdT)
                ?: run { Log.i(TAG, "Mesh: bucket-index eval failed — rate-limited or transport; using /match."); return emptyList() }
            val buckets = MeshWire.parseOutputs(out1, OUTPUT_LEN)
                .map { MeshWire.indexFromDigest(it, params.N) }
                .distinct()

            // eval-B: the per-bucket record keys (first 32 bytes of each 64-byte output).
            val rkeyTags = buckets.map { MeshWire.meshTag("rkey", sr, it) }
            val out2 = evalTags(base, token, pubKey, rkeyTags, client, if (useThreshold) committee else null, params.thresholdT)
                ?: run { Log.i(TAG, "Mesh: record-key eval failed — rate-limited or transport; using /match."); return emptyList() }
            val keys = MeshWire.parseOutputs(out2, OUTPUT_LEN).map { it.copyOf(32) }

            // A2.2/A2.3 proxy-read: read each bucket by asking a SEED shard (over its Reality tunnel)
            // to resolve + fetch the OWNING shards for us (POST /resolve-read) — so the client never
            // learns, nor the broker ever lists, the owning shards (docs/A2_ENUMERATION_SURFACE_v0.1).
            // The broker's own mirror store, read DIRECTLY, is the last-resort fallback (it isn't a
            // shard and has no /resolve-read). SR_e (`sr`) routes the resolve to the owners the
            // volunteer published to.
            val readSources: List<Pair<String, OkHttpClient>> =
                shardReads.map { it.baseUrl to it.client } + (base to client)

            // Per bucket, take the first source that returns records: each seed shard proxies the
            // read; the broker mirror is read directly. (An owning shard holds all of a bucket's records.)
            val found = LinkedHashMap<String, MeshVolunteer>()
            var fromShard = 0
            var fromBroker = 0
            var sealedSeen = 0
            var badKey = 0
            var badBase64 = 0
            var badJson = 0
            val unopenedBuckets = mutableListOf<Int>()
            var opened = 0
            // R28: a source that does not answer is out for the REST of this connect. It used to be
            // asked again for every remaining bucket, so one dead shard cost its timeout eight times
            // over — 5m49s of a 6m26s connect, in silence. The retry that matters here is the NEXT
            // SOURCE, not the same one again.
            val rotation = ReadRotation()
            for (j in buckets.indices) {
                // Defensive: if a truncated/partial eval yielded fewer record-keys than buckets, skip
                // this bucket rather than let keys[j] throw IndexOutOfBounds and sink the whole
                // discovery (the outer catch would drop every already-found bridge).
                val bucketKey = keys.getOrNull(j) ?: continue
                var sealedList: List<String> = emptyList()
                // R28: seed shards first, worst-performing LAST, then the broker mirror as the final
                // resort. Order, not exclusion — a shard that failed is never lost, it just stops
                // being the one we wait on. A dead shard therefore costs one bounded timeout for the
                // whole connect instead of one per bucket, and a healthy proxy that happened to hit a
                // dead OWNER is still asked for the buckets it can serve.
                val tryOrder = rotation.order(shardReads.size) + listOf(readSources.size - 1)
                for (idx in tryOrder) {
                    val src = readSources[idx]
                    val isSeedShard = idx < shardReads.size
                    val outcome = if (isSeedShard)
                        resolveRead(src.first, buckets[j], sr, src.second)
                    else
                        readBucket(src.first, buckets[j], src.second)
                    if (rotation.record(idx, buckets[j], outcome)) {
                        // Said on FAILURE, which is the direction that had no line at all: for 5m49s
                        // this phase was indistinguishable from a hang, and the user reported exactly
                        // that. The one existing line prints only on success, so it can never describe
                        // the case where a read source is what went wrong. Once per source, not once
                        // per bucket, or a silent stall just becomes a noisy one.
                        Log.w(
                            TAG,
                            "Mesh: read source ${idx + 1}/${readSources.size} " +
                                "(${if (isSeedShard) "seed shard" else "broker mirror"}) did not answer " +
                                "for bucket ${buckets[j]} — trying it last from now on.",
                        )
                    }
                    val recs = (outcome as? BucketRead.Answered)?.records ?: continue
                    if (recs.isNotEmpty()) {
                        sealedList = recs
                        if (isSeedShard) {
                            fromShard++
                        } else {
                            fromBroker++
                            BrokerReliance.note(BrokerReliance.Reason.BUCKET_READ)
                        }
                        break
                    }
                }
                for (sealed in sealedList) {
                    sealedSeen++
                    val raw = runCatching {
                        Base64.decode(sealed, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                    }.getOrNull()
                    if (raw == null) {
                        badBase64++
                        continue
                    }
                    val pt = MeshWire.aesGcmOpen(bucketKey, raw)
                    if (pt == null) {
                        badKey++
                        // Name the BUCKET. R20's epoch filter took this count from 3-of-5 to 1-of-2 and
                        // not to zero, and with only a count there is nothing to pull on: every
                        // volunteer looked healthy, the clocks agreed to within 3 s of a 3600 s epoch,
                        // and no read came from the broker mirror. A bucket index is correlatable —
                        // each volunteer logs the buckets it publishes to — so the next occurrence
                        // says WHOSE record would not open instead of only that one would not.
                        unopenedBuckets.add(buckets[j])
                        // R21: the READER's half. Printed only on a failure, so a healthy run stays
                        // quiet. Everything but the fingerprint is public (epoch, SR_e, N, bucket);
                        // the fingerprint is a 32-bit hash prefix of the key, not the key. Line this
                        // up with the volunteer's "sealed a record" entry for the same bucket: a
                        // disagreement on sr or N is the answer outright, and matching inputs with a
                        // differing keyfp means the two ends derived different keys — different
                        // issuers, or a bad committee share (R10).
                        Log.w(
                            TAG,
                            "Mesh: bucket ${buckets[j]} would not open — epoch=$epoch sr=${sr.take(8)} " +
                                "N=${params.N} keyfp=${MeshWire.keyFingerprint(bucketKey)} (R21)",
                        )
                        continue
                    }
                    val v = runCatching { json.decodeFromString(MeshVolunteer.serializer(), String(pt)) }.getOrNull()
                    if (v != null) {
                        opened++
                        found[v.volunteerId] = v
                    } else {
                        badJson++
                    }
                }
            }
            // R19: this line used to read "discovered 0 volunteer(s) ... 0 via shard(s), 5 via broker",
            // whose two halves count DIFFERENT NOUNS — volunteers and buckets — so it parsed as a
            // contradiction and was ignored for months. Buckets, records and volunteers are now said
            // separately, and a record that came back but would not open is named rather than dropped
            // by a bare `?: continue`.
            Log.i(
                TAG,
                "Mesh: read ${buckets.size} bucket(s) — $fromShard answered via shard(s), $fromBroker via the " +
                    // R28: say how many sources fell out, so a slow connect has a cause on the same
                    // line as its result rather than in a gap between two log entries.
                    (if (rotation.sourcesThatFailed() > 0) "(${rotation.sourcesThatFailed()} source(s) went silent) " else "") +
                    // RECORDS opened, then DISTINCT volunteers. `found` is keyed by volunteerId, so
                    // using its size as the opened count made the arithmetic fail to close: a live run
                    // read "4 sealed record(s) returned, 3 opened ... 0 unopened" because two records
                    // were two buckets of the SAME volunteer. That is the R19 defect — two halves of
                    // one sentence counting different nouns — reappearing in the line written to
                    // replace it. Records reconcile with records; volunteers are said separately.
                    "broker mirror; $sealedSeen sealed record(s) returned, $opened opened " +
                    "(${found.size} distinct volunteer(s))" +
                    if (sealedSeen > found.size) {
                        " (unopened: $badKey wrong-key, $badBase64 malformed, $badJson unparseable" +
                            if (unopenedBuckets.isNotEmpty()) "; bucket(s) ${unopenedBuckets.joinToString(",")})." else ")."
                    } else ".",
            )
            reportDiscoveryOdds(params, found.size, sealedSeen)
            // G5 (GOSSIP §8): drop any discovered bridge whose identity is REVOKED, per the verified
            // signed revoke-digest fetched from the shards. Fail-open on a fetch miss (availability
            // first) but never keep a proven-revoked bridge. Refreshed on every discovery/re-match.
            // Isolated in its own guard so a revocation-fetch/verify problem can NEVER sink an
            // otherwise-successful discovery — it fails open to the unfiltered set, matching the intent.
            val live = try {
                // R28: a source already proven not to answer this connect is not asked again here.
                val revoked = fetchRevocations(rotation.survivors(readSources))
                val kept = found.values.filter { !revoked.isRevoked(it.reality.publicKey) }
                if (kept.size < found.size) {
                    Log.w(TAG, "Mesh: filtered ${found.size - kept.size} revoked bridge(s) (${revoked.revokedCount()} known-revoked).")
                }
                kept
            } catch (e: Exception) {
                Log.w(TAG, "Mesh: revocation filter skipped (fail-open): ${e.javaClass.simpleName}: ${e.message}")
                found.values.toList()
            }
            live
        } catch (e: Exception) {
            // Log the message (not just the class) so a live-run abort is diagnosable — exception text
            // here references the broker/`shard.zat` placeholder host, never a user IP.
            Log.w(TAG, "Mesh: discover failed: ${e.javaClass.simpleName}: ${e.message}")
            emptyList()
        }
    }

    /** One oblivious round: blind the tags → POST /blind-evaluate → finalize. */
    private fun obliviousRound(
        base: String,
        token: String,
        pubKey: ByteArray,
        tags: List<ByteArray>,
        client: OkHttpClient,
    ): ByteArray? {
        MeshOprf.create(pubKey).use { oprf ->
            val request = oprf.blind(MeshWire.buildInputsBlob(tags))
            val evalB64 = blindEvaluate(base, token, Base64.encodeToString(request, Base64.NO_WRAP), client)
                ?: return null
            return oprf.finalizeEval(Base64.decode(evalB64, Base64.NO_WRAP))
        }
    }

    /** Evaluate the tags: the B2a threshold committee when [committee] is given (no broker, no
     *  blind budget), else the broker. On a committee failure, fall back to the broker so a shard
     *  hiccup never sinks discovery. */
    private fun evalTags(
        base: String,
        token: String,
        pubKey: ByteArray,
        tags: List<ByteArray>,
        client: OkHttpClient,
        committee: List<ShardRead>?,
        thresholdT: Int,
    ): ByteArray? {
        if (committee != null) {
            thresholdEval(pubKey, tags, committee, thresholdT)?.let { return it }
            Log.i(TAG, "Mesh: threshold eval failed — falling back to broker blind-evaluate.")
        }
        // Either no committee was reachable or its eval failed: the broker is the issuer for this
        // evaluation, which is the single heaviest thing still tying a client to us.
        BrokerReliance.note(BrokerReliance.Reason.BLIND_EVAL)
        return obliviousRound(base, token, pubKey, tags, client)
    }

    private data class CommitResult(val session: Long, val round1: ByteArray)

    /** B2a threshold eval against the committee: blind → each shard's /threshold/commit (round 1)
     *  → coordinator round 1 → broadcast the challenge → /threshold/respond (round 2) → coordinator
     *  round 2 → the voprf-ts evaluation → the SAME finalize. Null on any failure. No broker; the
     *  committee reads over the shards' own Reality tunnels (already open). */
    /**
     * R29: the subsets to try after a round COMPLETED but did not verify — each leaves exactly one
     * member out, in order, so with `n=3, t=2` one of the three is the honest pair.
     *
     * Leaving one out is the only question the protocol can answer. The DLEQ proof is over the
     * COMBINATION, so a wrong answer accuses the set and never a member; "who, if absent, makes the
     * rest verify" turns that into a name. Subsets below `t` are dropped rather than attempted —
     * with exactly `t` members present there is no subset left to try, and saying so is the honest
     * result instead of a silent failure.
     */
    internal fun <T> subsetsExcludingOne(members: List<T>, t: Int): List<List<T>> =
        members.indices
            .map { i -> members.filterIndexed { j, _ -> j != i } }
            .filter { it.size >= t }

    private fun thresholdEval(
        pubKey: ByteArray,
        tags: List<ByteArray>,
        committee: List<ShardRead>,
        t: Int,
    ): ByteArray? {
        // R24: try, and on a member failing mid-protocol try again WITHOUT it. A round-2 reply is
        // bound to the session its round-1 commit opened, so a member cannot simply be dropped
        // between the rounds — the whole two-round exchange is redone with the survivors. Bounded by
        // the committee size, so this cannot spin.
        var usable = committee
        repeat(committee.size) {
            val attempt = evalOnce(pubKey, tags, usable, t) ?: return null
            attempt.evaluation?.let { return it }
            // R29: the round COMPLETED and the answer was wrong. Nothing in the reply identifies the
            // culprit — the proof is over the combination — so ask the only question that does: which
            // member, if left out, makes the rest verify. With n=3 and t=2 that is three cheap
            // attempts and one of them is the honest pair. Leaving this unhandled meant a single
            // faulty or hostile member could deny the mesh to every client and push them all back to
            // the broker, silently, which is worse than the member simply being dead.
            if (attempt.didNotVerify) {
                for (without in subsetsExcludingOne(usable, t)) {
                    val retry = evalOnce(pubKey, tags, without, t) ?: continue
                    retry.evaluation?.let {
                        Log.w(
                            TAG,
                            "Mesh: threshold eval — verified after excluding one member of " +
                                "${usable.size}. That member answered wrongly rather than not at all; " +
                                "it is a candidate for tracing, not merely an absence.",
                        )
                        return it
                    }
                }
                Log.w(
                    TAG,
                    "Mesh: threshold eval — no subset of ${usable.size} member(s) produced a verifying " +
                        "evaluation. More than one is answering wrongly, or the mesh key this client " +
                        "holds does not match the committee's.",
                )
                return null
            }
            // `failed` is the member that broke this attempt; drop it and try the rest.
            usable = usable.filter { it !== attempt.failed }
            if (usable.size < t) {
                Log.w(
                    TAG,
                    "Mesh: threshold eval — only ${usable.size} committee member(s) left, need t=$t.",
                )
                return null
            }
            Log.i(TAG, "Mesh: threshold eval — a member dropped mid-protocol; retrying with ${usable.size}.")
        }
        return null
    }

    /**
     * One two-round attempt. `evaluation` on success; otherwise `failed` names who to drop, or
     * [didNotVerify] says the round COMPLETED and the result was wrong.
     *
     * R29: those last two are different failures and used to be one. A member that goes silent is
     * absent; a member that answers WRONGLY is a member we cannot identify from its answer, because
     * the DLEQ proof is over the COMBINATION — it says the set is bad, never which one.
     */
    private class EvalAttempt(
        val evaluation: ByteArray?,
        val failed: ShardRead?,
        val didNotVerify: Boolean = false,
    )

    /**
     * A single threshold evaluation over [members], tolerating up to `size - t` of them.
     *
     * R24: this used to map over ALL members and fail closed on the FIRST failure, so with `t=2` and
     * `n=3` one dead member killed the eval and the client fell back to the broker — losing one of
     * three did not degrade the mesh, it moved the client onto us, which under a broker blackout is a
     * total failure to connect.
     *
     * The same protocol was already implemented correctly twenty lines away in another language:
     * `mesh_seal.rs::derive_seal_keys` collects whoever answers and errors only when fewer than `t`
     * replied. Two implementations of one protocol disagreeing about the single property the
     * committee exists to provide. This is that Rust behaviour, in Kotlin.
     */
    private fun evalOnce(
        pubKey: ByteArray,
        tags: List<ByteArray>,
        members: List<ShardRead>,
        t: Int,
    ): EvalAttempt? {
        return MeshOprf.create(pubKey).use { oprf ->
            val request = oprf.blind(MeshWire.buildInputsBlob(tags))
            val blindedB64 = extractBlindedB64(request)

            // Round 1: whoever answers. A member that does not is absent, not fatal — and "the
            // tunnel opened" is not liveness (the bridge can be up while the app is stopped), so a
            // failed commit is the only honest evidence that a member is not there.
            val answered = ArrayList<Pair<ShardRead, CommitResult>>(members.size)
            for (node in members) {
                val c = thrCommit(node, blindedB64)
                if (c != null) answered.add(node to c) else Log.i(TAG, "Mesh: a committee member did not commit.")
            }
            if (answered.size < t) {
                Log.w(
                    TAG,
                    "Mesh: threshold eval — only ${answered.size}/${members.size} committee member(s) " +
                        "answered round 1, need t=$t.",
                )
                return@use EvalAttempt(null, null)
            }

            val pending = MeshOprf.thrRound1(pubKey, request, frameBlobList(answered.map { it.second.round1 }))
            val cB64 = Base64.encodeToString(pending.copyOfRange(0, 32), Base64.NO_WRAP)

            // Round 2 is bound to round 1's sessions, so a member lost HERE invalidates this attempt
            // rather than being droppable — the caller retries without it.
            val round2s = ArrayList<ByteArray>(answered.size)
            for ((node, m) in answered) {
                val r = thrRespond(node, m.session, cB64)
                    ?: return@use EvalAttempt(null, node)
                round2s.add(r)
            }
            val evaluation = MeshOprf.thrRound2(pubKey, pending, frameBlobList(round2s))
            Log.i(TAG, "Mesh: threshold eval done with ${answered.size}/${members.size} member(s) (t=$t).")
            // R29: the DLEQ check is the protocol catching a wrong answer, not this app crashing. It
            // used to be neither caught nor distinguished: `finalizeEval` threw, the exception left
            // `thresholdEval` untouched, and `discover`'s outer catch logged "discover failed" and
            // returned nothing — so one member answering wrongly took down the whole mesh path for
            // this client and sent it to the broker, which is the exact outcome a t-of-n committee
            // exists to prevent. Seen live 2026-08-11 13:45:52.
            try {
                EvalAttempt(oprf.finalizeEval(evaluation), null)
            } catch (e: Exception) {
                Log.w(
                    TAG,
                    "Mesh: threshold eval — the combined evaluation of ${answered.size} member(s) does " +
                        "NOT verify against the mesh key. At least one of them answered wrongly; the " +
                        "proof is over the combination, so it cannot say which.",
                )
                EvalAttempt(null, null, didNotVerify = true)
            }
        }
    }

    /** Split a `blind` request (`u16 count || elem(32)*count`) into base64 blinded elements. */
    private fun extractBlindedB64(request: ByteArray): List<String> {
        val count = ((request[0].toInt() and 0xff) shl 8) or (request[1].toInt() and 0xff)
        return (0 until count).map { i ->
            val off = 2 + i * 32
            Base64.encodeToString(request.copyOfRange(off, off + 32), Base64.NO_WRAP)
        }
    }

    /** Frame a list of blobs as `u16(count) || (u16(len) || blob)*count` (the coordinator's input). */
    private fun frameBlobList(blobs: List<ByteArray>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write((blobs.size shr 8) and 0xff)
        out.write(blobs.size and 0xff)
        for (b in blobs) {
            out.write((b.size shr 8) and 0xff)
            out.write(b.size and 0xff)
            out.write(b)
        }
        return out.toByteArray()
    }

    /** POST /threshold/commit {blinded:[…]} to a committee shard → its Round1 bytes + session. */
    private fun thrCommit(node: ShardRead, blindedB64: List<String>): CommitResult? {
        val body = buildJsonObject {
            putJsonArray("blinded") { blindedB64.forEach { add(it) } }
        }.toString()
        val resp = postToCommitteeMember("${node.baseUrl}/threshold/commit", body, node.client) ?: return null
        val parsed = runCatching { json.decodeFromString(ThrCommitResponse.serializer(), resp) }.getOrNull()
            ?: return null
        val round1 = runCatching { Base64.decode(parsed.round1, Base64.NO_WRAP) }.getOrNull() ?: return null
        return CommitResult(parsed.session, round1)
    }

    /** POST /threshold/respond {session, c} to a committee shard → its Round2 bytes. */
    private fun thrRespond(node: ShardRead, session: Long, cB64: String): ByteArray? {
        val body = buildJsonObject {
            put("session", session)
            put("c", cB64)
        }.toString()
        val resp = postToCommitteeMember("${node.baseUrl}/threshold/respond", body, node.client) ?: return null
        val parsed = runCatching { json.decodeFromString(ThrRespondResponse.serializer(), resp) }.getOrNull()
            ?: return null
        return runCatching { Base64.decode(parsed.round2, Base64.NO_WRAP) }.getOrNull()
    }

    /**
     * Mesh entry parameters — **from the signed snapshot when it carries them**, else from the broker.
     *
     * Until 2026-07-28 this only asked the broker, which meant the mesh path — the thing that exists
     * to replace `/match` — began at the broker. Reads were peer-to-peer; the way IN was not, so
     * switching the broker off broke both paths at once.
     *
     * The snapshot is the right source: committee-signed (so a lying source is caught by a check the
     * client already performs), and served by every node since the same date. A client holding one
     * can enter the mesh with the broker gone.
     */
    private fun getParams(base: String, client: OkHttpClient): MeshParams? =
        snapshotMeshEntry?.let { e ->
            Log.i(TAG, "Mesh: entry parameters came from the SIGNED SNAPSHOT — no broker call needed.")
            MeshParams(e.suite, e.publicKey, e.N, e.r, e.s, e.epochMs, e.thresholdT, e.thresholdN)
        } ?: get("$base/params", client)?.let {
            BrokerReliance.note(BrokerReliance.Reason.PARAMS)
            runCatching { json.decodeFromString(MeshParams.serializer(), it) }.getOrNull()
        }

    /**
     * The mesh entry the last verified snapshot carried, or null on an older snapshot. Set by
     * [BootstrapResolver] when it parses one, so this stays a pure lookup with no fetch of its own.
     */
    @Volatile internal var snapshotMeshEntry: MeshEntry? = null

    /**
     * R19 — say out loud whether finding NOTHING was expected, because for months it was.
     *
     * A volunteer writes its record into `r` of `N` buckets; a token reads `s` buckets chosen from
     * its own blinded evaluation. So discovery is a sampling problem, and the chance that one
     * client's read touches one volunteer's writes is `1-(1-r/N)^s`. The parameter's own doc-comment
     * in the broker says N "scales with the live pool to hold k≈r·s·V/N fixed" — it never did. It is
     * the constant 4096, sized for a network of hundreds, against a pool of one:
     *
     *     N=4096, r=4, s=8  ->  0.78% per volunteer.
     *
     * Every such run then fell back to the broker's `/match` and connected, so the surface stayed
     * green while the path built to REMOVE the broker produced nothing. The zero was never the
     * anomaly; the silence was. This turns the arithmetic into a line that reads itself.
     */
    private fun reportDiscoveryOdds(params: MeshParams, found: Int, sealedSeen: Int) {
        if (found > 0) return
        if (params.N <= 0 || params.r <= 0 || params.s <= 0) return
        val perVolunteer = 1.0 - Math.pow(1.0 - params.r.toDouble() / params.N, params.s.toDouble())
        val pct = perVolunteer * 100.0
        if (pct < 25.0) {
            Log.w(
                TAG,
                "Mesh: found nothing, and at these parameters that is EXPECTED, not a fault — " +
                    "N=${params.N} r=${params.r} s=${params.s} gives a ${"%.2f".format(pct)}% chance of " +
                    "touching any one volunteer's buckets. N is meant to scale with the live pool " +
                    "(k≈r·s·V/N); it is a constant. This connection will ride the BROKER. (R19)",
            )
        } else {
            Log.w(
                TAG,
                "Mesh: found nothing, and the parameters do NOT explain it — N=${params.N} r=${params.r} " +
                    "s=${params.s} gives ${"%.2f".format(pct)}% per volunteer and $sealedSeen sealed " +
                    "record(s) came back. Something is wrong beyond pool size. (R19)",
            )
        }
    }

    /**
     * The volunteer-run Dir shards to read from (B1b model C), via `GET {base}/shards`.
     * `[]` when the mesh is dormant → the caller reads only from the broker's mirror store.
     * TRANSITIONAL: the broker sourcing shard discovery is a seam that dissolves once
     * clients find shards peer-to-peer (DHT / gossip / the signed snapshot).
     */
    private fun getShardSeeds(base: String, client: OkHttpClient): List<MeshShardSeed> {
        // Same reasoning as `getParams`: prefer the signed snapshot, so shard discovery does not
        // require us to be reachable. The endpoint's own summary called itself transitional; this is
        // the transition.
        snapshotMeshEntry?.shards?.takeIf { it.isNotEmpty() }?.let { return it }
        BrokerReliance.note(BrokerReliance.Reason.SHARD_SEEDS)
        return get("$base/shards", client)
            ?.let { runCatching { json.decodeFromString(ShardsResponse.serializer(), it) }.getOrNull() }
            ?.shards
            ?: emptyList()
    }

    /**
     * G5: fetch + verify the revoke-digest (`GET {base}/trust/revoked`) from the reachable shard
     * surfaces, building a [RevocationSet]. Each delta is signed under the pinned trust anchor, so a
     * withholding shard cannot hide a revocation an honest one still carries. Fail-open per source.
     */
    /**
     * #33 — ask peers for the signed bootstrap snapshot (`GET {base}/snapshot`) and adopt the first
     * that verifies.
     *
     * Best-effort in the strictest sense: every failure path simply returns. This annotates a session
     * that is already working, and a snapshot refresh must never be able to delay or sink volunteer
     * discovery — the user is waiting on that, not on this.
     *
     * Stops at the first ADOPTED one rather than the first that answers. A peer can be reachable and
     * still serve nothing useful (503 before its own first fetch, or a body older than what we hold),
     * and treating "answered" as "done" would let one such peer shadow the others. Asking a second
     * costs one request on a tunnel that is already open.
     *
     * [BootstrapResolver.adoptFromPeer] does the deciding: pinned-key signature plus A9's monotonic
     * rule, exactly as for a channel. Nothing here inspects the body, so there is no second, weaker
     * idea of what a valid snapshot is.
     */
    private fun refreshSnapshotFromPeers(shardReads: List<ShardRead>) {
        if (shardReads.isEmpty()) return
        // A lazy sequence, so a peer after the first success is never asked at all.
        //
        // R28: bounded, one attempt per peer. Peers are redundant here by construction, and the whole
        // routine is best-effort — it fails into "no peer offered a newer snapshot", which is a normal
        // outcome. In the run that found R28 this phase took 21.9 s against one dead shard (tunnels up
        // at 10:20:43.3, evaluation starting at 10:21:05.2) with two log lines in between, which is
        // what four retries on a 12 s connect buys on a source we were happy to skip.
        val bodies = shardReads.asSequence().map {
            val bounded = it.client.newBuilder()
                .callTimeout(READ_CALL_TIMEOUT_SEC, java.util.concurrent.TimeUnit.SECONDS)
                .build()
            runCatching {
                bounded.newCall(Request.Builder().url("${it.baseUrl}/snapshot").get().build())
                    .execute().use { r -> if (r.isSuccessful) r.body?.string() else null }
            }.getOrNull()
        }
        if (adoptFirstUsable(bodies) { BootstrapResolver.adoptFromPeer(it) }) {
            // NOT "the channels were not needed" — that was this line for a while, and it was read
            // back off a live device beside a log showing channel 1 had succeeded 1.4 seconds
            // earlier. This runs over a tunnel that is already open, so it can never be the thing
            // that opened it; what it buys is the NEXT attempt not needing a channel.
            Log.i(TAG, "Mesh: snapshot refreshed from a peer — the next attempt can skip the channels.")
        } else {
            // Said out loud. Silence here would look exactly like "we never tried", and this is the
            // path that has to work on the day the channels do not.
            Log.i(TAG, "Mesh: no peer offered a snapshot newer than the one this device holds.")
        }
    }

    /**
     * Walk peer answers until one is ADOPTED, and return whether any was.
     *
     * Split out from the fetching so the policy can be tested without sockets, because the policy is
     * where this would go wrong. A peer can be perfectly reachable and still serve nothing usable —
     * 503 before its own first fetch, a body older than what this device holds, a cover page — and
     * treating "answered" as "done" would let one such peer shadow every other peer we have. `null`
     * is an unreachable peer and is likewise a skip, never an answer.
     *
     * [adopt] is wrapped: a peer's body must not be able to throw its way out of the loop and take
     * the remaining peers with it.
     */
    internal fun adoptFirstUsable(bodies: Sequence<String?>, adopt: (String) -> Boolean): Boolean {
        for (body in bodies) {
            if (body.isNullOrBlank()) continue
            if (runCatching { adopt(body) }.getOrDefault(false)) return true
        }
        return false
    }

    /**
     * R28: bounded, one attempt per source. This walks EVERY read source on every discovery and
     * re-match, so before the bound a dead shard was paid for here as well — the same ~36s, a second
     * time, on a path that is explicitly fail-open (a miss keeps the unfiltered set). Somewhere that
     * already treats "no answer" as an acceptable outcome has no business retrying four times.
     */
    private fun fetchRevocations(readSources: List<Pair<String, OkHttpClient>>): RevocationSet {
        val set = RevocationSet()
        for ((base, client) in readSources) {
            val bounded = client.newBuilder()
                .callTimeout(READ_CALL_TIMEOUT_SEC, java.util.concurrent.TimeUnit.SECONDS)
                .build()
            val body = runCatching {
                bounded.newCall(Request.Builder().url("$base/trust/revoked").get().build())
                    .execute().use { r -> if (r.isSuccessful) r.body?.string() else null }
            }.getOrNull() ?: continue
            val deltas = runCatching {
                json.decodeFromString(TrustRevokedResponse.serializer(), body).deltas
            }.getOrNull() ?: continue
            set.apply(deltas)
        }
        return set
    }

    private fun blindEvaluate(base: String, token: String, requestB64: String, client: OkHttpClient): String? {
        val body = buildJsonObject {
            put("token", token)
            put("request", requestB64)
        }.toString()
        val resp = post("$base/blind-evaluate", body, client) ?: return null
        return runCatching { json.decodeFromString(BlindEvaluateResponse.serializer(), resp).evaluation }.getOrNull()
    }

    /**
     * R28: what a read source DID when asked for a bucket. Every read used to collapse to
     * `emptyList()`, so "this shard answered and that bucket happens to be empty" and "this shard is
     * dead" were the same value — and the loop therefore asked a dead shard again for all eight
     * buckets. Separating them is the whole fix.
     */
    internal sealed interface BucketRead {
        /** The source answered. [records] may legitimately be empty — an empty bucket is normal. */
        data class Answered(val records: List<String>) : BucketRead
        /** The source did not answer: a transport failure. Do not ask it again this connect. */
        object Unreachable : BucketRead
        /** WE could not solve the read-PoW in time. Our failure, so the source keeps its place —
         *  dropping a healthy shard because this device was busy would push reads to the broker for
         *  no reason, which is the outcome the whole path exists to avoid. */
        object PowTimedOut : BucketRead
    }

    /**
     * R28: which read sources are still worth asking, for the life of ONE connect.
     *
     * Kept as its own type rather than a `Set<Int>` in the loop so the rule it encodes can be stated
     * and tested directly: only a source that DID NOT ANSWER is dropped. An empty bucket is a normal
     * answer from a healthy shard, and a read-PoW timeout is this device's own failure — dropping a
     * shard for either would push reads onto the broker mirror for no reason, which is precisely the
     * outcome the mesh exists to avoid.
     */
    internal class ReadRotation {
        private val failedBuckets = mutableMapOf<Int, MutableSet<Int>>()
        private val dropped = mutableSetOf<Int>()

        /**
         * The order to try seed shards in for the next bucket: fewest failures first, ties in the
         * original order. This REPLACES retiring a source, and two live runs are why.
         *
         * Retiring looked right and was wrong. A proxy-read makes a seed shard consult the shards
         * that OWN a bucket, so when one node is dead every proxy fails on the buckets that node
         * owns — and no per-source rule can tell that apart from the proxy itself being dead, because
         * the evidence is identical. Dropping on one failure retired two of three shards (both on
         * `bucket 6`); requiring two distinct buckets retired the same two (they each own more than
         * one). Both runs ended `0 answered via shard(s)` with everything served by the broker mirror
         * — faster than the 5m49s stall, and further from dissolution, which is the wrong trade.
         *
         * Deprioritising cannot make that mistake. A source that fails sinks to the back, so a
         * genuinely dead shard stops being the one we wait on first, while a healthy proxy that
         * merely hit a dead owner is still there for the buckets it CAN serve. Nothing is ever lost,
         * so the rule has no failure mode worse than trying a source in a slightly worse order.
         */
        fun order(seedCount: Int): List<Int> =
            (0 until seedCount).sortedBy { failedBuckets[it]?.size ?: 0 }

        /** Record that source [index] failed to answer for [bucket]. Returns true the first time this
         *  source is seen to fail at all, so the caller says so once instead of once per bucket. */
        fun record(index: Int, bucket: Int, outcome: BucketRead): Boolean {
            if (outcome !is BucketRead.Unreachable) return false
            val first = failedBuckets[index].isNullOrEmpty()
            failedBuckets.getOrPut(index) { mutableSetOf() }.add(bucket)
            return first
        }

        /** How many sources have failed at least once — reported on the summary line, so a slow
         *  connect has its cause beside its result rather than in a gap between two log entries. */
        fun sourcesThatFailed(): Int = failedBuckets.count { it.value.isNotEmpty() }

        /** Sources worth asking for the revocation digest: the ones that have not failed. That fetch
         *  walks every source on every discovery and re-match, and it is explicitly fail-open, so
         *  spending a bounded timeout there on a shard already known to be silent buys nothing.
         *  Unlike the read path this may skip a source safely — a miss keeps the unfiltered set. */
        fun <T> survivors(sources: List<T>): List<T> =
            sources.filterIndexed { i, _ -> failedBuckets[i].isNullOrEmpty() }
    }

    /** Fetch + solve a bucket's crawl-wall read-PoW against [base]'s `/read-challenge`. Shared by the
     *  direct read (broker mirror) and the proxy-read (a seed shard) — both pay the SAME read-PoW, so
     *  proxying is no cheaper to abuse. Returns which of the two failure kinds occurred, because the
     *  caller must not treat our own PoW timeout as a dead source. */
    private fun solveReadChallenge(
        base: String,
        bucketIndex: Int,
        client: OkHttpClient,
        bounded: Boolean,
    ): Pair<Pair<PowChallenge, String>?, BucketRead?> {
        val challengeBody = buildJsonObject { put("bucketIndex", bucketIndex) }.toString()
        val challengeResp = postToReadSource("$base/read-challenge", challengeBody, client, bounded)
            ?: return null to BucketRead.Unreachable
        val challenge = runCatching { json.decodeFromString(PowChallenge.serializer(), challengeResp) }.getOrNull()
            ?: return null to BucketRead.Unreachable // answered, but not with a challenge we can use
        val deadline = minOf(challenge.exp, System.currentTimeMillis() + MAX_SOLVE_MS)
        val solution = RendezvousPow.solve(challenge, deadline)
            ?: return null to BucketRead.PowTimedOut
        return (challenge to solution) to null
    }

    /** Serialize a solved challenge into the wire shape both `/read` and `/resolve-read` expect. */
    private fun JsonObjectBuilder.putChallenge(challenge: PowChallenge) {
        putJsonObject("challenge") {
            put("nonce", challenge.nonce)
            put("difficulty", challenge.difficulty)
            put("tokenId", challenge.tokenId)
            put("exp", challenge.exp)
            put("mac", challenge.mac)
        }
    }

    /** Read one bucket DIRECTLY behind the crawl-wall PoW — the broker-mirror fallback. This is the
     *  LAST source, with nothing behind it, so it keeps the retrying `post`: here a transient hiccup
     *  really does sink discovery, which is the case the retry was written for. */
    private fun readBucket(base: String, bucketIndex: Int, client: OkHttpClient): BucketRead {
        val (solved, failure) = solveReadChallenge(base, bucketIndex, client, bounded = false)
        val (challenge, solution) = solved ?: return failure ?: BucketRead.Unreachable
        val readBody = buildJsonObject {
            put("bucketIndex", bucketIndex)
            putChallenge(challenge)
            put("solution", solution)
        }.toString()
        val readResp = post("$base/read", readBody, client) ?: return BucketRead.Unreachable
        return BucketRead.Answered(
            runCatching { json.decodeFromString(ReadResponse.serializer(), readResp).records }.getOrNull() ?: emptyList(),
        )
    }

    /**
     * A2.2/A2.3 proxy-read: ask a SEED shard (over its Reality tunnel) to resolve the shards that
     * OWN [bucketIndex] at [sharedRandom] and read them shard-to-shard, returning the opaque sealed
     * records. So we never learn — nor open tunnels to — the owning shards (the broker never lists
     * them either): the "whole backbone" is never exposed. Gated by the same read-PoW a direct read
     * pays (anti-amplification).
     *
     * R28: bounded, ONE attempt — the same reasoning that bounds a committee call. A seed shard is
     * redundant by construction (the other seed shards, then the broker mirror), so retrying one four
     * times spends the user's connect on a source we are explicitly allowed to lose.
     */
    private fun resolveRead(base: String, bucketIndex: Int, sharedRandom: String, client: OkHttpClient): BucketRead {
        val (solved, failure) = solveReadChallenge(base, bucketIndex, client, bounded = true)
        val (challenge, solution) = solved ?: return failure ?: BucketRead.Unreachable
        val body = buildJsonObject {
            put("bucketIndex", bucketIndex)
            put("sharedRandom", sharedRandom)
            putChallenge(challenge)
            put("solution", solution)
        }.toString()
        val resp = postToReadSource("$base/resolve-read", body, client, bounded = true)
            ?: return BucketRead.Unreachable
        return BucketRead.Answered(
            runCatching { json.decodeFromString(ReadResponse.serializer(), resp).records }.getOrNull() ?: emptyList(),
        )
    }

    // ---- tiny HTTP helpers (mirror RendezvousClient) ----

    /**
     * R26: a committee member gets ONE attempt on this deadline. Healthy members answer in ~0.6s over
     * an already-open Reality tunnel; a dead one cost ~22s of retries, twice per connect.
     */
    private const val COMMITTEE_CALL_TIMEOUT_SEC = 6L

    /**
     * R28: a SEED-SHARD read gets one attempt on this deadline, for the reason R26 bounded a
     * committee call — and this is the same bug, one phase later, found only because R26's fix
     * removed the cost that had been hiding it.
     *
     * Measured 2026-08-11 with one of three shards stopped: the evaluation phase cost 5.6s per
     * round (R26 working exactly as designed) and the connect still took 6m26s, because the read
     * phase sat on the dead shard for 5m49s. `HTTP_RETRIES = 3` plus a 12s connect and a 12s read
     * on the shared SOCKS client is ~36s per call, two calls per bucket, eight buckets — and every
     * one of those was spent on a source the very next line of code was willing to replace.
     *
     * Slightly longer than the committee's 6s because a proxy-read is a shard-to-shard fan-out
     * behind the request, not a single local operation.
     */
    private const val READ_CALL_TIMEOUT_SEC = 8L
    private const val HTTP_RETRIES = 3 // transient-network-only retries per request
    private const val HTTP_RETRY_BACKOFF_MS = 250L

    private fun get(url: String, client: OkHttpClient): String? =
        executeWithRetry(client, Request.Builder().url(url).get().build())

    private fun post(url: String, body: String, client: OkHttpClient): String? =
        executeWithRetry(client, Request.Builder().url(url).post(body.toRequestBody(JSON_MEDIA)).build())

    /**
     * A committee call: ONE attempt, on a short deadline (R26).
     *
     * The general `post` retries three times with backoff, which is right for a 19-round-trip flow
     * where one transient hiccup must not sink discovery. It is wrong for a committee member,
     * because `t`-of-`n` IS that redundancy — a member we are explicitly allowed to lose gets
     * retried four times, and the user pays every timeout.
     *
     * Measured 2026-08-11 with one of three members stopped: each evaluation took ~22 seconds to
     * give up on it, twice, and a cold connect took 114 seconds. It was CORRECT — R24's fix carried
     * it on two members and scored `broker=0` — but a minute and a half of "connecting" is a user
     * who has already closed the app, and in a censored country it reads as "this does not work".
     *
     * Healthy members answered in 0.64 seconds over the same already-open Reality tunnel, so the
     * deadline is generous by more than an order of magnitude. It is deliberately not tighter: a
     * legitimate member on a bad link must not be dropped, which is how strengthening a check
     * narrows it.
     */
    /**
     * A read call. [bounded] = a seed shard: one attempt on [READ_CALL_TIMEOUT_SEC], because the other
     * seed shards and the broker mirror ARE the retry. Otherwise the broker mirror, which is the last
     * source with nothing behind it, so it keeps the retrying `post`.
     */
    private fun postToReadSource(url: String, body: String, client: OkHttpClient, bounded: Boolean): String? {
        if (!bounded) return post(url, body, client)
        val boundedClient = client.newBuilder()
            .callTimeout(READ_CALL_TIMEOUT_SEC, java.util.concurrent.TimeUnit.SECONDS)
            .build()
        val request = Request.Builder().url(url).post(body.toRequestBody(JSON_MEDIA)).build()
        return try {
            boundedClient.newCall(request).execute().use { r ->
                if (r.isSuccessful) r.body?.string() else null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun postToCommitteeMember(url: String, body: String, client: OkHttpClient): String? {
        val bounded = client.newBuilder()
            .callTimeout(COMMITTEE_CALL_TIMEOUT_SEC, java.util.concurrent.TimeUnit.SECONDS)
            .build()
        val request = Request.Builder().url(url).post(body.toRequestBody(JSON_MEDIA)).build()
        return try {
            bounded.newCall(request).execute().use { r ->
                if (r.isSuccessful) r.body?.string() else null
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Execute [request], retrying ONLY transient network failures (thrown exceptions) with a
     * short backoff. The mesh flow is ~19 sequential round-trips over a just-established Reality
     * SOCKS, so one transient hiccup must not sink discovery (it previously fell silently to
     * /match). A NON-2xx response — notably the per-epoch rate-limit 429 — returns null WITHOUT
     * retry, so we never storm the broker or double-spend a token's blind budget.
     */
    private fun executeWithRetry(client: OkHttpClient, request: Request): String? {
        var attempt = 0
        while (true) {
            try {
                client.newCall(request).execute().use { r ->
                    return if (r.isSuccessful) r.body?.string() else null
                }
            } catch (e: Exception) {
                if (attempt++ >= HTTP_RETRIES) return null
                try {
                    Thread.sleep(HTTP_RETRY_BACKOFF_MS * attempt)
                } catch (ie: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return null
                }
            }
        }
    }

    private const val OUTPUT_LEN = 64 // ristretto255-SHA512 VOPRF output (Nh)
}
