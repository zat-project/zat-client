package zat.manager.vpn

import android.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull

/**
 * G5 (GOSSIP_TRUST_PROPAGATION_v0.1 §8) — the client's own, VERIFIED view of gossip revocations.
 *
 * Given signed TrustDelta bodies fetched from volunteers (`GET /trust/revoked`), it verifies each
 * under the pinned snapshot/committee key — reusing [BootstrapResolver]'s Ed25519 verify + canonical
 * form, the SAME trust anchor as the snapshot — and tracks the revoked subjects by monotonic epoch.
 *
 * Fail-closed: an unverifiable, forged, or stale delta is ignored. So a lying volunteer can neither
 * FORGE a revocation nor UN-revoke a real one by merely withholding it (an honest peer still carries
 * it). The client uses this to never match to — nor keep — a bridge whose identity is revoked.
 */
class RevocationSet {
    // subject (a bridge's reality public key) -> (highest epoch seen, revoked at that epoch?)
    private val latest = HashMap<String, Pair<Long, Boolean>>()

    /** Verify + apply signed delta bodies. Idempotent + monotonic by epoch. Returns this. */
    fun apply(deltas: List<String>): RevocationSet {
        for (body in deltas) applyOne(body)
        return this
    }

    private fun applyOne(body: String) {
        val root = try {
            Json.parseToJsonElement(body).jsonObject
        } catch (e: Exception) {
            return
        }
        val sigB64 = (root["signature"] as? JsonPrimitive)?.contentOrNull ?: return
        val sig = try {
            Base64.decode(sigB64, Base64.DEFAULT)
        } catch (e: Exception) {
            return
        }
        // Canonical = the object MINUS `signature`, sorted-key — matches the broker's signer exactly.
        val canonical = BootstrapResolver
            .sortedStringify(JsonObject(root.filterKeys { it != "signature" }))
            .toByteArray(Charsets.UTF_8)
        // A3 rung 5 (2026-07-28): the committee's key alone, same anchor as the snapshot. The broker's
        // signing key used to be accepted here too — and retiring it would have quietly ended
        // traitor-tracing's fast response, since nothing else could sign a revocation. That is why
        // revocations were moved to committee signing FIRST (`signAndStoreTrustDelta`), and only then
        // was this dropped.
        val anchor = StealthConfig.getSnapshotThresholdPublicKey() ?: return
        if (!BootstrapResolver.verifyEd25519(canonical, sig, anchor)) return

        val subject = (root["subject"] as? JsonPrimitive)?.contentOrNull ?: return
        val epoch = (root["epoch"] as? JsonPrimitive)?.longOrNull ?: return
        val revoked = (root["kind"] as? JsonPrimitive)?.contentOrNull == "revoke"
        val prev = latest[subject]
        if (prev == null || epoch > prev.first) {
            latest[subject] = epoch to revoked
        }
    }

    /** Is this subject (a bridge's reality public key) currently revoked? */
    fun isRevoked(subject: String): Boolean = latest[subject]?.second == true

    /** Count of standing revocations (observability — a count, never an identity in logs). */
    fun revokedCount(): Int = latest.count { it.value.second }
}
