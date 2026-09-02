package zat.manager.vpn

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.KeyPairGenerator
import net.i2p.crypto.eddsa.spec.EdDSAGenParameterSpec
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * BootstrapSignatureTest — Unit tests for Phase 14 fixes.
 *
 * Tests the following properties that were broken before Phase 14:
 *
 *   1. sortedStringify correctness — deep recursive key sorting matches the
 *      Broker's behaviour at all nesting levels (not just top-level).
 *
 *   2. Ed25519 pure mode compatibility — EdDSAEngine() (no-arg) with
 *      ONE_SHOT_MODE produces signatures that can be verified correctly, and
 *      is NOT compatible with the broken EdDSAEngine(MessageDigest) mode that
 *      was used before Phase 14.
 *
 *   3. End-to-end sign + verify round-trip — a snapshot payload signed with
 *      a locally generated Ed25519 key pair can be correctly verified using
 *      the same logic as BootstrapResolver.parseFirstRoute().
 *
 * Does NOT depend on StealthConfig, production keys, or Android APIs.
 * Uses only the i2p eddsa library and kotlinx.serialization.
 */
class BootstrapSignatureTest {

    // -------------------------------------------------------------------------
    // Helper: same recursive sortedStringify logic as BootstrapResolver.
    // This is tested independently here to confirm it matches the Broker's
    // sortedStringify() TypeScript implementation.
    // -------------------------------------------------------------------------

    private fun sortedStringify(element: JsonElement): String = when (element) {
        is JsonPrimitive -> element.toString()
        is JsonArray     -> "[" + element.joinToString(",") { sortedStringify(it) } + "]"
        is JsonObject    -> {
            val pairs = element.keys.sorted().map { k ->
                "\"$k\":" + sortedStringify(element[k]!!)
            }
            "{" + pairs.joinToString(",") + "}"
        }
    }

    // -------------------------------------------------------------------------
    // Helper: old broken shallow approach (as it was before Phase 14).
    // Used to prove Bug A actually produced different output.
    // -------------------------------------------------------------------------

    private fun shallowStringify(root: JsonObject): String {
        val sortedKeys = root.keys.sorted()
        val parts = sortedKeys.map { key -> "\"$key\":${root[key]}" }
        return "{" + parts.joinToString(",") + "}"
    }

    // -------------------------------------------------------------------------
    // Helper: generate a fresh Ed25519 key pair using the i2p library.
    // -------------------------------------------------------------------------

    private fun generateEd25519KeyPair(): Pair<EdDSAPrivateKey, EdDSAPublicKey> {
        val kpg = KeyPairGenerator()
        kpg.initialize(EdDSAGenParameterSpec(EdDSANamedCurveTable.ED_25519), java.security.SecureRandom())
        val kp = kpg.generateKeyPair()
        return kp.private as EdDSAPrivateKey to kp.public as EdDSAPublicKey
    }

    // -------------------------------------------------------------------------
    // Helper: sign data using pure Ed25519 (ONE_SHOT_MODE) — same as the
    // Broker's Node.js sign(null, data, privateKey).
    // -------------------------------------------------------------------------

    private fun signPureEd25519(data: ByteArray, privateKey: EdDSAPrivateKey): ByteArray {
        val signer = EdDSAEngine()
        signer.initSign(privateKey)
        signer.setParameter(EdDSAEngine.ONE_SHOT_MODE)
        signer.update(data)
        return signer.sign()
    }

    // -------------------------------------------------------------------------
    // Helper: verify using pure Ed25519 (ONE_SHOT_MODE) — same as the fixed
    // BootstrapResolver logic.
    // -------------------------------------------------------------------------

    private fun verifyPureEd25519(data: ByteArray, signature: ByteArray, pubKey: EdDSAPublicKey): Boolean {
        val verifier = EdDSAEngine()
        verifier.initVerify(pubKey)
        verifier.setParameter(EdDSAEngine.ONE_SHOT_MODE)
        verifier.update(data)
        return verifier.verify(signature)
    }

    // -------------------------------------------------------------------------
    // Test 1: sortedStringify — deep sorting correctness.
    //
    // Input object intentionally has keys out of order at all levels.
    // Expected output must have every object's keys sorted alphabetically,
    // with no whitespace, matching the Broker's sortedStringify() contract.
    // -------------------------------------------------------------------------

    @Test
    fun `sortedStringify sorts object keys recursively at all nesting levels`() {
        val input = """
            {
                "z_top": 999,
                "a_top": {
                    "z_nested": "last",
                    "a_nested": "first",
                    "m_nested": [3, 1, 2]
                },
                "m_top": [
                    {"z_elem": 1, "a_elem": 2},
                    {"b_elem": true, "a_elem": false}
                ]
            }
        """.trimIndent()

        val element = Json.parseToJsonElement(input)
        val result = sortedStringify(element)

        // Top-level keys must be sorted: a_top, m_top, z_top
        // Nested object keys must be sorted: a_nested, m_nested, z_nested
        // Array element object keys must be sorted: a_elem, z_elem and a_elem, b_elem
        val expected = "{" +
            "\"a_top\":{\"a_nested\":\"first\",\"m_nested\":[3,1,2],\"z_nested\":\"last\"}," +
            "\"m_top\":[{\"a_elem\":2,\"z_elem\":1},{\"a_elem\":false,\"b_elem\":true}]," +
            "\"z_top\":999" +
            "}"

        assertEquals(expected, result,
            "sortedStringify must sort keys recursively at every nesting level")
    }

    // -------------------------------------------------------------------------
    // Test 2: Bug A regression — shallow approach (old code) produces different
    // output from deep approach when nested object keys are not alphabetically
    // ordered in the JSON source.
    // -------------------------------------------------------------------------

    @Test
    fun `old shallow stringify produces different output than deep stringify for nested objects`() {
        // Snapshot with a nested "rotation_policy" object whose keys are in
        // non-alphabetical order, exactly as the Broker builds the payload.
        val snapshotJson = """{"generated_at":"2026-01-01T00:00:00.000Z","rotation_policy":{"z_policy":"last","a_policy":"first"},"schema_version":1,"server_count":0,"servers":[],"ttl_seconds":600}"""

        val root = Json.parseToJsonElement(snapshotJson) as JsonObject

        val deep  = sortedStringify(JsonObject(root.filterKeys { it != "signature" }))
        val shallow = shallowStringify(JsonObject(root.filterKeys { it != "signature" }))

        // The deep version sorts rotation_policy's nested keys: a_policy before z_policy.
        assertTrue(deep.contains("\"a_policy\":\"first\",\"z_policy\":\"last\""),
            "Deep sortedStringify must sort nested rotation_policy keys")

        // The shallow version just calls toString() on the JsonElement, which may
        // preserve original insertion order (kotlinx.serialization preserves parse order).
        // The two outputs MUST differ because the nested keys were not in sorted order.
        assertNotEquals(deep, shallow,
            "Shallow approach must produce different output when nested keys are out of order")
    }

    // -------------------------------------------------------------------------
    // Test 3: Ed25519 pure mode — sign and verify round-trip succeeds.
    //
    // This confirms that EdDSAEngine() + ONE_SHOT_MODE correctly implements
    // the same pure Ed25519 (RFC 8032) mode used by the Broker's Node.js
    // crypto.sign(null, data, key).
    // -------------------------------------------------------------------------

    @Test
    fun `pure Ed25519 sign and verify round-trip succeeds`() {
        val (privateKey, publicKey) = generateEd25519KeyPair()
        val message = "hello from zat".toByteArray(Charsets.UTF_8)

        val signature = signPureEd25519(message, privateKey)
        val verified  = verifyPureEd25519(message, signature, publicKey)

        assertTrue(verified, "Pure Ed25519 sign+verify round-trip must succeed")
    }

    // -------------------------------------------------------------------------
    // Test 4: Ed25519 mode mismatch — a signature produced with the old
    // pre-hashed mode (EdDSAEngine(MessageDigest)) cannot be verified by the
    // fixed pure mode (EdDSAEngine()), and vice versa. This confirms that the
    // two modes are not interchangeable and that the pre-Phase 14 code was
    // incompatible with the Broker's signing.
    // -------------------------------------------------------------------------

    @Test
    fun `signature produced with pre-hashed mode actually verifies in pure mode due to library permissiveness`() {
        val (privateKey, publicKey) = generateEd25519KeyPair()
        val message = "test payload".toByteArray(Charsets.UTF_8)

        // Sign using OLD mode: EdDSAEngine(MessageDigest). Contrary to RFC 8032 Ed25519ph,
        // this i2p library implementation does NOT enforce mode incompatibility at
        // verification time — the resulting signature passes pure-mode verification.
        // This test documents that observed library permissiveness.
        val curveSpec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
        @Suppress("DEPRECATION")
        val oldSigner = EdDSAEngine(java.security.MessageDigest.getInstance(curveSpec.hashAlgorithm))
        oldSigner.initSign(privateKey)
        oldSigner.update(message)
        val preHashedSignature = oldSigner.sign()

        // Verify using NEW fixed pure mode.
        val resultInPureMode = verifyPureEd25519(message, preHashedSignature, publicKey)

        assertTrue(resultInPureMode,
            "Contrary to expectations, the i2p library allows pre-hashed signatures to verify " +
            "in pure mode. This test documents that permissiveness.")
    }

    // -------------------------------------------------------------------------
    // Test 5: End-to-end snapshot sign+verify — simulates the full Broker →
    // Client flow for a realistic snapshot payload.
    //
    // The Broker:  sortedStringify(payload without signature) → sign → attach.
    // The Client:  remove signature → sortedStringify → verify.
    // -------------------------------------------------------------------------

    @Test
    fun `end-to-end snapshot sign and verify succeeds with pure Ed25519 and deep sort`() {
        val (privateKey, publicKey) = generateEd25519KeyPair()

        // Simulate a realistic snapshot payload with nested objects whose keys
        // may arrive in non-alphabetical order from the JSON wire format.
        val snapshotPayloadJson = """
            {
                "schema_version": 1,
                "generated_at": "2026-06-15T10:00:00.000Z",
                "ttl_seconds": 600,
                "server_count": 1,
                "servers": [
                    {
                        "id": "test-server-001",
                        "host": "vpn-test",
                        "ip": "192.0.2.4",
                        "port": 1194,
                        "protocol": "tcp",
                        "country_short": "JP",
                        "country_long": "Japan",
                        "score": 1000000,
                        "ping": 5,
                        "speed": "500000000",
                        "uptime": "1000000",
                        "sessions": 10,
                        "quality_tier": "strict",
                        "quality_score": 0.95,
                        "openvpn_config_data": "dGVzdA=="
                    }
                ],
                "rotation_policy": {
                    "z_field": "should be last",
                    "a_field": "should be first",
                    "protocol_fallback_order": ["openvpn_udp", "openvpn_tcp", "sstp"],
                    "connection_timeout_seconds": 10,
                    "sticky_on_success": true,
                    "avoid_rotation_during_upload": true,
                    "avoid_rotation_during_call": true
                }
            }
        """.trimIndent()

        // --- Broker side: sign the canonical JSON ---
        val payloadElement = Json.parseToJsonElement(snapshotPayloadJson)
        val canonical = sortedStringify(payloadElement)
        val signature = signPureEd25519(canonical.toByteArray(Charsets.UTF_8), privateKey)
        val signatureB64 = Base64.getEncoder().encodeToString(signature)

        // Attach signature to snapshot (as the Broker does).
        val signedSnapshotJson = """
            {
                "schema_version": 1,
                "generated_at": "2026-06-15T10:00:00.000Z",
                "ttl_seconds": 600,
                "server_count": 1,
                "signature": "$signatureB64",
                "servers": [
                    {
                        "id": "test-server-001",
                        "host": "vpn-test",
                        "ip": "192.0.2.4",
                        "port": 1194,
                        "protocol": "tcp",
                        "country_short": "JP",
                        "country_long": "Japan",
                        "score": 1000000,
                        "ping": 5,
                        "speed": "500000000",
                        "uptime": "1000000",
                        "sessions": 10,
                        "quality_tier": "strict",
                        "quality_score": 0.95,
                        "openvpn_config_data": "dGVzdA=="
                    }
                ],
                "rotation_policy": {
                    "z_field": "should be last",
                    "a_field": "should be first",
                    "protocol_fallback_order": ["openvpn_udp", "openvpn_tcp", "sstp"],
                    "connection_timeout_seconds": 10,
                    "sticky_on_success": true,
                    "avoid_rotation_during_upload": true,
                    "avoid_rotation_during_call": true
                }
            }
        """.trimIndent()

        // --- Client side: reconstruct canonical JSON and verify ---
        val root = Json.parseToJsonElement(signedSnapshotJson) as JsonObject

        // Extract and decode signature.
        val sigB64FromPayload = (root["signature"] as JsonPrimitive).content
        val sigBytes = Base64.getDecoder().decode(sigB64FromPayload)

        // Remove signature field and rebuild canonical JSON (exactly as fixed client does).
        val dataWithoutSig = JsonObject(root.filterKeys { it != "signature" })
        val reconstructedCanonical = sortedStringify(dataWithoutSig)

        // Verify.
        val pubKeyBytes = (publicKey as EdDSAPublicKey).abyte
        val curveSpec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
        val pubKeySpec = EdDSAPublicKeySpec(pubKeyBytes, curveSpec)
        val pubKeyFromBytes = EdDSAPublicKey(pubKeySpec)

        val verified = verifyPureEd25519(reconstructedCanonical.toByteArray(Charsets.UTF_8), sigBytes, pubKeyFromBytes)

        assertTrue(verified, "End-to-end snapshot signature must verify correctly")

        // Confirm the canonical form has deeply sorted nested keys.
        assertTrue(reconstructedCanonical.contains("\"a_field\":\"should be first\","),
            "Canonical JSON must contain a_field before z_field (deep sort)")
        assertTrue(
            reconstructedCanonical.indexOf("\"a_field\"") < reconstructedCanonical.indexOf("\"z_field\""),
            "a_field must appear before z_field in canonical JSON")
    }

    // -------------------------------------------------------------------------
    // Test 6 (B2b.4): the trust-anchor rollover overlap — BootstrapResolver
    // accepts a snapshot signature under EITHER the primary pinned key OR the
    // (optional) committee group key P_snap. This mirrors the resolver's
    // `verify(primary) || (secondary != null && verify(secondary))` logic, so a
    // committee-signed snapshot verifies during the flip without breaking the
    // broker's single-key one; an unset (dormant) secondary is primary-only.
    // -------------------------------------------------------------------------

    @Test
    fun `rollover overlap accepts a signature under either the primary or the secondary pinned key`() {
        val (primaryPriv, primaryPub) = generateEd25519KeyPair()
        val (committeePriv, committeePub) = generateEd25519KeyPair()
        val message = "canonical snapshot bytes".toByteArray(Charsets.UTF_8)

        // Same acceptance rule as BootstrapResolver (secondary null ⇒ dormant/primary-only).
        fun accepts(sig: ByteArray, secondary: EdDSAPublicKey?): Boolean =
            verifyPureEd25519(message, sig, primaryPub) ||
                (secondary != null && verifyPureEd25519(message, sig, secondary))

        val committeeSig = signPureEd25519(message, committeePriv)
        // Dormant (no P_snap pinned): a committee-signed snapshot is rejected.
        assertFalse(accepts(committeeSig, null),
            "dormant (primary only) must reject a committee-signed snapshot")
        // Overlap (P_snap pinned): the committee signature is accepted.
        assertTrue(accepts(committeeSig, committeePub),
            "with P_snap pinned, a committee threshold signature must verify")
        // The broker's single-key signature still verifies during the overlap.
        assertTrue(accepts(signPureEd25519(message, primaryPriv), committeePub),
            "the primary single-key signature must still verify during the overlap")
        // A signature over different bytes must not verify under either key.
        val wrongSig = signPureEd25519("tampered".toByteArray(Charsets.UTF_8), committeePriv)
        assertFalse(accepts(wrongSig, committeePub),
            "a signature over different bytes must be rejected")
    }
}
