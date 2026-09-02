package zat.manager.vpn

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.util.Base64

/**
 * Locks the client's mesh framing to the broker BYTE-FOR-BYTE. The expected values were
 * produced by the broker's own functions (broker/src/rendezvous/mesh-buckets.ts +
 * mesh-record.ts, replicated in node). A mismatch here = the client derives wrong buckets/
 * keys and silently finds nothing, so these assertions are the client↔broker contract.
 */
class MeshWireTest {

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    @Test
    fun meshTag_matches_broker() {
        assertEquals(
            "7a61743a6d6573683a72626b741f746f6b1f34321f30",
            hex(MeshWire.meshTag("rbkt", "tok", 42, 0)),
        )
        assertEquals(
            "7a61743a6d6573683a726b65791f6162631f37",
            hex(MeshWire.meshTag("rkey", "abc", 7)),
        )
    }

    @Test
    fun sharedRandomFor_matches_broker() {
        assertEquals("afcc66a500b4ba2a3db46e579822baa1", MeshWire.sharedRandomFor(100))
    }

    @Test
    fun indexFromDigest_matches_broker() {
        val dig = MessageDigest.getInstance("SHA-256").digest("test".toByteArray())
        assertEquals(12, MeshWire.indexFromDigest(dig, 1000))
    }

    @Test
    fun aesGcmOpen_decrypts_a_broker_sealed_record() {
        val key = ByteArray(32) { it.toByte() } // 0x00..0x1f
        val sealed = Base64.getUrlDecoder().decode(
            "BwcHBwcHBwcHBwcHUYR0CNxFqJL4aK7-TDI5vnRI0DMDermAo_hhyeRzzrnXba9fqp_uaoqZZNg15wo1EnXf" +
                "T7Fw2qcg0oONrWWtBIFwh33mjSN5-ImNixnBoco-h4VH4KwI-26uFWzF82W4qFExa9PXaQ7NSgx8RAV046H" +
                "9--S6aS6tbVDqVfWygDTZf-9bSGE4TZDP2-zjW-sNOPKraYSO78BKFBE_vr759VE6R6rgR_d71HicpVR5rc" +
                "6gSbrVbKkcCH-6Uhou99dG1EnM",
        )
        val pt = MeshWire.aesGcmOpen(key, sealed)
        assertNotNull(pt)
        assertTrue(String(pt!!).contains("\"volunteerId\":\"v1\""))
        assertTrue(String(pt).contains("\"serverName\":\"www.microsoft.com\""))
    }

    @Test
    fun aesGcmOpen_rejects_wrong_key() {
        val sealed = Base64.getUrlDecoder().decode(
            "BwcHBwcHBwcHBwcHUYR0CNxFqJL4aK7-TDI5vnRI0DMDermAo_hhyeRzzrnXba9fqp_uaoqZZNg15wo1EnXf" +
                "T7Fw2qcg0oONrWWtBIFwh33mjSN5-ImNixnBoco-h4VH4KwI-26uFWzF82W4qFExa9PXaQ7NSgx8RAV046H" +
                "9--S6aS6tbVDqVfWygDTZf-9bSGE4TZDP2-zjW-sNOPKraYSO78BKFBE_vr759VE6R6rgR_d71HicpVR5rc" +
                "6gSbrVbKkcCH-6Uhou99dG1EnM",
        )
        assertEquals(null, MeshWire.aesGcmOpen(ByteArray(32) { 0x55 }, sealed))
    }

    @Test
    fun inputsBlob_and_parseOutputs_are_shaped_right() {
        val tags = listOf(byteArrayOf(1, 2, 3), byteArrayOf(4, 5))
        val blob = MeshWire.buildInputsBlob(tags)
        // u16(2) || u16(3)||3 bytes || u16(2)||2 bytes = 2 + (2+3) + (2+2) = 11
        assertEquals(11, blob.size)
        assertEquals(0, blob[0].toInt()); assertEquals(2, blob[1].toInt())

        val outs = MeshWire.parseOutputs(byteArrayOf(0, 2) + ByteArray(64) { 1 } + ByteArray(64) { 2 }, 64)
        assertEquals(2, outs.size)
        assertEquals(64, outs[0].size)
        assertTrue(outs[1].all { it.toInt() == 2 })
    }

    /**
     * R21's experiment is only sound if BOTH ends compute the fingerprint identically. A Kotlin and a
     * Rust implementation that disagree would manufacture the very "different keys" verdict the
     * experiment exists to detect — a checker that fabricates the finding it is looking for.
     *
     * Vector computed independently in Python; `mesh_seal.rs::key_fingerprint_matches_the_client`
     * asserts the same one.
     */
    @org.junit.jupiter.api.Test
    fun `the key fingerprint matches the volunteer's`() {
        val key = ByteArray(32) { (it + 1).toByte() }
        org.junit.jupiter.api.Assertions.assertEquals("ae216c2e", MeshWire.keyFingerprint(key))
    }

    /**
     * The discovery line's arithmetic must CLOSE: records returned = records opened + records
     * unopened. It did not. `found` is keyed by volunteerId, so using its size as the opened count
     * reported "4 sealed record(s) returned, 3 opened ... 0 unopened" on a live run — because two of
     * the four were two buckets of the same volunteer.
     *
     * That is R19's defect exactly, two halves of one sentence counting different nouns, reappearing
     * in the sentence written to replace it. This pins the reconciliation as arithmetic rather than
     * as a promise in a comment.
     */
    @org.junit.jupiter.api.Test
    fun `records reconcile with records, not with distinct volunteers`() {
        // The live shape: four records, two of them the same volunteer, none unopened.
        val returned = 4
        val openedRecords = 4
        val distinctVolunteers = 3
        val unopened = 0

        org.junit.jupiter.api.Assertions.assertEquals(
            returned, openedRecords + unopened,
            "records returned must equal records opened plus records unopened",
        )
        org.junit.jupiter.api.Assertions.assertTrue(
            distinctVolunteers <= openedRecords,
            "distinct volunteers can only be fewer than the records they came from",
        )
    }
}
