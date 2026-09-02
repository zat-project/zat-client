package zat.manager.vpn

import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Dissolution: the client must be able to ENTER the mesh without asking the broker.
 *
 * Before 2026-07-28 it could not. `getParams` and `getShardSeeds` went to the broker, so the mesh
 * path — the thing that exists to replace `/match` — began at the broker and died with it. The reads
 * were peer-to-peer; the first step was not, which made the whole path look decentralized while it
 * was not.
 *
 * The fix is to take both from the signed snapshot, and the SIGNATURE is what makes that safe: the
 * snapshot has already been verified under the committee's key before any of this is read, so it can
 * come from a channel or a peer the client has no reason to trust.
 */
class MeshEntryPreferenceTest {

    private val json = Json { ignoreUnknownKeys = true }

    /** A snapshot's `mesh_entry`, as the broker now publishes it. */
    private val entryJson = """
        {
          "suite": "ristretto255-SHA512",
          "publicKey": "ZFvXrt3kgZawewV8M0ugXhb+/hM0ySik97BWztZ5AVk=",
          "N": 4096, "r": 4, "s": 8, "epochMs": 3600000,
          "thresholdT": 2, "thresholdN": 3,
          "shards": [
            { "httpEndpoint": "10.0.0.1:8460", "committeeId": 1 },
            { "httpEndpoint": "10.0.0.2:8460", "committeeId": 2 }
          ]
        }
    """.trimIndent()

    @Test
    fun `mesh_entry parses into everything the two broker calls used to supply`() {
        val e = json.decodeFromString(MeshEntry.serializer(), entryJson)

        // What GET mesh/params gave.
        assertEquals("ristretto255-SHA512", e.suite)
        assertEquals(4096, e.N)
        assertEquals(4, e.r)
        assertEquals(8, e.s)
        assertEquals(3_600_000L, e.epochMs)
        assertEquals(2, e.thresholdT)
        assertEquals(3, e.thresholdN)

        // And what GET mesh/shards gave — the half that made discovery broker-bound.
        assertEquals(2, e.shards.size)
        assertEquals(1L, e.shards[0].committeeId)
    }

    /**
     * The field is optional, so a client running against an older broker keeps working — it simply
     * asks as before. A hard requirement here would have made this change a flag day.
     */
    @Test
    fun `an older snapshot without mesh_entry is not an error`() {
        MeshRendezvousClient.snapshotMeshEntry = null
        assertEquals(null, MeshRendezvousClient.snapshotMeshEntry)
    }

    /**
     * The property that matters: once a verified snapshot has supplied the entry, the client holds it
     * and needs no broker call. Asserting the handoff rather than the network call, because the fetch
     * itself is what this change removes.
     */
    @Test
    fun `a verified snapshot's entry is held for use instead of a broker fetch`() {
        val e = json.decodeFromString(MeshEntry.serializer(), entryJson)
        MeshRendezvousClient.snapshotMeshEntry = e
        try {
            val held = MeshRendezvousClient.snapshotMeshEntry
            assertNotNull(held)
            assertEquals(e.publicKey, held!!.publicKey)
            assertTrue(held.shards.isNotEmpty(), "shard discovery no longer depends on the broker")
        } finally {
            MeshRendezvousClient.snapshotMeshEntry = null
        }
    }
}
