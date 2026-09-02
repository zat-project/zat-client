package zat.manager.vpn

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * R28 — a read source that goes silent stops being the one we wait on, and is never thrown away.
 *
 * Measured live 2026-08-11 with one of three shards stopped. R26's bound had already fixed the
 * evaluation (5.6 s a round) and the connect still took 6 m 26 s, because the read loop asked the dead
 * shard again for every one of eight buckets — `HTTP_RETRIES = 3` over a 12 s connect and a 12 s read
 * is ~36 s a call, two calls a bucket. For 5 m 49 s the phase logged nothing, so it was
 * indistinguishable from hung, which is exactly how it was reported.
 *
 * Two attempts at RETIRING a bad source both failed the same way, in production, and that is why this
 * class orders instead. A proxy-read makes a seed shard consult the shards that OWN a bucket, so when
 * one node is dead every proxy fails on the buckets that node owns — evidence identical to the proxy
 * itself being dead. Dropping after one failure retired two of three shards (both naming `bucket 6`
 * with only ONE node stopped); requiring two distinct buckets retired the same two, because each owns
 * more than one. Both runs ended `0 answered via shard(s)`, the whole read phase served by the broker
 * mirror: faster than the stall, and further from dissolution, which is the wrong trade.
 *
 * Ordering cannot make that mistake. Its worst case is asking a good source slightly later.
 */
class ReadRotationTest {

    private val dead = MeshRendezvousClient.BucketRead.Unreachable
    private val someRecords = MeshRendezvousClient.BucketRead.Answered(listOf("sealed-record"))
    private val emptyBucket = MeshRendezvousClient.BucketRead.Answered(emptyList())

    /** Nothing has failed: the original order stands. */
    @Test
    fun `an untouched rotation preserves the seed order`() {
        assertEquals(listOf(0, 1, 2), MeshRendezvousClient.ReadRotation().order(3))
    }

    /** The saving: the silent shard sinks, so the next bucket does not begin by waiting on it. */
    @Test
    fun `a source that fails sinks to the back for the next bucket`() {
        val rotation = MeshRendezvousClient.ReadRotation()
        rotation.record(0, bucket = 3, outcome = dead)
        assertEquals(listOf(1, 2, 0), rotation.order(3))

        // ...and it keeps sinking as it keeps failing, without ever leaving.
        rotation.record(1, bucket = 3, outcome = dead)
        rotation.record(1, bucket = 4, outcome = dead)
        assertEquals(listOf(2, 0, 1), rotation.order(3))
    }

    /**
     * The property retiring did not have. A shard that fails on the buckets a dead node OWNS is still
     * asked for every other bucket — so the connect keeps reading from shards instead of handing the
     * lot to the broker mirror, which is what both retiring rules did in production.
     */
    @Test
    fun `a failed source is never removed, only moved`() {
        val rotation = MeshRendezvousClient.ReadRotation()
        repeat(8) { rotation.record(0, bucket = it, outcome = dead) }
        val order = rotation.order(3)
        assertTrue(order.contains(0), "a source must never be lost — it is the mesh read we are protecting")
        assertEquals(3, order.size)
        assertEquals(2, order.indexOf(0)) // last, but present
    }

    /** The drop notice is said once per source, not once per bucket: a silent stall must not simply
     *  become a noisy one. */
    @Test
    fun `only the first failure of a source is announced`() {
        val rotation = MeshRendezvousClient.ReadRotation()
        assertTrue(rotation.record(2, bucket = 1, outcome = dead))
        assertFalse(rotation.record(2, bucket = 2, outcome = dead))
        assertFalse(rotation.record(2, bucket = 3, outcome = dead))
        assertEquals(1, rotation.sourcesThatFailed())
    }

    /**
     * A bucket with nothing in it is a good answer from a good shard — most buckets are empty, since
     * `k` is tuned to about two hits per read. Counting it as a failure would reorder the whole
     * rotation on noise.
     */
    @Test
    fun `an empty bucket is an answer, not a failure`() {
        val rotation = MeshRendezvousClient.ReadRotation()
        assertFalse(rotation.record(0, bucket = 1, outcome = emptyBucket))
        assertFalse(rotation.record(0, bucket = 2, outcome = someRecords))
        assertEquals(listOf(0, 1, 2), rotation.order(3))
        assertEquals(0, rotation.sourcesThatFailed())
    }

    /**
     * A read-PoW this device could not solve in time is OUR failure. The shard served the challenge
     * and will serve the next one; the same timeout would hit whatever source we moved to.
     */
    @Test
    fun `our own read-PoW timeout does not move the source`() {
        val rotation = MeshRendezvousClient.ReadRotation()
        assertFalse(rotation.record(1, bucket = 1, outcome = MeshRendezvousClient.BucketRead.PowTimedOut))
        assertEquals(listOf(0, 1, 2), rotation.order(3))
        assertEquals(0, rotation.sourcesThatFailed())
    }

    /**
     * `survivors` feeds the revocation fetch, which walks every source on every discovery and
     * re-match and is explicitly fail-open. Skipping a known-silent source there is safe precisely
     * because a miss keeps the unfiltered set — unlike the read path, where skipping loses records.
     */
    @Test
    fun `the revocation fetch skips a source already known to be silent`() {
        val rotation = MeshRendezvousClient.ReadRotation()
        val sources = listOf("a", "b", "c")
        rotation.record(1, bucket = 1, outcome = dead)
        assertEquals(listOf("a", "c"), rotation.survivors(sources))
        assertEquals(1, rotation.sourcesThatFailed())
    }
}
