package zat.manager.vpn

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * A9 — the snapshot's freshness rule (`TECH_DEBT` A9).
 *
 * A valid signature says "we produced this", not "this is current". Without a freshness rule, anyone
 * who can control one bootstrap channel or poison a CDN cache pins a client to an old bridge list
 * forever: bridges rotate and get revoked, and that client stays in a world the network has moved
 * past, with the signature intact the whole time so nothing looks wrong.
 *
 * It stopped being hypothetical on 2026-07-27, when the publishing dependency turned out to mean the
 * snapshot FREEZES the moment the broker is switched off. A frozen snapshot and a live one are the
 * same bytes; this rule is what tells them apart.
 */
class BootstrapFreshnessTest {

    @BeforeEach
    fun clean() = BootstrapResolver.resetFreshnessForTest()

    private fun at(iso: String?) = BootstrapResolver.acceptFreshness(iso, "test")

    @Test
    fun `a rollback to an older snapshot is refused`() {
        assertTrue(at("2026-07-27T12:00:00.000Z"), "the first snapshot seen sets the mark")
        assertFalse(
            at("2026-07-20T12:00:00.000Z"),
            "a week-old snapshot must be refused even though its signature is perfectly valid",
        )
    }

    @Test
    fun `moving forward is accepted, and the same snapshot twice is fine`() {
        assertTrue(at("2026-07-27T12:00:00.000Z"))
        assertTrue(at("2026-07-27T12:05:00.000Z"), "a newer snapshot advances the mark")
        assertTrue(
            at("2026-07-27T12:05:00.000Z"),
            "an equal stamp is the same snapshot arriving again — from another channel or another poll",
        )
        assertFalse(at("2026-07-27T12:00:00.000Z"), "…and the mark stayed at the newest, not the last")
    }

    // Leniency here would be a way around the entire rule, so it is checked rather than assumed.
    @Test
    fun `a missing or unreadable stamp is refused, not waved through`() {
        assertFalse(at(null), "no stamp at all")
        assertFalse(at(""), "empty")
        assertFalse(at("not-a-timestamp"), "unparseable")
        assertFalse(at("1785000000"), "epoch seconds are not the format the signer emits")
    }

    /**
     * The mark has to survive a restart, because "app closed overnight" is exactly the window a freeze
     * attack wants. Without an installed store it is in-memory only — still useful within a session,
     * but that is a degraded mode, not the intended one.
     */
    @Test
    fun `an installed store carries the mark across a restart`() {
        var persisted = 0L
        val store = object : BootstrapResolver.FreshnessStore {
            override fun read(): Long = persisted
            override fun write(value: Long) { persisted = value }
        }

        BootstrapResolver.installFreshnessStore(store)
        assertTrue(at("2026-07-27T12:00:00.000Z"))
        assertEquals(1785153600000L, persisted, "the accepted stamp was written through")

        // The restart: fresh in-memory state, same store.
        BootstrapResolver.resetFreshnessForTest()
        BootstrapResolver.installFreshnessStore(store)
        assertFalse(
            at("2026-07-20T12:00:00.000Z"),
            "after a restart the client must still refuse the rollback it already knew about",
        )
    }

    /**
     * A store that throws must not cost the user their connection. The mark degrades to in-memory —
     * weaker, but a bootstrap that fails closed on a disk error would be a worse bug than the one
     * this rule exists to fix.
     */
    @Test
    fun `a failing store degrades to in-memory instead of blocking the bootstrap`() {
        BootstrapResolver.installFreshnessStore(object : BootstrapResolver.FreshnessStore {
            override fun read(): Long = throw IllegalStateException("disk")
            override fun write(value: Long) = throw IllegalStateException("disk")
        })
        assertTrue(at("2026-07-27T12:00:00.000Z"), "a store failure must not reject a good snapshot")
        assertFalse(at("2026-07-20T12:00:00.000Z"), "and the in-memory mark still holds this session")
    }
}

/**
 * The stored-snapshot fallback: a client that has connected before must survive every channel being
 * blocked at once — which is what a censor who blocks our six accounts achieves in one move.
 *
 * The property that makes it safe is that the stored body goes back through the SAME parse: the
 * signature is re-verified against the pinned keys and the freshness rule still applies. A fallback
 * that trusted its own cache would be a blind-trust path bolted onto a design whose whole point is
 * that nothing is trusted without a signature.
 */
class BootstrapStoredSnapshotTest {

    @org.junit.jupiter.api.BeforeEach
    fun clean() = BootstrapResolver.resetFreshnessForTest()

    /** A store that records what it was asked to keep. */
    private class Recording : BootstrapResolver.FreshnessStore {
        var mark = 0L
        var snapshot: String? = null
        override fun read(): Long = mark
        override fun write(value: Long) { mark = value }
        override fun readSnapshot(): String? = snapshot
        override fun writeSnapshot(body: String) { snapshot = body }
    }

    @Test
    fun `a store may decline to keep the snapshot, and nothing breaks`() {
        // The interface defaults are no-ops: a store that only wants the freshness mark is valid, and
        // the fallback simply has nothing to offer. This is checked because the defaults are the only
        // thing standing between "optional feature" and "every implementer must write two more methods".
        val markOnly = object : BootstrapResolver.FreshnessStore {
            override fun read(): Long = 0L
            override fun write(value: Long) = Unit
        }
        BootstrapResolver.installFreshnessStore(markOnly)
        assertEquals(null, markOnly.readSnapshot())
    }

    @Test
    fun `the freshness mark and the stored snapshot are kept independently`() {
        val store = Recording()
        BootstrapResolver.installFreshnessStore(store)
        assertTrue(BootstrapResolver.acceptFreshness("2026-07-27T12:00:00.000Z", "test"))
        assertEquals(1785153600000L, store.mark, "the mark was written")
        assertEquals(null, store.snapshot, "…but accepting a stamp is not the same as storing a body")
    }
}
