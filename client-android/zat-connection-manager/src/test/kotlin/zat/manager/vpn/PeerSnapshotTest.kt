package zat.manager.vpn

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * #33 — the client takes its snapshot from a PEER, with no channel and no broker in the path.
 *
 * This is the step that changes what the six public channels ARE. Until now they were the only way a
 * snapshot could reach anyone: block the set and every client freezes on whatever it last stored,
 * however old. A volunteer can serve the document instead, and the channels demote to "how you find
 * your very first node".
 *
 * A signed snapshot does not need a TRUSTED carrier, only a reachable one — a peer that lies is
 * caught by the signature, and a peer that withholds is merely useless. These tests are about the two
 * halves that make that true in practice: nothing unverified is ever adopted, and one unhelpful peer
 * cannot shadow the others.
 */
class PeerSnapshotTest {

    // ---- what may be adopted -------------------------------------------------------------------

    /**
     * The direction that matters. A peer is an arbitrary node on the network; if anything it serves
     * could be adopted, #33 would be a way to hand every client a bridge list of the attacker's
     * choosing — strictly worse than the channels it replaces.
     *
     * In a unit-test build there is no pinned committee key, so `parseSnapshot` refuses everything,
     * which is exactly the fail-closed shape being asserted: no key, no adoption, no exception.
     */
    @Test
    fun `nothing a peer serves is adopted without passing the same verification a channel's body does`() {
        assertFalse(BootstrapResolver.adoptFromPeer(""), "an empty body")
        assertFalse(BootstrapResolver.adoptFromPeer("   "), "whitespace")
        assertFalse(BootstrapResolver.adoptFromPeer("<html>cover page</html>"), "a stealth cover page")
        assertFalse(BootstrapResolver.adoptFromPeer("{\"reality_servers\":[]}"), "unsigned JSON")
        assertFalse(
            BootstrapResolver.adoptFromPeer(
                """{"generated_at":"2099-01-01T00:00:00.000Z","signature":"AAAA","reality_servers":[{"address":"192.0.2.4"}]}""",
            ),
            "a future stamp and a plausible shape are not a signature",
        )
    }

    // ---- which peer is believed ----------------------------------------------------------------

    private val mesh = MeshRendezvousClient

    /**
     * THE bug this ordering exists to prevent. A peer can answer and still be useless — a 503 before
     * its own first fetch, a body older than the one this device already holds, a cover page — and if
     * "answered" counted as "done", that one peer would shadow every other peer we have open a tunnel
     * to. The search stops on ADOPTED, not on answered.
     */
    @Test
    fun `a peer that answers with something unusable does not end the search`() {
        val asked = mutableListOf<String>()
        val adopted = mesh.adoptFirstUsable(sequenceOf("stale", "cover-page", "good")) {
            asked += it
            it == "good"
        }
        assertTrue(adopted)
        assertEquals(listOf("stale", "cover-page", "good"), asked, "every peer up to the usable one is asked")
    }

    /** …and no peer beyond the first usable one is asked, because the sequence is walked lazily. */
    @Test
    fun `the search stops at the first peer whose snapshot is adopted`() {
        var fetches = 0
        val bodies = generateSequence {
            fetches += 1
            "body-$fetches"
        }
        val adopted = mesh.adoptFirstUsable(bodies) { true }
        assertTrue(adopted)
        assertEquals(1, fetches, "a peer after the first success must never even be fetched from")
    }

    /**
     * An unreachable peer contributes `null`, and a blank body is the same nothing. Neither is an
     * answer, and neither may be mistaken for one — that would turn one dead peer into a refusal to
     * ask the live ones.
     */
    @Test
    fun `unreachable and empty peers are skipped rather than counted`() {
        val asked = mutableListOf<String>()
        val adopted = mesh.adoptFirstUsable(sequenceOf(null, "", "  ", "real")) {
            asked += it
            true
        }
        assertTrue(adopted)
        assertEquals(listOf("real"), asked)
    }

    /** Every peer unusable is a normal outcome — this device keeps what it has. Never an exception. */
    @Test
    fun `all peers unusable is false, not a failure`() {
        assertFalse(mesh.adoptFirstUsable(sequenceOf("a", "b")) { false })
        assertFalse(mesh.adoptFirstUsable(emptySequence()) { true })
    }

    /**
     * A hostile peer must not be able to throw its way out of the loop and take the remaining peers
     * with it. The refresh runs inside a working session; one bad body may cost us that peer, never
     * the rest of them.
     */
    @Test
    fun `a peer whose body throws does not stop the ones after it`() {
        val adopted = mesh.adoptFirstUsable(sequenceOf("boom", "fine")) {
            if (it == "boom") throw IllegalStateException("malformed") else true
        }
        assertTrue(adopted, "the peer after the one that threw must still be tried")
    }
}
