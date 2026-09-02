package zat.manager.vpn

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * R29 — a completed round that does not verify must not end the connect.
 *
 * Seen live 2026-08-11 13:45:52 with one of three members stopped: the round completed on two
 * members and `batch_finalize (DLEQ verify)` threw. Nothing caught it — the exception left
 * `thresholdEval` untouched, `discover`'s outer catch logged "discover failed", and the client went
 * to the broker. So a member that goes SILENT was tolerated (R24) while a member that answers
 * WRONGLY took the whole mesh path down, which is backwards: the second is the case a `t`-of-`n`
 * committee is supposed to be for, and the first is merely absence.
 *
 * It is also the cheaper attack. A hostile member need not go offline, be probed, or be traced — it
 * answers, correctly formed and wrong, and every client that includes it in its quorum is pushed
 * back onto the broker. Against the dissolution endgame, where there is no broker to be pushed onto,
 * it is simply a denial of the network by one node out of three.
 *
 * The proof is over the COMBINATION, so a failure accuses the set and never a member. The only
 * question the protocol can answer is "who, if left out, makes the rest verify" — which is what
 * these subsets ask, in order.
 */
class ThresholdSubsetTest {

    private val committee = listOf("member-1", "member-2", "member-3")

    /** With n=3 and t=2 there are three pairs, and if one member is lying one pair is the honest
     *  one. Each subset leaves out exactly one member, so the index of the successful attempt names
     *  the liar — that is the difference between recovering and merely surviving. */
    @Test
    fun `each subset leaves exactly one member out, in order`() {
        val subsets = MeshRendezvousClient.subsetsExcludingOne(committee, t = 2)
        assertEquals(
            listOf(
                listOf("member-2", "member-3"),
                listOf("member-1", "member-3"),
                listOf("member-1", "member-2"),
            ),
            subsets,
        )
        subsets.forEach { assertEquals(2, it.size) }
    }

    /**
     * The honest stop. With exactly `t` members present, leaving one out drops below the threshold,
     * so there is NO subset to try — and the caller must say that rather than appear to have tried
     * something. Returning a sub-threshold set here would send an evaluation that cannot succeed and
     * report its failure as if it were the committee's.
     */
    @Test
    fun `no subset is offered when dropping one would fall below t`() {
        assertTrue(MeshRendezvousClient.subsetsExcludingOne(listOf("a", "b"), t = 2).isEmpty())
        assertTrue(MeshRendezvousClient.subsetsExcludingOne(listOf("a"), t = 1).isEmpty())
        assertTrue(MeshRendezvousClient.subsetsExcludingOne(emptyList<String>(), t = 1).isEmpty())
    }

    /** A larger committee still only ever excludes ONE member per attempt: the cost stays linear in
     *  `n`, not exponential, and one liar is the case actually being defended against. */
    @Test
    fun `the number of attempts is linear in the committee size`() {
        val five = listOf("a", "b", "c", "d", "e")
        val subsets = MeshRendezvousClient.subsetsExcludingOne(five, t = 3)
        assertEquals(5, subsets.size)
        subsets.forEach { assertEquals(4, it.size) }
        // Every member is the excluded one exactly once, so a single liar is always isolated.
        assertEquals(five.toSet(), five.indices.map { five[it] }.toSet())
        five.forEachIndexed { i, m -> assertTrue(!subsets[i].contains(m)) }
    }
}
