package zat.manager.vpn

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * The dissolution scoreboard.
 *
 * The project's destination is that the broker can be switched off. Nothing measured how close we
 * are, and R19 is what that cost: mesh discovery found a volunteer 0.78% of the time, every miss
 * fell through to the broker's `/match` and CONNECTED, and the path built to remove the broker
 * produced nothing for months while every surface stayed green.
 *
 * These tests are about the two properties that make the number trustworthy: it must be able to say
 * ZERO out loud, and it must never carry anything but counts.
 */
class BrokerRelianceTest {

    @BeforeEach
    fun clean() = BrokerReliance.beginAttempt()

    /**
     * THE case worth reporting, and the one a silent metric would lose. A connection that needed
     * nothing from us is the single most important event this project can observe — so zero gets a
     * sentence, not an absence. R19 hid inside exactly that kind of silence.
     */
    @Test
    fun `a connection that needed nothing says so`() {
        assertEquals(0, BrokerReliance.total())
        assertTrue(BrokerReliance.oneLine().contains("broker=0"), BrokerReliance.oneLine())
        assertTrue(
            BrokerReliance.oneLine().contains("did not need us"),
            "zero must be stated, not implied by an empty line: ${BrokerReliance.oneLine()}",
        )
    }

    /** Each reach is counted with WHY, so the score doubles as an ordered work list. */
    @Test
    fun `reaches are counted by reason`() {
        BrokerReliance.note(BrokerReliance.Reason.BUCKET_READ)
        BrokerReliance.note(BrokerReliance.Reason.BUCKET_READ)
        BrokerReliance.note(BrokerReliance.Reason.MATCH)

        assertEquals(3, BrokerReliance.total())
        assertEquals(2, BrokerReliance.breakdown()[BrokerReliance.Reason.BUCKET_READ])
        assertEquals(1, BrokerReliance.breakdown()[BrokerReliance.Reason.MATCH])
        val line = BrokerReliance.oneLine()
        assertTrue(line.contains("broker=3"), line)
        assertTrue(line.contains("bucket_read:2"), line)
        assertTrue(line.contains("match:1"), line)
    }

    /**
     * A previous attempt's score must not survive. A run that reports the last connection's reliance
     * is worse than no number: it would show progress that did not happen, or an alarm that already
     * cleared.
     */
    @Test
    fun `a new attempt starts from zero`() {
        BrokerReliance.note(BrokerReliance.Reason.MATCH)
        assertEquals(1, BrokerReliance.total())

        BrokerReliance.beginAttempt()
        assertEquals(0, BrokerReliance.total())
        assertTrue(BrokerReliance.oneLine().contains("broker=0"), BrokerReliance.oneLine())
    }

    /**
     * Counts and reason classes only. This number is meant to come back from a tester in a censored
     * country, so the line must be as safe to send as `RunDiagnostics`: no URL, no host, no token.
     */
    @Test
    fun `the line carries no address and no identity`() {
        BrokerReliance.Reason.entries.forEach { BrokerReliance.note(it) }
        val line = BrokerReliance.oneLine()

        assertFalse(line.contains("http"), line)
        assertFalse(line.contains("."), "no dotted host may appear: $line")
        assertFalse(line.contains("/"), "no path may appear: $line")
        assertEquals(BrokerReliance.Reason.entries.size, BrokerReliance.total())
    }

    /**
     * Every reason is a distinct piece of the endgame. If one is ever folded into another the score
     * still moves, but it stops telling us WHICH dependency to dissolve next — which is most of the
     * value.
     */
    @Test
    fun `each reason is a separate line item`() {
        BrokerReliance.Reason.entries.forEach { BrokerReliance.note(it) }
        assertEquals(BrokerReliance.Reason.entries.size, BrokerReliance.breakdown().size)
    }
}
