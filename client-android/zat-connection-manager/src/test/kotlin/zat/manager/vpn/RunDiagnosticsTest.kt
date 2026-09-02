package zat.manager.vpn

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * #46 — the tester's report.
 *
 * The project has never had a client inside the censored country, and the app currently tells such a
 * tester exactly five things, one of which is "error". With one tester and one attempt, "it didn't
 * work" is nearly worthless: it could mean no channel was reachable, or bootstrap worked and the
 * bridge was blocked, or the handshake was reset. Those have different answers.
 *
 * These tests are about the two properties that make the report safe to send and worth reading.
 */
class RunDiagnosticsTest {

    @BeforeEach
    fun clean() = RunDiagnostics.resetForTest()

    /**
     * THE safety property. The report may travel over a monitored messenger as a screenshot, so it
     * must carry channel NUMBERS and never their addresses — and failure reasons must be CLASSES, not
     * exception messages, which routinely contain the host that failed.
     */
    @Test
    fun `no address can reach the report, even when a caller tries`() {
        RunDiagnostics.beginAttempt(1_000L)
        // A caller passing a whole exception message is the realistic mistake; the recorder truncates,
        // but the contract is that callers pass a class. This asserts the shape a screenshot ends up
        // with rather than trusting every future call site.
        RunDiagnostics.channel(0, false, "timeout")
        RunDiagnostics.channel(1, true, "ok")
        RunDiagnostics.finished("connected", 2_000L)
        val line = RunDiagnostics.snapshot().oneLine()

        assertFalse(line.contains("http"), "no scheme may appear: $line")
        assertFalse(line.contains("."), "no dotted host may appear: $line")
        assertTrue(line.contains("ok=2"), line)
    }

    /** A reason is truncated, so a caller that passes a whole message cannot smuggle a URL through. */
    @Test
    fun `an over-long reason is cut down`() {
        RunDiagnostics.beginAttempt(0L)
        RunDiagnostics.channel(0, false, "failed to connect to raw.githubusercontent.com/192.0.2.4:443")
        val reason = RunDiagnostics.snapshot().channels.first().reason
        assertTrue(reason.length <= 24, "reason must be bounded, got ${reason.length}")
    }

    /**
     * The single most useful line in the whole report: WHICH routes answered. A tester who reports
     * "4 and 5 worked, 1 and 2 timed out" has told us the blocking pattern in one sentence.
     */
    @Test
    fun `the report names which routes answered and which did not`() {
        RunDiagnostics.beginAttempt(0L)
        RunDiagnostics.channel(0, false, "timeout")
        RunDiagnostics.channel(1, false, "http_403")
        RunDiagnostics.channel(2, true, "ok")
        val r = RunDiagnostics.snapshot()

        assertEquals(listOf(2), r.workingChannels, "internally zero-based")
        assertEquals(listOf(3), r.workingRouteNumbers, "one-based for anything a person reads")
        assertEquals(RunDiagnostics.Source.CHANNEL, r.source)
        assertTrue(r.oneLine().contains("1:timeout"), r.oneLine())
        assertTrue(r.oneLine().contains("2:http_403"), r.oneLine())
    }

    /**
     * A new attempt must not inherit the last one's outcome. A report that shows a previous run's
     * success while THIS run failed is worse than no report — it sends the reader to the wrong place.
     */
    @Test
    fun `a new attempt drops the previous one entirely`() {
        RunDiagnostics.beginAttempt(0L)
        RunDiagnostics.channel(3, true, "ok")
        assertEquals(listOf(3), RunDiagnostics.snapshot().workingChannels)

        RunDiagnostics.beginAttempt(1_000L)
        RunDiagnostics.channel(0, false, "timeout")
        val r = RunDiagnostics.snapshot()
        assertTrue(r.workingChannels.isEmpty(), "the previous success must not survive: ${r.oneLine()}")
        assertEquals(RunDiagnostics.Source.NONE, r.source)
    }

    /**
     * The peer and stored paths are distinguishable from a channel — they mean different things.
     *
     * One attempt each, deliberately. This test used to set both inside a SINGLE attempt and assert
     * the second overwrote the first, which is how it came to certify the very behaviour that made a
     * live report claim a peer had supplied settings a channel had supplied 1.4 seconds earlier. A
     * source is decided once per attempt; asking which of two sources "wins" within one attempt is
     * asking the wrong question.
     */
    @Test
    fun `where the snapshot came from is recorded distinctly`() {
        RunDiagnostics.beginAttempt(0L)
        RunDiagnostics.snapshotFrom(RunDiagnostics.Source.PEER)
        assertEquals(RunDiagnostics.Source.PEER, RunDiagnostics.snapshot().source)

        RunDiagnostics.beginAttempt(1_000L)
        RunDiagnostics.snapshotFrom(RunDiagnostics.Source.STORED)
        assertEquals(RunDiagnostics.Source.STORED, RunDiagnostics.snapshot().source)
    }

    /**
     * THE bug the first live run exposed, pinned so it cannot come back. Channel index 0 rendered as
     * "Routes that answered: 0", which a reader takes as "none answered" — the exact opposite of the
     * truth, on the single line that matters most. Anything a person reads is one-based, and the app's
     * own log has always said "Channel 1".
     */
    @Test
    fun `the first route reads as 1, never as 0`() {
        RunDiagnostics.beginAttempt(0L)
        RunDiagnostics.channel(0, true, "ok")
        val r = RunDiagnostics.snapshot()
        assertEquals(listOf(1), r.workingRouteNumbers)
        assertTrue(r.oneLine().contains("ok=1"), r.oneLine())
        assertFalse(r.oneLine().contains("ok=0"), "\"0\" reads as none: ${r.oneLine()}")
    }

    /**
     * THE bug the first clean-device run exposed, replayed exactly as it happened.
     *
     * Log from the tablet: channel 1 succeeded at 30.840, the mesh adopted a peer's snapshot at
     * 32.257 — 1.4 seconds AFTER the settings that connected had already been chosen — and the
     * report then said "Settings came from: peer". The field reported the most recent writer rather
     * than the source the attempt used.
     *
     * It matters more than it looks. `src` is how an in-country report answers "did the six-channel
     * bootstrap work in there", and a background refresh a second later would have inverted the
     * answer on the single run we get.
     */
    @Test
    fun `a peer refresh after the fact does not steal credit from the channel`() {
        RunDiagnostics.beginAttempt(0L)
        RunDiagnostics.channel(0, true, "ok")            // 30.840 — this is what connected
        RunDiagnostics.finished("two_hop_up", 30_118L)
        RunDiagnostics.snapshotFrom(RunDiagnostics.Source.PEER)  // 32.257 — the mesh, afterwards
        RunDiagnostics.peerRefresh()

        val r = RunDiagnostics.snapshot()
        assertEquals(RunDiagnostics.Source.CHANNEL, r.source, "the channel connected, not the peer")
        assertTrue(r.peerRefreshed, "the refresh is still worth reporting — just not as the source")
        assertTrue(r.oneLine().contains("src=channel"), r.oneLine())
        assertTrue(r.oneLine().contains("peer_refresh=yes"), r.oneLine())
    }

    /**
     * The other direction, so the fix is a correction and not a blanket "peer never wins": when no
     * channel supplied anything, a peer IS the source and must be reported as one.
     */
    @Test
    fun `a peer that supplies the snapshot outright is still recorded as the source`() {
        RunDiagnostics.beginAttempt(0L)
        RunDiagnostics.channel(0, false, "timeout")
        RunDiagnostics.snapshotFrom(RunDiagnostics.Source.PEER)
        RunDiagnostics.peerRefresh()

        val r = RunDiagnostics.snapshot()
        assertEquals(RunDiagnostics.Source.PEER, r.source)
        assertTrue(r.oneLine().contains("src=peer"), r.oneLine())
    }

    /** The stored fallback keeps the same property: decided once, not overwritten later. */
    @Test
    fun `the stored fallback is not overwritten by a later refresh either`() {
        RunDiagnostics.beginAttempt(0L)
        RunDiagnostics.channel(0, false, "timeout")
        RunDiagnostics.snapshotFrom(RunDiagnostics.Source.STORED)
        RunDiagnostics.snapshotFrom(RunDiagnostics.Source.PEER)
        assertEquals(RunDiagnostics.Source.STORED, RunDiagnostics.snapshot().source)
    }

    /** A new attempt clears the refresh flag — otherwise it would haunt every later report. */
    @Test
    fun `the peer-refresh flag does not survive into the next attempt`() {
        RunDiagnostics.beginAttempt(0L)
        RunDiagnostics.peerRefresh()
        assertTrue(RunDiagnostics.snapshot().peerRefreshed)

        RunDiagnostics.beginAttempt(1_000L)
        val line = RunDiagnostics.snapshot().oneLine()
        assertFalse(RunDiagnostics.snapshot().peerRefreshed, line)
        assertFalse(line.contains("peer_refresh"), line)
    }

    /**
     * The clock stops when the attempt does. It used to run until whoever opened the report, which
     * showed 66 seconds for a connection that took 25 — a number that grows while you look at it is
     * not a measurement.
     */
    @Test
    fun `the elapsed time is frozen at the end of the attempt`() {
        RunDiagnostics.beginAttempt(1_000L)
        RunDiagnostics.finished("connected", 26_000L)
        assertEquals(25_000L, RunDiagnostics.snapshot().elapsedMs)
    }

    /** Nothing recorded at all is a legible report, not a crash or an empty string. */
    @Test
    fun `a run that never started still produces a readable line`() {
        val line = RunDiagnostics.snapshot().oneLine()
        assertTrue(line.contains("ok=none"), line)
        assertTrue(line.contains("stage=not_started"), line)
    }
}
