package zat.manager.vpn

/**
 * What happened on the last connection attempt, in a form a TESTER can screenshot and send back.
 *
 * ## Why this exists
 *
 * Everything ZAT does has been validated from OUTSIDE the censored country. The single most valuable
 * piece of evidence the project has never had is one real client inside it — and the app currently
 * tells such a tester exactly five things: disconnected, connecting, connected, reconnecting, ERROR.
 *
 * "It didn't work" is nearly worthless with one tester and one attempt. It could mean no channel was
 * reachable, or bootstrap succeeded and the bridge was blocked, or the Reality handshake was reset, or
 * it connected and something else failed. Those have completely different answers, and guessing wrong
 * costs another round trip through a person who took a risk to help.
 *
 * ## What is deliberately NOT here
 *
 * **No channel URLs — only their index.** The URLs are semi-secret (obfuscated in the binary), and a
 * screenshot sent over a monitored messenger must not carry them. An index tells us everything we need
 * ("channel 4 worked, 1 and 2 timed out") and tells a censor nothing it did not already have.
 *
 * **No IPs, no hostnames, no user data**, consistent with `PRIVACY_MODEL §11`. Failure reasons are
 * CLASSES — `timeout`, `http_403`, `tls`, `no_routes` — never messages that might carry an address.
 *
 * The record is in memory and resets each attempt. It is a diagnosis of the run in front of you, not a
 * history: a history is a file on a device that may be inspected at a border.
 */
object RunDiagnostics {

    /** One channel's outcome. `index` is its position in the bootstrap order, never its address. */
    data class ChannelOutcome(val index: Int, val ok: Boolean, val reason: String)

    /** Where the snapshot that was actually used came from. */
    enum class Source { NONE, CHANNEL, PEER, STORED }

    private val channels = mutableListOf<ChannelOutcome>()
    @Volatile private var source: Source = Source.NONE
    @Volatile private var peerRefreshed: Boolean = false
    @Volatile private var stage: String = "not_started"
    @Volatile private var startedAtMs: Long = 0L
    @Volatile private var endedAtMs: Long = 0L

    /** A new attempt begins: everything from the previous one is dropped. */
    @Synchronized
    fun beginAttempt(nowMs: Long) {
        channels.clear()
        source = Source.NONE
        peerRefreshed = false
        stage = "bootstrap"
        startedAtMs = nowMs
        endedAtMs = 0L
    }

    /**
     * Record one channel's result.
     *
     * `reason` must be a CLASS, not a message. Callers pass things like `timeout` or `http_403`; an
     * exception's own text can carry a host or an address and must never reach a screenshot.
     */
    @Synchronized
    fun channel(index: Int, ok: Boolean, reason: String) {
        channels.add(ChannelOutcome(index, ok, reason.take(24)))
        if (ok) snapshotFrom(Source.CHANNEL)
    }

    /**
     * Record where the snapshot this attempt CONNECTED with came from. **First writer wins.**
     *
     * The first live run on a clean device reported `src=peer` while the log showed channel 1 had
     * supplied the settings 1.4 seconds earlier; the mesh's post-connect refresh then stamped PEER
     * over it. Last-writer-wins made the field report whatever happened most recently rather than
     * what the attempt actually used — and "which channel got a first-ever install online" is the
     * one question an in-country report exists to answer.
     *
     * A refresh that lands after the source is decided belongs in [peerRefresh], not here.
     */
    @Synchronized
    fun snapshotFrom(s: Source) {
        if (source == Source.NONE) source = s
    }

    /**
     * A peer served a newer snapshot than this device held. Recorded as its own fact because today
     * it always happens over an already-open tunnel — that is, AFTER the thing it would otherwise
     * be mistaken for. It says the mesh works; it does not say the mesh got us online.
     */
    @Synchronized
    fun peerRefresh() {
        peerRefreshed = true
    }

    /**
     * The furthest stage reached. The whole vocabulary, so a reader of a returned report can decode
     * it without the source: `not_started`, `bootstrap`, `bootstrap_failed`, `two_hop_up`,
     * `engine_up`. Anything added here must also be added to `docs/IN_COUNTRY_TEST_fa.md`, which is
     * what someone actually reads the report against.
     */
    @Synchronized
    fun stage(name: String) {
        stage = name
    }

    /**
     * The attempt has reached a terminal state — stop the clock.
     *
     * Without this the elapsed time counted until whoever opened the report, which on the first live
     * test read `66424ms` for a connection that took twenty-five seconds. A number that grows while
     * you look at it is not a measurement.
     */
    @Synchronized
    fun finished(name: String, nowMs: Long) {
        stage = name
        endedAtMs = nowMs
    }

    /**
     * A compact report for the diagnostics screen. Rendered by the app in Persian; this returns the
     * FACTS, not the words, so the wording stays in the app's string resources where it belongs.
     */
    @Synchronized
    fun snapshot(): Report =
        Report(
            channels = channels.toList(),
            source = source,
            peerRefreshed = peerRefreshed,
            stage = stage,
            elapsedMs = when {
                startedAtMs == 0L -> 0
                endedAtMs != 0L -> endedAtMs - startedAtMs
                else -> System.currentTimeMillis() - startedAtMs
            },
        )

    data class Report(
        val channels: List<ChannelOutcome>,
        val source: Source,
        val peerRefreshed: Boolean,
        val stage: String,
        val elapsedMs: Long,
    ) {
        /**
         * Channels that answered with a usable snapshot — the single most useful line in a report.
         *
         * ZERO-BASED here and ONE-BASED everywhere a person reads it. The first live test rendered
         * index 0 as "Routes that answered: 0", which reads as "none answered" — the exact opposite of
         * the truth, on the one line that matters most. The app's own log has always said
         * "Channel 1", so one-based is also the consistent choice.
         */
        val workingChannels: List<Int> get() = channels.filter { it.ok }.map { it.index }
        /** The same list as a person should see it: one-based. */
        val workingRouteNumbers: List<Int> get() = workingChannels.map { it + 1 }

        /**
         * One line a tester can read aloud over a phone call if screenshots are risky.
         *
         * Deliberately terse and ASCII-safe: it may be retyped by hand at the other end.
         */
        fun oneLine(): String {
            val ok = workingChannels.joinToString(",") { (it + 1).toString() }.ifEmpty { "none" }
            val failed = channels.filter { !it.ok }
                .joinToString(",") { "${it.index + 1}:${it.reason}" }
                .ifEmpty { "-" }
            val refresh = if (peerRefreshed) " peer_refresh=yes" else ""
            return "ok=$ok fail=$failed src=${source.name.lowercase()}$refresh stage=$stage ${elapsedMs}ms"
        }
    }

    /** Test-only reset, so one test's attempt cannot leak into another's report. */
    @Synchronized
    internal fun resetForTest() {
        channels.clear()
        source = Source.NONE
        peerRefreshed = false
        stage = "not_started"
        startedAtMs = 0L
        endedAtMs = 0L
    }
}
