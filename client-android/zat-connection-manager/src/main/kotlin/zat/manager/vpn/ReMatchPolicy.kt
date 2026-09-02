package zat.manager.vpn

/**
 * Pure policy for the two-hop auto-re-match supervisor — no Android dependencies,
 * so it is JVM unit-testable (the connectivity probing + engine lifecycle that use
 * it live in [ZatVpnService]).
 *
 * A blind two-hop tunnel rides a volunteer bridge from the churning pool (Layer 2).
 * When that volunteer goes away (it paused on its schedule / hit its volume cap /
 * went offline — all common with the M3 controls), sing-box keeps retrying the dead
 * outbound and the tunnel wedges. This policy decides, from two consecutive-failure
 * counters, WHEN to declare the volunteer dead and re-match, and when to give up the
 * blind two-hop and fall back to single-hop so the user is never stuck offline.
 */
class ReMatchPolicy(
    /** Consecutive failed liveness probes before the current volunteer is "dead"
     *  (one miss can be a transient blip; a run of them means it is gone). */
    val maxProbeFailures: Int = 3,
    /** Consecutive failed re-match attempts before we fall back to single-hop. */
    val maxRematchAttempts: Int = 5,
    private val baseBackoffMs: Long = 1_000,
    private val maxBackoffMs: Long = 15_000,
) {
    /** The current volunteer is dead once this many probes have failed in a row. */
    fun isDead(consecutiveProbeFailures: Int): Boolean =
        consecutiveProbeFailures >= maxProbeFailures

    /** Give up re-matching (degrade to single-hop) after this many failed attempts. */
    fun shouldFallBack(consecutiveRematchFailures: Int): Boolean =
        consecutiveRematchFailures >= maxRematchAttempts

    /**
     * Backoff before the [attempt]-th re-match (1-based): the first attempt is
     * immediate, then exponential (base, 2·base, 4·base, …) capped at [maxBackoffMs]
     * so a sustained introducer outage doesn't busy-loop the network.
     */
    fun backoffMs(attempt: Int): Long {
        if (attempt <= 1) return 0L
        val shift = (attempt - 2).coerceIn(0, 20)
        return (baseBackoffMs shl shift).coerceAtMost(maxBackoffMs)
    }
}
