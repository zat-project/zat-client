package zat.manager.vpn

/**
 * How much did THIS connection need us?
 *
 * ## Why this exists
 *
 * The project's stated destination is that the broker can be switched off and the network keeps
 * working. Everything is built toward that, and until now nothing measured it. R19 is what that costs:
 * mesh discovery had a 0.78% chance of finding a volunteer, every miss fell through to the broker's
 * `/match` and CONNECTED, and so the path built to remove the broker produced nothing for months while
 * every surface stayed green. A working fallback is precisely what makes a dead primary invisible.
 *
 * So the dissolution gets a number, and the number is allowed to be embarrassing. Each time a
 * connection reaches for the broker instead of a volunteer or the signed snapshot, that is one point
 * of reliance, recorded with WHY. Zero is the destination; anything else is a list of things still to
 * dissolve, in priority order, measured rather than assumed.
 *
 * It is also a regression alarm of the only kind that would have caught R19: if a decentralized path
 * quietly dies and its fallback covers, the connection still succeeds — but this count jumps, on the
 * very first attempt, instead of staying silent for months.
 *
 * ## What is deliberately NOT here
 *
 * Counts and reason CLASSES, never a URL, an address, or anything about the user — the same rule as
 * [RunDiagnostics], because this number is meant to be reportable by a tester in a censored country.
 * In-memory, reset per attempt: a history is a file on a device that may be inspected at a border.
 */
object BrokerReliance {

    /**
     * Why a connection had to reach the broker. Each is a distinct piece of the endgame, so the
     * count is not just a score but a work list.
     */
    enum class Reason {
        /** The signed snapshot carried no `mesh_entry`, so parameters came from the broker. */
        PARAMS,

        /** No shard seeds in the snapshot, so the shard list came from the broker. */
        SHARD_SEEDS,

        /** No committee reachable, so the oblivious evaluation went to the broker as issuer. */
        BLIND_EVAL,

        /** A bucket no volunteer shard served, read from the broker's mirror store instead. */
        BUCKET_READ,

        /** The revoke-digest came from the broker rather than a shard. */
        TRUST_DIGEST,

        /** The whole mesh found nothing and the connection fell back to the broker's `/match`. */
        MATCH,
    }

    private val counts = LinkedHashMap<Reason, Int>()

    /** A new attempt begins; the previous one's tally is dropped. */
    @Synchronized
    fun beginAttempt() {
        counts.clear()
    }

    /** Record one reach for the broker. */
    @Synchronized
    fun note(reason: Reason) {
        counts[reason] = (counts[reason] ?: 0) + 1
    }

    /** Total reaches this attempt. Zero means the broker could have been switched off. */
    @Synchronized
    fun total(): Int = counts.values.sum()

    @Synchronized
    fun breakdown(): Map<Reason, Int> = LinkedHashMap(counts)

    /**
     * One line for the log and the tester's report.
     *
     * Says the good case out loud rather than staying silent. A run that needed nothing from us is
     * the single most important event this project can observe, and a silent success is exactly how
     * R19 hid — so zero gets a sentence, not an absence.
     */
    @Synchronized
    fun oneLine(): String =
        if (counts.isEmpty()) {
            "broker=0 (this connection did not need us)"
        } else {
            "broker=${total()} " +
                counts.entries.joinToString(",") { "${it.key.name.lowercase()}:${it.value}" }
        }
}
