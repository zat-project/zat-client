package zat.manager.vpn

import kotlinx.serialization.Serializable
import java.security.MessageDigest

/**
 * A server-issued PoW challenge (GATE_AND_TRAITOR_TRACING_v0.1 §A.2). Shape mirrors
 * `PowChallenge` in `broker/src/rendezvous/pow.ts` and `powChallengeObjectSchema`; it is
 * echoed back VERBATIM (alongside the solution) on /match.
 */
@Serializable
data class PowChallenge(
    val nonce: String,
    val difficulty: Int,
    val tokenId: String,
    val exp: Long,
    val mac: String,
)

/**
 * Client-side proof-of-work for the rendezvous GATE — a faithful port of the broker's
 * `pow.ts` so a solution the broker issued a challenge for verifies there.
 *
 * The scheme is a token-bound, time-boxed hashcash over a FAST hash (SHA-256): find a
 * `solution` whose `SHA256(nonce|difficulty|tokenId|exp|solution)` has at least
 * `difficulty` leading ZERO BITS. The reference solver enumerates `i.toString(36)` for
 * i = 0,1,2,…; we mirror that exactly so the search space and encoding match.
 */
object RendezvousPow {

    /** The bytes hashed, minus the trailing solution — mirrors pow.ts `challengeBody | `. */
    private fun prefix(c: PowChallenge): String =
        "${c.nonce}|${c.difficulty}|${c.tokenId}|${c.exp}|"

    /** Count leading zero BITS of [hash] (mirrors pow.ts `leadingZeroBits`). */
    fun leadingZeroBits(hash: ByteArray): Int {
        var bits = 0
        for (b in hash) {
            val v = b.toInt() and 0xFF
            if (v == 0) {
                bits += 8
                continue
            }
            // numberOfLeadingZeros of a 0..255 value, minus its 24 high zero bits.
            bits += Integer.numberOfLeadingZeros(v) - 24
            break
        }
        return bits
    }

    /** True iff `SHA256(nonce|difficulty|tokenId|exp|solution)` has ≥ `difficulty` zero bits. */
    fun verifySolution(c: PowChallenge, solution: String): Boolean {
        if (solution.isEmpty()) return false
        val h = MessageDigest.getInstance("SHA-256")
            .digest((prefix(c) + solution).toByteArray(Charsets.UTF_8))
        return leadingZeroBits(h) >= c.difficulty
    }

    /**
     * Find a solution at or before [deadlineMs] (wall clock), or null if it could not be
     * solved in time. Honest clients run this; at the base difficulty (18 bits) it is sub-
     * second. The clock is only checked every 16k iterations so the hash loop stays tight.
     */
    fun solve(c: PowChallenge, deadlineMs: Long): String? {
        if (c.difficulty <= 0) return "0"
        val md = MessageDigest.getInstance("SHA-256")
        val pfx = prefix(c)
        var i = 0L
        while (true) {
            val solution = i.toString(36)
            md.reset()
            val h = md.digest((pfx + solution).toByteArray(Charsets.UTF_8))
            if (leadingZeroBits(h) >= c.difficulty) return solution
            i++
            // Check the clock periodically (not every iter); the caller logs the give-up.
            if ((i and 0x3FFF) == 0L && System.currentTimeMillis() >= deadlineMs) return null
        }
    }
}
