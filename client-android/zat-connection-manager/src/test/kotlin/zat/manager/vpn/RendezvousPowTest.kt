package zat.manager.vpn

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Verifies the client PoW solver mirrors broker/src/rendezvous/pow.ts: leading-zero-bit
 * counting, and that a solved challenge verifies under the same hash (so a solution the
 * broker issued a challenge for will verify there).
 */
class RendezvousPowTest {

    @Test
    fun `leadingZeroBits counts bits the way pow_ts does`() {
        assertEquals(0, RendezvousPow.leadingZeroBits(byteArrayOf(0xFF.toByte())))
        assertEquals(4, RendezvousPow.leadingZeroBits(byteArrayOf(0x0F)))
        assertEquals(8, RendezvousPow.leadingZeroBits(byteArrayOf(0, 0xFF.toByte())))
        assertEquals(16, RendezvousPow.leadingZeroBits(byteArrayOf(0, 0, 0x80.toByte())))
        assertEquals(7, RendezvousPow.leadingZeroBits(byteArrayOf(0x01)))
    }

    @Test
    fun `solve finds a solution that verifies (round-trip)`() {
        val c = PowChallenge(nonce = "abc123", difficulty = 12, tokenId = "tok", exp = Long.MAX_VALUE, mac = "x")
        val solution = RendezvousPow.solve(c, System.currentTimeMillis() + 10_000)
        assertNotNull(solution, "a 12-bit challenge must be solvable quickly")
        assertTrue(RendezvousPow.verifySolution(c, solution!!), "the solver's output must verify")
    }

    @Test
    fun `solve enumerates base-36 counters from zero (matches the reference solver)`() {
        // difficulty 0 ⇒ any non-empty solution verifies; the reference solver's first
        // candidate is i=0 → "0".
        val c = PowChallenge(nonce = "n", difficulty = 0, tokenId = "t", exp = Long.MAX_VALUE, mac = "m")
        assertEquals("0", RendezvousPow.solve(c, System.currentTimeMillis() + 1_000))
    }

    @Test
    fun `solve respects the deadline and gives up`() {
        // 64 leading zero bits is intractable; with a 0 ms budget solve must bail out null.
        val c = PowChallenge(nonce = "n", difficulty = 64, tokenId = "t", exp = Long.MAX_VALUE, mac = "m")
        assertEquals(null, RendezvousPow.solve(c, System.currentTimeMillis()))
    }
}
