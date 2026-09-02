package zat.manager.vpn

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ReMatchPolicyTest {

    private val policy = ReMatchPolicy()

    @Test
    fun `volunteer is dead only after the configured run of failed probes`() {
        assertFalse(policy.isDead(0))
        assertFalse(policy.isDead(2))
        assertTrue(policy.isDead(3))
        assertTrue(policy.isDead(4))
    }

    @Test
    fun `falls back to single-hop only after the attempt budget is spent`() {
        assertFalse(policy.shouldFallBack(4))
        assertTrue(policy.shouldFallBack(5))
        assertTrue(policy.shouldFallBack(6))
    }

    @Test
    fun `backoff is immediate first, then exponential, then capped`() {
        assertEquals(0L, policy.backoffMs(1)) // first re-match is immediate
        assertEquals(1_000L, policy.backoffMs(2))
        assertEquals(2_000L, policy.backoffMs(3))
        assertEquals(4_000L, policy.backoffMs(4))
        assertEquals(8_000L, policy.backoffMs(5))
        assertEquals(15_000L, policy.backoffMs(20)) // capped at maxBackoffMs
    }
}
