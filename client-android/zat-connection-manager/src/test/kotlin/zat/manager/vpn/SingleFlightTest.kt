package zat.manager.vpn

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * #19 — only ONE bootstrap resolution runs at a time.
 *
 * A live capture showed two full resolutions for what looked like a single tap, and the note left
 * behind said the function had two callers and neither could be the source. It had SEVEN, five of
 * them passing no trigger at all — so the investigation eliminated the wrong candidate set and then
 * trusted the elimination. The pair is almost certainly `ApplicationLoader`'s launch auto-start
 * racing a user tap.
 *
 * The cost is not the wasted work. Each resolution sweeps all six bootstrap channels, so two at once
 * DOUBLE the network fingerprint at exactly the moment a censored user is most exposed, and both
 * threads then race to start the VPN.
 *
 * These test the guard's own contract rather than `VpnManager` (which needs a `Context` and real
 * sockets): admit exactly one, and — the half that actually matters — always release.
 */
class SingleFlightTest {

    /** The guard as `fetchRouteAndStartVpn` applies it: claim, run, release in a `finally`. */
    private class Guard {
        private val inFlight = AtomicBoolean(false)
        val admitted = AtomicInteger(0)
        val rejected = AtomicInteger(0)

        fun attempt(body: () -> Unit) {
            if (!inFlight.compareAndSet(false, true)) {
                rejected.incrementAndGet()
                return
            }
            admitted.incrementAndGet()
            try {
                body()
            } finally {
                inFlight.set(false)
            }
        }

        fun isIdle(): Boolean = !inFlight.get()
    }

    @Test
    fun `only one of many simultaneous connect requests resolves`() {
        val guard = Guard()
        val holdInside = CountDownLatch(1)
        val allArrived = CountDownLatch(8)

        val threads = (1..8).map {
            Thread {
                guard.attempt {
                    allArrived.countDown()
                    // Hold the claim so every other thread is guaranteed to meet it taken — without
                    // this the test could pass by luck, admitting them one after another.
                    holdInside.await(5, TimeUnit.SECONDS)
                }
                allArrived.countDown()
            }
        }
        threads.forEach { it.start() }
        assertTrue(allArrived.await(5, TimeUnit.SECONDS), "all callers must have made their attempt")
        holdInside.countDown()
        threads.forEach { it.join(5_000) }

        assertEquals(1, guard.admitted.get(), "exactly one resolution may run")
        assertEquals(7, guard.rejected.get(), "every other caller is turned away, not queued")
    }

    /**
     * The half that would hurt most if it were wrong. A guard that leaks on failure turns ONE bad
     * bootstrap into a client that can never try again — trading a duplicate resolve for a permanent
     * outage, which is much the worse of the two. So the release lives in a `finally`.
     */
    @Test
    fun `a failed resolution still releases the guard`() {
        val guard = Guard()
        repeat(3) {
            runCatching { guard.attempt { throw IllegalStateException("channels all blocked") } }
            assertTrue(guard.isIdle(), "the guard must be free again after a failure")
        }
        assertEquals(3, guard.admitted.get(), "each retry after a failure must be admitted")
        assertEquals(0, guard.rejected.get())
    }

    /** Sequential connects are not duplicates and must all be admitted. */
    @Test
    fun `connects that do not overlap are all admitted`() {
        val guard = Guard()
        repeat(4) { guard.attempt { } }
        assertEquals(4, guard.admitted.get())
        assertEquals(0, guard.rejected.get())
    }
}
