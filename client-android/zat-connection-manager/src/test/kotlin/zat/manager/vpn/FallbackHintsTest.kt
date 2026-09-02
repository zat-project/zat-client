package zat.manager.vpn

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import zat.manager.models.VpnRoute

/**
 * #31 — the third-party SSTP list leaves the signed snapshot.
 *
 * It was the one field a committee member could never re-derive: two members scraping VPN Gate
 * seconds apart legitimately disagree. Inside the signed snapshot, the signature said "the committee
 * vouches for these servers" — a claim nobody had checked, and the permanent exception to R12's rule
 * that a member signs only what it can establish.
 *
 * So it is fetched separately and UNSIGNED now, and merged here. The safety argument is not the
 * transport but the destination: these are public servers run by strangers, carrying no ZAT secret
 * and no claim from us, so a hostile one is the exposure a user had before ZAT existed. Everything
 * that IS ZAT stays in the signed snapshot.
 */
class FallbackHintsTest {

    private fun route(host: String, port: Int) = VpnRoute(
        id = "$host-$port",
        host = host,
        ip = "192.0.2.4",
        score = 0,
        speed = "0",
        countryShort = "JP",
        countryLong = "Japan",
        protocol = "sstp",
        port = port,
    )

    private fun resolved(vararg routes: VpnRoute) =
        ResolvedBootstrap(sstpRoutes = routes.toList(), realityServers = emptyList())

    private fun hints(vararg hosts: Pair<String, Int>): String {
        val items = hosts.joinToString(",") { (h, p) ->
            """{"id":"$h-$p","host":"$h","ip":"192.0.2.4","score":0,"speed":"0","country_short":"JP","country_long":"Japan","protocol":"sstp","port":$p}"""
        }
        return """{"doc":"zat.fallback-servers.v1","signed":false,"count":${hosts.size},"servers":[$items]}"""
    }

    @Test
    fun `unsigned hints are merged into the resolved bootstrap`() {
        val out = BootstrapResolver.withFallbackHints(resolved(), hints("a" to 443, "b" to 992))
        assertEquals(listOf("a", "b"), out.sstpRoutes.map { it.host })
    }

    /**
     * A snapshot published before the split still carries its own `servers`. Both must work at once
     * during the overlap — dropping either would be a self-inflicted outage of the fallback transport,
     * and the signed copy has to come FIRST because it is the one the committee actually signed.
     */
    @Test
    fun `the snapshot's own signed list outranks a hint and duplicates collapse`() {
        val out = BootstrapResolver.withFallbackHints(
            resolved(route("a", 443)),
            hints("a" to 443, "c" to 443),
        )
        assertEquals(listOf("a", "c"), out.sstpRoutes.map { it.host })
        assertEquals(2, out.sstpRoutes.size, "the same host:port must not be dialled twice")
    }

    /**
     * Every failure shape degrades to "no hints" rather than to an exception. A fallback transport
     * that cannot be reached is a far smaller problem than one that is trusted because it answered —
     * and an unreadable body is exactly what a censor's interception page looks like.
     */
    @Test
    fun `an unreachable or malformed hint list changes nothing`() {
        val base = resolved(route("a", 443))
        for (body in listOf(null, "", "   ", "not json", "{}", """{"servers":"nope"}""")) {
            val out = BootstrapResolver.withFallbackHints(base, body)
            assertEquals(base.sstpRoutes, out.sstpRoutes, "body=$body must leave the routes untouched")
        }
    }

    /** One malformed entry must not discard the list — the same rule the snapshot parser follows. */
    @Test
    fun `one bad entry does not discard the good ones`() {
        val body = """{"servers":[{"nope":true},{"id":"g","host":"g","ip":"192.0.2.4","score":0,"speed":"0","country_short":"JP","country_long":"Japan","protocol":"sstp","port":443}]}"""
        val out = BootstrapResolver.withFallbackHints(resolved(), body)
        assertEquals(listOf("g"), out.sstpRoutes.map { it.host })
    }

    /**
     * The signed half must be untouched by any of this. If a hint could reach `realityServers` or
     * `rendezvousEntries`, the split would have moved the trust boundary instead of clarifying it.
     */
    @Test
    fun `hints can never reach the signed fields`() {
        val body = """{"servers":[],"reality_servers":[{"id":"evil"}],"rendezvous_entries":[{"id":"evil"}]}"""
        val out = BootstrapResolver.withFallbackHints(resolved(), body)
        assertTrue(out.realityServers.isEmpty(), "an unsigned list must not supply Reality exits")
        assertTrue(out.rendezvousEntries.isEmpty(), "an unsigned list must not supply rendezvous entries")
    }
}
