package zat.manager.vpn

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Verifies RendezvousClient.parseHandle decodes the introducer's match response
 * (the exact camelCase shape emitted by RendezvousService.MatchResult).
 */
class RendezvousClientTest {

    @Test
    fun `parses a single-use volunteer handle from the introducer`() {
        val raw = """
            {
              "handleId": "h-123",
              "expiresAt": 1750000000000,
              "volunteer": {
                "host": "203.0.113.7",
                "port": 443,
                "reality": {
                  "uuid": "u",
                  "publicKey": "pk",
                  "shortId": "sid",
                  "serverName": "www.microsoft.com",
                  "fingerprint": "chrome"
                },
                "tier": "tier1a"
              }
            }
        """.trimIndent()

        val h = RendezvousClient.parseHandle(raw)
        assertNotNull(h)
        assertEquals("h-123", h!!.handleId)
        assertEquals(1750000000000L, h.expiresAt)
        assertEquals("203.0.113.7", h.volunteer.host)
        assertEquals(443, h.volunteer.port)
        assertEquals("tier1a", h.volunteer.tier)
        assertEquals("pk", h.volunteer.reality.publicKey)
        assertEquals("www.microsoft.com", h.volunteer.reality.serverName)
    }

    @Test
    fun `returns null on malformed or empty input`() {
        assertNull(RendezvousClient.parseHandle("not json"))
        assertNull(RendezvousClient.parseHandle(""))
        assertNull(RendezvousClient.parseHandle("{}"))
    }

    // --- Invite-graph I1 (P3.1): the tier credential is PRESENTED on /pow-challenge + /match iff set. ---

    @Test
    fun `pow-challenge body carries the credential only when present`() {
        assertEquals("""{"token":"tok"}""", RendezvousClient.powChallengeBody("tok", null))
        assertEquals(
            """{"token":"tok","credential":"CRED.1"}""",
            RendezvousClient.powChallengeBody("tok", "CRED.1"),
        )
    }

    @Test
    fun `match body carries the credential only when present`() {
        val without = RendezvousClient.matchBody("tok", "IR", null, null)
        assertFalse(without.contains("credential"), "no credential field when none is presented")
        assertTrue(without.contains(""""token":"tok""""))
        assertTrue(without.contains(""""country":"IR""""))

        val with = RendezvousClient.matchBody("tok", "IR", null, "CRED.2")
        assertTrue(with.contains(""""credential":"CRED.2""""), "presents the tier credential")
    }

    @Test
    fun `match body echoes the PoW challenge and solution when present`() {
        val pow = PowChallenge(nonce = "n", difficulty = 12, tokenId = "tid", exp = 1750000000000L, mac = "m") to "sol"
        val body = RendezvousClient.matchBody("tok", "IR", pow, "CRED.3")
        assertTrue(body.contains(""""powSolution":"sol""""))
        assertTrue(body.contains(""""difficulty":12"""))
        assertTrue(body.contains(""""credential":"CRED.3""""))
    }

    // --- Invite-graph I2 (P3.1b): minting a child invitation from a parent credential. ---

    @Test
    fun `invite body wraps the parent credential`() {
        assertEquals("""{"credential":"PARENT.1"}""", RendezvousClient.inviteBody("PARENT.1"))
    }

    @Test
    fun `parses the minted child credential from the invite response`() {
        assertEquals("CHILD.9", RendezvousClient.parseMintedCredential("""{"credential":"CHILD.9"}"""))
        assertNull(RendezvousClient.parseMintedCredential(""))
        assertNull(RendezvousClient.parseMintedCredential("not json"))
        assertNull(RendezvousClient.parseMintedCredential("{}"))
    }
}
