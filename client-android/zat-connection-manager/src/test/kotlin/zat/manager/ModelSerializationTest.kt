package zat.manager

import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import zat.manager.models.*

/**
 * ModelSerializationTest — verifies that the client data models correctly
 * parse the Broker's signed bootstrap snapshot JSON.
 *
 * The expected JSON structure is the exact shape produced by
 * BootstrapService.generateSnapshot() in the broker.
 */
class ModelSerializationTest {

    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = false
    }

    @Test
    fun `parses a BootstrapSnapshot JSON correctly`() {
        // This JSON matches the exact shape produced by BootstrapService.generateSnapshot()
        // in the broker. speed and uptime are BigInt.toString() strings on the server side.
        val raw = """
            {
              "schema_version": 1,
              "generated_at": "2026-06-12T06:14:45.000Z",
              "ttl_seconds": 600,
              "server_count": 1,
              "servers": [
                {
                  "id": "vpngate-server-001",
                  "host": "vpn.example.jp",
                  "ip": "203.0.113.50",
                  "score": 542819,
                  "ping": 18,
                  "speed": "8547120",
                  "uptime": "2345678",
                  "sessions": 12,
                  "country_short": "JP",
                  "country_long": "Japan",
                  "protocol": "udp",
                  "port": 1194,
                  "quality_tier": "good",
                  "quality_score": 0.8765,
                  "ca_pem": "-----BEGIN CERTIFICATE-----MIICtestCA-----END CERTIFICATE-----"
                }
              ],
              "rotation_policy": {
                "protocol_fallback_order": ["sstp"],
                "connection_timeout_seconds": 10,
                "sticky_on_success": true,
                "avoid_rotation_during_upload": true,
                "avoid_rotation_during_call": true
              }
            }
        """.trimIndent()

        val snapshot: BootstrapSnapshot = json.decodeFromString(raw)

        // Top-level fields
        assertEquals(1, snapshot.schemaVersion)
        assertEquals("2026-06-12T06:14:45.000Z", snapshot.generatedAt)
        assertEquals(600, snapshot.ttlSeconds)
        assertEquals(1, snapshot.serverCount)
        assertEquals(1, snapshot.servers.size)

        // Server fields — all match VpnRoute model
        val server = snapshot.servers[0]
        assertEquals("vpngate-server-001", server.id)
        assertEquals("vpn.example.jp", server.host)
        assertEquals("203.0.113.50", server.ip)
        assertEquals(542819, server.score)
        assertEquals(18, server.ping)
        assertEquals("8547120", server.speed)        // String (BigInt.toString() from broker)
        assertEquals("2345678", server.uptime)       // String (BigInt.toString() from broker)
        assertEquals(12, server.sessions)
        assertEquals("JP", server.countryShort)
        assertEquals("Japan", server.countryLong)
        assertEquals("udp", server.protocol)
        assertEquals(1194, server.port)
        assertEquals("good", server.qualityTier)
        assertEquals(0.8765, server.qualityScore, 1e-9)
        assertEquals(
            "-----BEGIN CERTIFICATE-----MIICtestCA-----END CERTIFICATE-----",
            server.caPem,
        )

        // Rotation policy — SSTP-only
        val policy = snapshot.rotationPolicy
        assertEquals(listOf("sstp"), policy.protocolFallbackOrder)
        assertEquals(10, policy.connectionTimeoutSeconds)
        assertTrue(policy.stickyOnSuccess)
        assertTrue(policy.avoidRotationDuringUpload)
        assertTrue(policy.avoidRotationDuringCall)
    }

    @Test
    fun `ignores unknown fields without throwing`() {
        // Forward-compatibility: a snapshot with extra fields must still parse.
        val raw = """
            {
              "schema_version": 1,
              "generated_at": "2026-06-05T00:00:00Z",
              "ttl_seconds": 600,
              "server_count": 0,
              "servers": [],
              "rotation_policy": {
                "protocol_fallback_order": ["sstp"],
                "connection_timeout_seconds": 10,
                "sticky_on_success": true,
                "avoid_rotation_during_upload": false,
                "avoid_rotation_during_call": false
              },
              "future_unknown_field": "should_be_ignored"
            }
        """.trimIndent()

        val snapshot: BootstrapSnapshot = json.decodeFromString(raw)
        assertEquals(1, snapshot.schemaVersion)
        assertTrue(snapshot.servers.isEmpty())
    }

    @Test
    fun `parses reality_servers, flow, and introducer_url (Model B fields)`() {
        val raw = """
            {
              "schema_version": 1,
              "generated_at": "2026-06-22T00:00:00Z",
              "ttl_seconds": 600,
              "server_count": 0,
              "servers": [],
              "reality_servers": [
                {
                  "id": "exit-1", "address": "exit.example", "port": 9001, "uuid": "u",
                  "public_key": "pk", "short_id": "sid", "server_name": "www.microsoft.com",
                  "fingerprint": "chrome", "flow": "", "country_short": "FI",
                  "country_long": "Finland", "quality_score": 0.9
                }
              ],
              "introducer_url": "https://rdv.example",
              "rotation_policy": {
                "protocol_fallback_order": ["sstp"],
                "connection_timeout_seconds": 10,
                "sticky_on_success": true,
                "avoid_rotation_during_upload": true,
                "avoid_rotation_during_call": true
              }
            }
        """.trimIndent()

        val snapshot: BootstrapSnapshot = json.decodeFromString(raw)
        assertEquals("https://rdv.example", snapshot.introducerUrl)
        assertEquals(1, snapshot.realityServers.size)
        val exit = snapshot.realityServers[0]
        assertEquals("exit.example", exit.address)
        assertEquals(9001, exit.port)
        assertEquals("", exit.flow) // a two-hop exit declares no-flow
    }

    @Test
    fun `reality_server flow defaults to vision and introducer_url to empty`() {
        val s: RealityServer = json.decodeFromString(
            """{ "id":"s","address":"a","port":443,"uuid":"u","public_key":"pk" }""",
        )
        assertEquals("xtls-rprx-vision", s.flow)
    }

    @Test
    fun `parses rendezvous_entries (reach-over-Reality Stage 1)`() {
        val raw = """
            {
              "schema_version": 1,
              "generated_at": "2026-06-28T00:00:00Z",
              "ttl_seconds": 600,
              "server_count": 0,
              "servers": [],
              "rendezvous_entries": [
                {
                  "id": "rdv-box-1", "address": "203.0.113.50", "port": 8446, "uuid": "u",
                  "public_key": "pk", "short_id": "sid", "server_name": "www.cloudflare.com",
                  "fingerprint": "chrome", "flow": ""
                }
              ],
              "rotation_policy": {
                "protocol_fallback_order": ["sstp"],
                "connection_timeout_seconds": 10,
                "sticky_on_success": true,
                "avoid_rotation_during_upload": true,
                "avoid_rotation_during_call": true
              }
            }
        """.trimIndent()

        val snapshot: BootstrapSnapshot = json.decodeFromString(raw)
        assertEquals(1, snapshot.rendezvousEntries.size)
        val entry = snapshot.rendezvousEntries[0]
        assertEquals("203.0.113.50", entry.address)
        assertEquals(8446, entry.port)
        assertEquals("", entry.flow) // the rendezvous entry is plain vless+reality (no vision)
    }

    @Test
    fun `rendezvous_entries defaults to empty when absent (older snapshot, signature stays valid)`() {
        val raw = """
            {
              "schema_version": 1, "generated_at": "2026-06-28T00:00:00Z", "ttl_seconds": 600,
              "server_count": 0, "servers": [],
              "rotation_policy": {
                "protocol_fallback_order": ["sstp"], "connection_timeout_seconds": 10,
                "sticky_on_success": true, "avoid_rotation_during_upload": true,
                "avoid_rotation_during_call": true
              }
            }
        """.trimIndent()
        val snapshot: BootstrapSnapshot = json.decodeFromString(raw)
        assertTrue(snapshot.rendezvousEntries.isEmpty())
    }
}
