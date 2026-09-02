package zat.manager.vpn.engine.reality

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Verifies the sing-box config generator emits valid JSON with the right
 * structure for both the single-hop direct path and the two-hop blind chain
 * (the pattern validated by the local 3-instance sing-box proof).
 */
class RealitySingBoxConfigTest {

    private fun obj(s: String) = Json.parseToJsonElement(s).jsonObject

    @Test
    fun `single-hop builds valid JSON with one reality outbound and vision flow`() {
        val cfg = RealitySingBoxConfig.build(
            RealityRoute("s.example", 443, "u", "pk", "sid"),
            includePackages = listOf("org.telegram.messenger"),
        )
        val root = obj(cfg) // must parse → valid JSON
        val outs = root["outbounds"]!!.jsonArray
        assertEquals(2, outs.size) // reality-out + direct
        val realityOut = outs[0].jsonObject
        assertEquals("reality-out", realityOut["tag"]!!.jsonPrimitive.content)
        assertEquals("s.example", realityOut["server"]!!.jsonPrimitive.content)
        assertEquals("xtls-rprx-vision", realityOut["flow"]!!.jsonPrimitive.content)
        assertEquals("reality-out", root["route"]!!.jsonObject["final"]!!.jsonPrimitive.content)
        assertTrue(cfg.contains("\"include_package\": [\"org.telegram.messenger\"]"))
    }

    @Test
    fun `two-hop builds a detour chain - inner exit dialed through outer volunteer`() {
        val volunteer = RealityRoute("vol.example", 9002, "uv", "pkv", "sidv", flow = "")
        val exit = RealityRoute("exit.example", 9001, "ue", "pke", "side", flow = "")
        val cfg = RealitySingBoxConfig.buildTwoHop(volunteer, exit, includePackages = emptyList())

        val root = obj(cfg) // must parse → valid JSON
        val outs = root["outbounds"]!!.jsonArray
        assertEquals(3, outs.size) // exit + volunteer + direct

        val exitOut = outs[0].jsonObject
        val volOut = outs[1].jsonObject
        assertEquals("reality-exit", exitOut["tag"]!!.jsonPrimitive.content)
        assertEquals("exit.example", exitOut["server"]!!.jsonPrimitive.content)
        // The inner (exit) hop is dialed THROUGH the outer (volunteer) hop.
        assertEquals("reality-volunteer", exitOut["detour"]!!.jsonPrimitive.content)
        assertEquals("reality-volunteer", volOut["tag"]!!.jsonPrimitive.content)
        assertEquals("vol.example", volOut["server"]!!.jsonPrimitive.content)
        assertNull(volOut["detour"]) // outer hop has no further detour
        // No vision flow in the proven two-hop pattern.
        assertNull(exitOut["flow"])
        assertNull(volOut["flow"])
        // Traffic enters via the inner (exit) outbound.
        assertEquals("reality-exit", root["route"]!!.jsonObject["final"]!!.jsonPrimitive.content)
    }

    @Test
    fun `rendezvous proxy is a SOCKS mixed inbound dialed through one reality hop - no tun`() {
        val entry = RealityRoute("rdv.example", 8446, "ur", "pkr", "sidr", flow = "")
        val cfg = RealitySingBoxConfig.buildRendezvousProxy(entry, socksPort = 18080)
        val root = obj(cfg) // must parse → valid JSON

        // A local mixed (SOCKS+HTTP) inbound on loopback — NOT a tun.
        val ins = root["inbounds"]!!.jsonArray
        assertEquals(1, ins.size)
        val mixed = ins[0].jsonObject
        assertEquals("mixed", mixed["type"]!!.jsonPrimitive.content)
        assertEquals("127.0.0.1", mixed["listen"]!!.jsonPrimitive.content)
        assertEquals(18080, mixed["listen_port"]!!.jsonPrimitive.content.toInt())
        assertFalse(cfg.contains("\"type\": \"tun\"")) // the bootstrap proxy never opens a tun

        // Everything is dialed through the single Reality hop to the entry.
        val outs = root["outbounds"]!!.jsonArray
        assertEquals(2, outs.size) // rendezvous-out + direct
        val realityOut = outs[0].jsonObject
        assertEquals("rendezvous-out", realityOut["tag"]!!.jsonPrimitive.content)
        assertEquals("rdv.example", realityOut["server"]!!.jsonPrimitive.content)
        assertEquals(8446, realityOut["server_port"]!!.jsonPrimitive.content.toInt())
        assertNotNull(realityOut["tls"]!!.jsonObject["reality"]) // the Reality disguise is present
        assertEquals("rendezvous-out", root["route"]!!.jsonObject["final"]!!.jsonPrimitive.content)
    }

    @Test
    fun `shard-read proxy keeps the broker socks and adds one reality tunnel per shard`() {
        val entry = RealityRoute("rdv.example", 8446, "ur", "pkr", "sidr", flow = "")
        val shards = listOf(
            RealitySingBoxConfig.ShardTunnel(RealityRoute("volA.example", 8445, "ua", "pka", "sida", flow = ""), 19001),
            RealitySingBoxConfig.ShardTunnel(RealityRoute("volB.example", 8455, "ub", "pkb", "sidb", flow = ""), 19002),
        )
        val cfg = RealitySingBoxConfig.buildShardReadProxy(entry, entrySocksPort = 18080, shards = shards)
        val root = obj(cfg) // must parse → valid JSON

        // Inbounds: the kept bootstrap SOCKS + one loopback mixed per shard (no tun).
        val ins = root["inbounds"]!!.jsonArray
        assertEquals(3, ins.size)
        assertEquals("rendezvous-in", ins[0].jsonObject["tag"]!!.jsonPrimitive.content)
        assertEquals(18080, ins[0].jsonObject["listen_port"]!!.jsonPrimitive.content.toInt())
        assertEquals(19001, ins[1].jsonObject["listen_port"]!!.jsonPrimitive.content.toInt())
        assertEquals(19002, ins[2].jsonObject["listen_port"]!!.jsonPrimitive.content.toInt())
        assertTrue(ins.all { it.jsonObject["type"]!!.jsonPrimitive.content == "mixed" })
        assertFalse(cfg.contains("\"type\": \"tun\""))

        // Outbounds: the entry + one Reality tunnel per shard + direct.
        val outs = root["outbounds"]!!.jsonArray
        assertEquals(4, outs.size)
        assertEquals("rendezvous-out", outs[0].jsonObject["tag"]!!.jsonPrimitive.content)
        assertEquals("shard-out-0", outs[1].jsonObject["tag"]!!.jsonPrimitive.content)
        assertEquals("volA.example", outs[1].jsonObject["server"]!!.jsonPrimitive.content)
        assertEquals("volB.example", outs[2].jsonObject["server"]!!.jsonPrimitive.content)

        // Route: each shard SOCKS pins to its own shard outbound; the broker stays the default,
        // so the VOPRF keeps flowing to the entry while shard reads ride their own tunnels.
        val rules = root["route"]!!.jsonObject["rules"]!!.jsonArray
        assertEquals(2, rules.size)
        assertEquals("shard-in-0", rules[0].jsonObject["inbound"]!!.jsonArray[0].jsonPrimitive.content)
        assertEquals("shard-out-0", rules[0].jsonObject["outbound"]!!.jsonPrimitive.content)
        assertEquals("rendezvous-out", root["route"]!!.jsonObject["final"]!!.jsonPrimitive.content)
    }
}
