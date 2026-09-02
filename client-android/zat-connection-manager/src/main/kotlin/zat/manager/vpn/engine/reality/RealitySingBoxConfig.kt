package zat.manager.vpn.engine.reality

/**
 * One ZAT entry point reachable over VLESS + Reality (the anti-DPI transport).
 *
 * [serverName] is the SNI the client presents *and* the real site Reality steals
 * its TLS handshake from — an active prober sees that legitimate site, so the
 * server is indistinguishable from a normal web host. [realityPublicKey] pairs
 * with the server's private key; [shortId] must match one the server allows.
 *
 * [flow] is the XTLS flow: `xtls-rprx-vision` for a single direct hop (the
 * validated default), or empty for the two-hop blind chain, whose mechanics were
 * validated end-to-end with plain vless+reality (vision-in-vision is a later
 * optimization to test).
 */
data class RealityRoute(
    val serverAddress: String,
    val serverPort: Int,
    val uuid: String,
    val realityPublicKey: String,
    val shortId: String,
    val serverName: String = "www.cloudflare.com",
    val fingerprint: String = "chrome",
    val flow: String = "xtls-rprx-vision",
    /**
     * The matched volunteer's broker id, carried so the data-path supervisor can POST the
     * /report Trace-1 signal for it. Empty for a dedicated exit/entry (nothing to report).
     */
    val volunteerId: String = "",
    /**
     * R5: the single-use handle this route was matched with. The broker's trace counters are
     * HANDLE-GATED — a report only counts if it proves it came from a real match on that volunteer —
     * so the supervisor must carry it alongside [volunteerId]. Empty for a dedicated exit/entry.
     */
    val handleId: String = "",
)

/**
 * A two-hop BLIND selection (Model B): the client dials the [exit] (inner Reality)
 * THROUGH the [volunteer] (outer Reality). See [RealitySingBoxConfig.buildTwoHop].
 */
data class TwoHopRoute(
    val volunteer: RealityRoute,
    val exit: RealityRoute,
)

/**
 * Builds the sing-box JSON config that libbox runs for an app-scoped VLESS/Reality
 * tunnel.
 *
 * The `tun` inbound makes sing-box call back into [SingBoxPlatformInterface.openTun]
 * with [io.nekohasekai.libbox.TunOptions] derived from here (address, MTU, the
 * per-app include list); we turn those into a `VpnService.Builder`. `gvisor` is the
 * userspace network stack (no root needed). `route.auto_detect_interface` makes
 * sing-box protect its own outbound sockets via
 * [SingBoxPlatformInterface.autoDetectInterfaceControl], so the Reality connection
 * does not loop back into the tun.
 *
 * For ZAT the tunnel is scoped to Telegram via [includePackages]; an empty list
 * tunnels everything (the future full-device-VPN mode).
 */
object RealitySingBoxConfig {

    /**
     * Single-hop: client → one Reality server (direct egress). The validated
     * Stage-2 path used for a dedicated Reality entry from the signed snapshot.
     */
    fun build(
        route: RealityRoute,
        includePackages: List<String>,
        mtu: Int = 1400,
        logLevel: String = "info",
        logOutput: String? = null,
    ): String = assemble(
        outbounds = listOf(outbound(route, tag = "reality-out", detour = null)),
        finalTag = "reality-out",
        includePackages = includePackages,
        mtu = mtu,
        logLevel = logLevel,
        logOutput = logOutput,
    )

    /**
     * Two-hop BLIND Model-B chain (RENDEZVOUS_DESIGN_v0.1 §6): the client dials the
     * [exit] (inner Reality) THROUGH the [volunteer] (outer Reality) via sing-box
     * `detour`. The volunteer relays opaque ciphertext to our exit and never sees
     * the destination; the exit is the E2E endpoint. Validated end-to-end with a
     * local 3-instance sing-box proof (egress matched; the volunteer saw only the
     * exit, never the real destination; non-exit destinations were rejected).
     */
    fun buildTwoHop(
        volunteer: RealityRoute,
        exit: RealityRoute,
        includePackages: List<String>,
        mtu: Int = 1400,
        logLevel: String = "info",
        logOutput: String? = null,
    ): String = assemble(
        // The inner outbound (to the exit) is dialed THROUGH the outer (to the
        // volunteer) via `detour` — exactly the proven config pattern.
        outbounds = listOf(
            outbound(exit, tag = "reality-exit", detour = "reality-volunteer"),
            outbound(volunteer, tag = "reality-volunteer", detour = null),
        ),
        finalTag = "reality-exit",
        includePackages = includePackages,
        mtu = mtu,
        logLevel = logLevel,
        logOutput = logOutput,
    )

    /**
     * Bootstrap RENDEZVOUS proxy (MESH_RENDEZVOUS_v0.1 Stage 1 — "reach-over-Reality"):
     * a LOCAL SOCKS+HTTP proxy (a `mixed` inbound on 127.0.0.1:[socksPort]) whose every
     * connection is dialed THROUGH a single Reality hop to a rendezvous [entry].
     *
     * The client routes ONLY its control traffic (the match / snapshot / report) through
     * this proxy (OkHttp `Proxy.Type.SOCKS`), so the censor sees only an indistinguishable
     * Reality handshake to the entry — never the broker's SNI, IP, or DNS. There is NO
     * `tun` here: it does not touch app traffic. The DATA path uses [buildTwoHop] after a
     * volunteer is matched (a hot-reload of the same engine).
     *
     * Domain resolution happens at the ENTRY (vless forwards the destination domain), so
     * the broker domain is never resolved on the censored client — no DNS leak (verify on
     * device). `auto_detect_interface` keeps the Reality outbound on the physical network.
     */
    fun buildRendezvousProxy(
        entry: RealityRoute,
        socksPort: Int,
        logLevel: String = "info",
        logOutput: String? = null,
    ): String {
        val outputField = if (logOutput != null) ", \"output\": \"$logOutput\"" else ""
        val outboundsJoined = listOf(
            outbound(entry, tag = "rendezvous-out", detour = null),
            """{ "type": "direct", "tag": "direct" }""",
        ).joinToString(",\n    ")
        return """
{
  "log": { "level": "$logLevel", "timestamp": true$outputField },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "rendezvous-in",
      "listen": "127.0.0.1",
      "listen_port": $socksPort
    }
  ],
  "outbounds": [
    $outboundsJoined
  ],
  "route": {
    "auto_detect_interface": true,
    "final": "rendezvous-out"
  }
}
        """.trimIndent()
    }

    /**
     * A shard's Reality tunnel: the route to the shard-volunteer's bridge (from
     * `GET /mesh/shards`' `reality`) plus the local SOCKS port the client reads it over.
     */
    data class ShardTunnel(val route: RealityRoute, val socksPort: Int)

    /**
     * Extends the bootstrap rendezvous proxy with a dedicated Reality tunnel per Dir shard
     * (B1b shard transport — `docs/MESH_SHARD_TRANSPORT_v0.1.md`). Each [shards] entry gets its
     * own `mixed` SOCKS inbound routed to a Reality outbound to that shard-volunteer's bridge,
     * so the client reads the shard's loopback HTTP (`127.0.0.1:shardPort`) over the volunteer's
     * OWN egress-locked Reality — no broker in the read, no open relay. The bootstrap [entry]
     * SOCKS ([entrySocksPort] → `rendezvous-out`) is kept so the broker stays reachable for the
     * VOPRF during discovery. A single hot-reload of the one engine adds these tunnels.
     */
    fun buildShardReadProxy(
        entry: RealityRoute,
        entrySocksPort: Int,
        shards: List<ShardTunnel>,
        logLevel: String = "info",
        logOutput: String? = null,
    ): String {
        val outputField = if (logOutput != null) ", \"output\": \"$logOutput\"" else ""
        val inbounds = buildList {
            add(mixedInbound("rendezvous-in", entrySocksPort))
            shards.forEachIndexed { i, s -> add(mixedInbound("shard-in-$i", s.socksPort)) }
        }.joinToString(",\n    ")
        val outbounds = buildList {
            add(outbound(entry, tag = "rendezvous-out", detour = null))
            shards.forEachIndexed { i, s -> add(outbound(s.route, tag = "shard-out-$i", detour = null)) }
            add("""{ "type": "direct", "tag": "direct" }""")
        }.joinToString(",\n    ")
        val rules = shards.indices.joinToString(",\n      ") { i ->
            """{ "inbound": ["shard-in-$i"], "outbound": "shard-out-$i" }"""
        }
        val rulesField = if (rules.isNotEmpty()) "\n    \"rules\": [\n      $rules\n    ]," else ""
        return """
{
  "log": { "level": "$logLevel", "timestamp": true$outputField },
  "inbounds": [
    $inbounds
  ],
  "outbounds": [
    $outbounds
  ],
  "route": {
    "auto_detect_interface": true,$rulesField
    "final": "rendezvous-out"
  }
}
        """.trimIndent()
    }

    /** One local `mixed` (SOCKS+HTTP) inbound on `127.0.0.1:[port]`. */
    private fun mixedInbound(tag: String, port: Int): String = """
    {
      "type": "mixed",
      "tag": "$tag",
      "listen": "127.0.0.1",
      "listen_port": $port
    }""".trim()

    /** Emits one `vless`+`reality` outbound block; `flow` and `detour` are optional. */
    private fun outbound(route: RealityRoute, tag: String, detour: String?): String {
        val flowLine = if (route.flow.isNotBlank()) "\n      \"flow\": \"${route.flow}\"," else ""
        val detourLine = if (detour != null) "\n      \"detour\": \"$detour\"," else ""
        return """
    {
      "type": "vless",
      "tag": "$tag",
      "server": "${route.serverAddress}",
      "server_port": ${route.serverPort},
      "uuid": "${route.uuid}",$flowLine$detourLine
      "tls": {
        "enabled": true,
        "server_name": "${route.serverName}",
        "utls": { "enabled": true, "fingerprint": "${route.fingerprint}" },
        "reality": {
          "enabled": true,
          "public_key": "${route.realityPublicKey}",
          "short_id": "${route.shortId}"
        }
      }
    }""".trim()
    }

    /** Wraps [outbounds] (+ a `direct`) in the tun-inbound config envelope. */
    private fun assemble(
        outbounds: List<String>,
        finalTag: String,
        includePackages: List<String>,
        mtu: Int,
        logLevel: String,
        logOutput: String?,
    ): String {
        val includeLine = if (includePackages.isEmpty()) {
            ""
        } else {
            val pkgs = includePackages.joinToString(", ") { "\"$it\"" }
            ",\n      \"include_package\": [$pkgs]"
        }
        // Optional file sink for sing-box's own logs (they otherwise go to the
        // CommandServer buffer, not logcat) — for diagnosing the data path.
        val outputField = if (logOutput != null) ", \"output\": \"$logOutput\"" else ""
        val outboundsJoined =
            (outbounds + """{ "type": "direct", "tag": "direct" }""").joinToString(",\n    ")
        return """
{
  "log": { "level": "$logLevel", "timestamp": true$outputField },
  "inbounds": [
    {
      "type": "tun",
      "tag": "zat-tun",
      "address": ["172.19.0.1/30"],
      "mtu": $mtu,
      "auto_route": true,
      "strict_route": false,
      "stack": "gvisor"$includeLine
    }
  ],
  "outbounds": [
    $outboundsJoined
  ],
  "route": {
    "auto_detect_interface": true,
    "final": "$finalTag"
  }
}
        """.trimIndent()
    }
}
