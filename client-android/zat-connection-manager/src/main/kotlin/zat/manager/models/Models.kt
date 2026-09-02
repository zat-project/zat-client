package zat.manager.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// -------------------------------------------------------------------------
// VPN Gate models
//
// These models match the VPN Gate server entries carried by the Broker's
// signed bootstrap snapshot. The legacy MTProxy/relay models (RoutesResponse,
// RouteObject, RotationPolicy, RelayType, TrustTier) and the RouteFeedback
// telemetry model were removed when the client converged on the SSTP VPN path.
// -------------------------------------------------------------------------

/**
 * VpnRoute — a single VPN Gate server carried by the bootstrap snapshot.
 *
 * Field names use `@SerialName` to match the exact JSON keys from
 * `GET /v1/bootstrap-snapshot → servers[]`.
 *
 * Privacy / size:
 *   - `caPem` is the server's OpenVPN `<ca>` cert (PEM) — the SSTP client pins its TLS to it. The
 *     broker ships JUST this instead of the whole base64 `.ovpn` config, shrinking the snapshot ~5x.
 *   - This is public server metadata (a CA cert). `null` if the server carried no `<ca>`.
 */
@Serializable
data class VpnRoute(
    @SerialName("id") val id: String,
    @SerialName("host") val host: String,
    @SerialName("ip") val ip: String,
    @SerialName("score") val score: Int,
    @SerialName("ping") val ping: Int = 0,
    @SerialName("speed") val speed: String,
    @SerialName("uptime") val uptime: String = "0",
    @SerialName("sessions") val sessions: Int = 0,
    @SerialName("country_short") val countryShort: String,
    @SerialName("country_long") val countryLong: String,
    @SerialName("protocol") val protocol: String = "udp",
    @SerialName("port") val port: Int = 0,
    @SerialName("quality_tier") val qualityTier: String = "unknown",
    @SerialName("quality_score") val qualityScore: Double = 0.0,
    @SerialName("ca_pem") val caPem: String? = null,
)

/**
 * RealityServer — a single VLESS/Reality entry server carried by the bootstrap
 * snapshot's `reality_servers` array (the anti-DPI transport, Stage 2).
 *
 * Unlike [VpnRoute] (a VPN Gate / SSTP node), a Reality server is a dedicated
 * ZAT entry: the client dials [address]:[port], performs a Reality handshake
 * (stealing [serverName]'s TLS), and tunnels Telegram through it. [publicKey]
 * pairs with the server's x25519 private key; [shortId] must match one the
 * server allows; [uuid] is the VLESS user id.
 *
 * Privacy: contains only public server metadata + the client's pre-shared
 * connection params (no user identity). Carried inside the Ed25519-signed
 * snapshot, so it is authenticated end-to-end.
 */
@Serializable
data class RealityServer(
    @SerialName("id") val id: String,
    @SerialName("address") val address: String,
    @SerialName("port") val port: Int,
    @SerialName("uuid") val uuid: String,
    @SerialName("public_key") val publicKey: String,
    @SerialName("short_id") val shortId: String = "",
    @SerialName("server_name") val serverName: String = "www.cloudflare.com",
    @SerialName("fingerprint") val fingerprint: String = "chrome",
    // XTLS flow: vision for a single-hop direct server; a Reality server used as a
    // two-hop EXIT is no-flow (the validated two-hop pattern is plain vless+reality).
    @SerialName("flow") val flow: String = "xtls-rprx-vision",
    @SerialName("country_short") val countryShort: String = "",
    @SerialName("country_long") val countryLong: String = "",
    @SerialName("quality_score") val qualityScore: Double = 0.0,
)

// -------------------------------------------------------------------------
// Bootstrap Snapshot models — Phase 11.1 (Multi-Channel Bootstrap)
//
// These models match the top-level JSON document served at
// GET /v1/bootstrap-snapshot and republished to the bootstrap channels
// (GitHub, GitLab, Cloudflare R2). The `servers` array reuses [VpnRoute].
// -------------------------------------------------------------------------

/**
 * BootstrapSnapshot — the canonical, Ed25519-signed bootstrap document.
 *
 * It is published to external platforms (GitHub, GitLab, Cloudflare R2) so the
 * client can recover bootstrap routes even when the Broker is unreachable.
 *
 * Privacy: Contains only public VPN Gate volunteer server metadata. No user
 * identity, Telegram data, or device information is included.
 */
@Serializable
data class BootstrapSnapshot(
    @SerialName("schema_version") val schemaVersion: Int,
    @SerialName("generated_at") val generatedAt: String,
    @SerialName("ttl_seconds") val ttlSeconds: Int,
    @SerialName("server_count") val serverCount: Int,
    @SerialName("servers") val servers: List<VpnRoute>,
    // Anti-DPI Reality entry servers (Stage 2). Optional + defaulted so older
    // SSTP-only snapshots (and the signature over them) remain valid.
    @SerialName("reality_servers") val realityServers: List<RealityServer> = emptyList(),
    // The live rendezvous introducer base URL (Model B); empty when the broker has
    // none → the client uses single-hop Reality / SSTP. Optional + defaulted so
    // older snapshots (and the Ed25519 signature over them) remain valid.
    @SerialName("introducer_url") val introducerUrl: String = "",
    // Rendezvous-entries (MESH Stage 1 — "reach-over-Reality"): Reality inbounds whose
    // egress is locked to the broker. The client tunnels its match/report control
    // traffic THROUGH one of these over Reality, so the broker's SNI/IP/DNS never
    // appear on the wire. Reuses [RealityServer] (same Reality params). Optional +
    // defaulted so older snapshots (and the Ed25519 signature over them) stay valid.
    @SerialName("rendezvous_entries") val rendezvousEntries: List<RealityServer> = emptyList(),
    @SerialName("rotation_policy") val rotationPolicy: BootstrapRotationPolicy,
)

/**
 * BootstrapRotationPolicy — VPN connection behavior hints for the client.
 *
 * Specifies the protocol fallback order (SSTP-only) and connection timing
 * hints used by the VPN Gate bootstrap flow.
 */
@Serializable
data class BootstrapRotationPolicy(
    @SerialName("protocol_fallback_order") val protocolFallbackOrder: List<String>,
    @SerialName("connection_timeout_seconds") val connectionTimeoutSeconds: Int,
    @SerialName("sticky_on_success") val stickyOnSuccess: Boolean,
    @SerialName("avoid_rotation_during_upload") val avoidRotationDuringUpload: Boolean,
    @SerialName("avoid_rotation_during_call") val avoidRotationDuringCall: Boolean,
)

// -------------------------------------------------------------------------
// Rendezvous models — the live introducer's match response (L2 of
// RENDEZVOUS_DESIGN_v0.1). Keys are the introducer's camelCase JSON exactly
// (broker RendezvousService.MatchResult), so no @SerialName is needed.
// -------------------------------------------------------------------------

/** The outer-hop Reality params a client needs to dial a matched volunteer. */
@Serializable
data class VolunteerReality(
    val uuid: String,
    val publicKey: String,
    val shortId: String,
    val serverName: String,
    val fingerprint: String,
)

/** A currently-live volunteer bridge, with its reachability tier. */
@Serializable
data class MatchedVolunteer(
    // The volunteer's opaque id, for the IP-free /report Trace-1 signal. Defaulted so an
    // older introducer that omits it still parses (the client then simply does not report).
    val volunteerId: String = "",
    val host: String,
    val port: Int,
    val reality: VolunteerReality,
    val tier: String,
)

/**
 * VolunteerHandle — a single-use handle returned by `/v1/rendezvous/match`. The
 * client builds the two-hop chain from [volunteer] (outer hop) + a snapshot exit
 * (inner hop); the handle is redeemed once on connect.
 *
 * Note: single-use is a connection-binding / reputation *signal*, NOT an
 * anti-enumeration mechanism — a matched client must learn the volunteer's
 * address to connect, so the address is harvestable on the first match. The real
 * anti-enumeration levers are the introducer GATE + traitor-tracing and pool
 * churn (DEFENSE_ARCHITECTURE_v0.1 §6.F8; GATE_AND_TRAITOR_TRACING_v0.1).
 */
@Serializable
data class VolunteerHandle(
    val handleId: String,
    val expiresAt: Long,
    val volunteer: MatchedVolunteer,
)
