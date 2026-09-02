package zat.manager.vpn.engine

import zat.manager.models.VpnRoute

/**
 * VpnProtocolEngine — the SSTP fallback engine abstraction.
 *
 * The concrete implementation is [SstpEngine], a pure-Kotlin SSTP-over-TLS tunnel. The native
 * OpenVPN path was removed (the client is SSTP-only for this fallback — see the snapshot's
 * rotation policy). The PRIMARY data path is Reality / two-hop via `RealityEngine`, not this
 * interface; SSTP is the last-resort fallback.
 *
 * Each engine implementation:
 *   1. Receives a [VpnRoute] (server details + its OpenVPN `<ca>` PEM in [VpnRoute.caPem], which
 *      SSTP pins its TLS to).
 *   2. Establishes a tunnel using the protocol-specific logic.
 *   3. Reports its connection state.
 *
 * Privacy rules:
 *   - Engines must not write decoded configuration data to disk.
 *   - Engines must not log full configuration strings (only lengths).
 *   - No user identity, Telegram data, or end-user information is accessed.
 */
interface VpnProtocolEngine {

    /**
     * Starts the VPN engine with the given VPN Gate route profile.
     *
     * The engine pins its TLS to the profile's [VpnRoute.caPem] (the server's
     * OpenVPN `<ca>` cert, pre-extracted by the broker) and initiates a connection.
     *
     * @param profile The [VpnRoute] containing server host, ip, and the CA PEM.
     * @param vpnService The active [android.net.VpnService] instance, used for
     *                   socket protection via [android.net.VpnService.protect].
     * @param tunFd The TUN file descriptor from
     *              [android.net.VpnService.Builder.establish], or -1 if
     *              not yet available.
     */
    fun start(profile: VpnRoute, vpnService: android.net.VpnService, tunFd: Int)

    /**
     * Stops the VPN engine and tears down any active tunnel.
     */
    fun stop()

    /**
     * Returns the current engine state as a string.
     *
     * Possible values: "IDLE", "CONNECTING", "CONNECTED",
     * "DISCONNECTING", "ERROR".
     */
    fun getState(): String
}

