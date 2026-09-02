package zat.manager.vpn

import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit

/**
 * ProtectedHttp — the shared OkHttp client factory for ZAT's own control-plane
 * fetches (the bootstrap snapshot and the rendezvous match).
 *
 * When [client]'s `protect` is supplied, every socket is `VpnService.protect()`'d
 * before it connects, so the fetch reaches the network even under an always-on VPN
 * with "Block connections without VPN" (lockdown) while no tunnel is up yet. When
 * it is null, a shared plain client is returned.
 *
 * TLS uses the platform (system) trust store. These channels are public services
 * whose leaf certs rotate across major CAs, so no custom pinning is applied here —
 * endpoint authenticity is enforced separately (the bootstrap snapshot by its
 * Ed25519 signature). Short 5s timeouts keep channel failover snappy.
 */
object ProtectedHttp {

    private const val CONNECT_TIMEOUT_SEC = 5L
    // The signed bootstrap snapshot is ~200 KB; on a throttled/shaped censored link a 5 s read
    // ceiling can time out a healthy channel mid-body (a stall > read-timeout aborts the download,
    // needlessly burning a good channel). Keep CONNECT short for snappy failover, but give the READ
    // enough headroom to pull the whole body on a slow path. The rendezvous /match is tiny, so a
    // larger read ceiling never delays it (it responds well within).
    private const val READ_TIMEOUT_SEC = 15L

    private val plain: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(CONNECT_TIMEOUT_SEC, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT_SEC, TimeUnit.SECONDS)
            .build()
    }

    /**
     * Returns a client whose every socket is `protect()`'d, or the shared plain
     * client when [protect] is null.
     */
    fun client(protect: ((java.net.Socket) -> Boolean)?): OkHttpClient {
        if (protect == null) return plain
        val factory = object : javax.net.SocketFactory() {
            private fun prepared(s: java.net.Socket): java.net.Socket {
                // bind() forces the fd to be allocated so protect() (which needs a
                // real fd) takes effect; OkHttp then connect()s the bound socket.
                runCatching { if (!s.isBound) s.bind(java.net.InetSocketAddress(0)) }
                runCatching { protect(s) }
                return s
            }
            override fun createSocket(): java.net.Socket = prepared(java.net.Socket())
            override fun createSocket(host: String, port: Int): java.net.Socket =
                prepared(java.net.Socket()).apply { connect(java.net.InetSocketAddress(host, port)) }
            override fun createSocket(host: String, port: Int, localHost: java.net.InetAddress, localPort: Int): java.net.Socket =
                createSocket(host, port)
            override fun createSocket(host: java.net.InetAddress, port: Int): java.net.Socket =
                prepared(java.net.Socket()).apply { connect(java.net.InetSocketAddress(host, port)) }
            override fun createSocket(address: java.net.InetAddress, port: Int, localAddress: java.net.InetAddress, localPort: Int): java.net.Socket =
                createSocket(address, port)
        }
        return OkHttpClient.Builder()
            .connectTimeout(CONNECT_TIMEOUT_SEC, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT_SEC, TimeUnit.SECONDS)
            .socketFactory(factory)
            .build()
    }

    // The reach-over-Reality bootstrap proxy needs a longer budget than the direct
    // channels: the request rides a Reality handshake to the entry + the entry's hop
    // to the broker, not a single direct TLS.
    private const val SOCKS_CONNECT_TIMEOUT_SEC = 12L
    private const val SOCKS_READ_TIMEOUT_SEC = 12L

    /**
     * Returns a client that routes every request through a local SOCKS5 proxy at
     * `127.0.0.1:[port]` — the `mixed` inbound of the reach-over-Reality bootstrap
     * libbox (MESH Stage 1). OkHttp passes the destination host to the proxy
     * UNRESOLVED for a SOCKS proxy, so the broker domain is resolved AT THE ENTRY
     * (no client-side DNS leak). No `protect()` is needed: the only socket this
     * client opens is the loopback hop to the proxy, which is never tunnelled.
     */
    fun socksClient(port: Int): OkHttpClient =
        OkHttpClient.Builder()
            .connectTimeout(SOCKS_CONNECT_TIMEOUT_SEC, TimeUnit.SECONDS)
            .readTimeout(SOCKS_READ_TIMEOUT_SEC, TimeUnit.SECONDS)
            .proxy(java.net.Proxy(java.net.Proxy.Type.SOCKS, java.net.InetSocketAddress("127.0.0.1", port)))
            .build()
}
