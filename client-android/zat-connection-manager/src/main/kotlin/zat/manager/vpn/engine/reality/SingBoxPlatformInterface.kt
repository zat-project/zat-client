package zat.manager.vpn.engine.reality

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.system.OsConstants
import android.util.Log
import io.nekohasekai.libbox.ConnectionOwner
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.LocalDNSTransport
import io.nekohasekai.libbox.NetworkInterface as LibboxNetworkInterface
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.Notification
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.WIFIState

/**
 * Bridges sing-box's libbox [PlatformInterface] to the host Android VpnService.
 *
 * sing-box (inside libbox) obtains the VPN tun fd from [openTun] (delegated to the
 * hosting service via [host]) and learns the underlying physical network from the
 * **default-interface monitor** ([startDefaultInterfaceMonitor]). Crucially,
 * sing-box binds its OWN outbound sockets (e.g. the Reality connection to the
 * server) to that physical interface — without the monitor those sockets fall
 * back into the per-app tun and loop, so nothing reaches the server. (Matching
 * SagerNet/sing-box-for-android, [autoDetectInterfaceControl] is intentionally a
 * no-op: the binding is driven by the monitored default interface, not per-fd
 * VpnService.protect.)
 */
class SingBoxPlatformInterface(
    private val host: Host,
    private val context: Context,
) : PlatformInterface {

    /** What the hosting VpnService provides to libbox. */
    interface Host {
        /** Build the VPN tun from sing-box's requested [TunOptions]; return its fd. */
        fun openTun(options: TunOptions): Int

        /** Exempt a libbox outbound socket from the VPN tun (`VpnService.protect`). */
        fun protectSocket(fd: Int): Boolean
    }

    private val connectivity: ConnectivityManager
        get() = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun openTun(options: TunOptions): Int = host.openTun(options)

    // sing-box runs INSIDE the per-app-captured (Telegram) process, so its OWN
    // outbound sockets — including the Reality connection to the server — would be
    // pulled into the tun and loop. Protect each one so it bypasses the VPN and
    // rides the physical network directly. (The default-interface monitor tells
    // sing-box *which* physical network; protect is what actually exempts the fd.)
    override fun autoDetectInterfaceControl(fd: Int) {
        host.protectSocket(fd)
    }
    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true
    override fun useProcFS(): Boolean = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q
    override fun underNetworkExtension(): Boolean = false
    override fun includeAllNetworks(): Boolean = false

    // --- default-network monitor: tells sing-box which physical interface to bind
    @SuppressLint("NewApi")
    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        val cm = connectivity
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = notify(cm, network, listener)
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) =
                notify(cm, network, listener)
        }
        networkCallback = callback
        // Track the underlying PHYSICAL network only (NOT_VPN) — never the VPN's
        // own tun. registerDefaultNetworkCallback() would report the tun once the
        // VPN is up, and sing-box would bind its outbound back into the tunnel and
        // loop (the server then never receives the connection).
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        try {
            cm.registerNetworkCallback(request, callback)
        } catch (e: Exception) {
            Log.w(TAG, "default-interface monitor register failed: ${e.message}")
        }
        // SEED the current underlying interface SYNCHRONOUSLY. registerNetworkCallback delivers
        // onAvailable asynchronously, but a fresh bootstrap engine (reach-over-Reality match) dials
        // its outbound within ~4 ms of start — before the callback lands — and sing-box then fails
        // "no available network interface" (every match attempt SocketExceptions → single-hop
        // fallback). Pick the current INTERNET + NOT_VPN network now so the first outbound has it.
        try {
            @Suppress("DEPRECATION")
            cm.allNetworks.firstOrNull { n ->
                cm.getNetworkCapabilities(n)?.let {
                    it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                        it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                } == true
            }?.let { notify(cm, it, listener) }
        } catch (e: Exception) {
            Log.w(TAG, "default-interface seed failed: ${e.message}")
        }
    }

    private fun notify(cm: ConnectivityManager, network: Network, listener: InterfaceUpdateListener) {
        try {
            val name = cm.getLinkProperties(network)?.interfaceName ?: return
            if (name.startsWith("tun")) return // belt-and-suspenders: never the VPN tun
            val index = java.net.NetworkInterface.getByName(name)?.index ?: return
            val caps = cm.getNetworkCapabilities(network)
            val expensive = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false
            listener.updateDefaultInterface(name, index, expensive, false)
            Log.i(TAG, "Reality: default interface = $name (index $index)")
        } catch (e: Exception) {
            Log.w(TAG, "default-interface notify failed: ${e.message}")
        }
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        networkCallback?.let { cb -> runCatching { connectivity.unregisterNetworkCallback(cb) } }
        networkCallback = null
    }

    /**
     * Enumerate the host's network interfaces for sing-box.
     *
     * CRITICAL: this MUST be populated. sing-box resolves the default interface
     * (reported by [startDefaultInterfaceMonitor], e.g. `wlan0`) against this list
     * to bind/protect its outbound sockets. An empty list makes every outbound dial
     * fail with "no available network interface" (the box runs but carries nothing).
     */
    override fun getInterfaces(): NetworkInterfaceIterator {
        val list = mutableListOf<LibboxNetworkInterface>()
        try {
            val nifs = java.net.NetworkInterface.getNetworkInterfaces() ?: return InterfaceArray(list)
            for (nif in nifs) {
                val bi = LibboxNetworkInterface()
                bi.name = nif.name
                bi.index = nif.index
                try { bi.mtu = nif.mtu } catch (e: Exception) { /* leave 0 */ }
                bi.addresses = StringArray(
                    nif.interfaceAddresses.mapNotNull { ia ->
                        // Strip the IPv6 zone id (e.g. "fe80::1%dummy0") — sing-box's
                        // netip.ParsePrefix rejects a zone in a prefix and PANICS
                        // (SIGABRT), taking the whole process down.
                        ia.address.hostAddress?.substringBefore('%')?.let { "$it/${ia.networkPrefixLength}" }
                    }
                )
                bi.dnsServer = StringArray(emptyList())
                var flags = 0
                if (nif.isUp) flags = flags or OsConstants.IFF_UP
                if (nif.isLoopback) flags = flags or OsConstants.IFF_LOOPBACK
                if (nif.isPointToPoint) flags = flags or OsConstants.IFF_POINTOPOINT
                if (nif.supportsMulticast()) flags = flags or OsConstants.IFF_MULTICAST
                bi.flags = flags
                bi.type = when {
                    nif.name.startsWith("wlan") -> 0 // WIFI
                    nif.name.startsWith("rmnet") || nif.name.startsWith("ccmni") ||
                        nif.name.startsWith("radio") || nif.name.startsWith("pdp") -> 1 // Cellular
                    nif.name.startsWith("eth") -> 2 // Ethernet
                    else -> 3 // Other
                }
                bi.metered = false
                list.add(bi)
            }
        } catch (e: Exception) {
            Log.w(TAG, "getInterfaces failed: ${e.message}")
        }
        return InterfaceArray(list)
    }

    /** Backs [LibboxNetworkInterface.addresses]/`dnsServer` (a libbox StringIterator). */
    private class StringArray(private val items: List<String>) : StringIterator {
        private var i = 0
        override fun hasNext(): Boolean = i < items.size
        override fun len(): Int = items.size
        override fun next(): String = items[i++]
    }

    private class InterfaceArray(private val items: List<LibboxNetworkInterface>) : NetworkInterfaceIterator {
        private var i = 0
        override fun hasNext(): Boolean = i < items.size
        override fun next(): LibboxNetworkInterface = items[i++]
    }

    override fun clearDNSCache() {}
    override fun localDNSTransport(): LocalDNSTransport? = null
    override fun systemCertificates(): StringIterator? = null
    override fun readWIFIState(): WIFIState? = null
    override fun sendNotification(notification: Notification) {}
    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int
    ): ConnectionOwner = throw NotImplementedError("findConnectionOwner")

    companion object {
        private const val TAG = "ZAT"
    }
}
