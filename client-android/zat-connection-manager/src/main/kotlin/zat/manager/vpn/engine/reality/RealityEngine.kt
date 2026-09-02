package zat.manager.vpn.engine.reality

import android.util.Log
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.SetupOptions
import io.nekohasekai.libbox.SystemProxyStatus
import java.io.File

/**
 * Runs a sing-box instance (via libbox) for one VLESS/Reality route, inside the
 * ZAT VpnService.
 *
 * Lifecycle (libbox v1.13): [Libbox.setup] once → `CommandServer(handler, platform)`
 * → `start()` → `startOrReloadService(config)`; `closeService()` + `close()` to stop.
 * This class is the [CommandServerHandler], so sing-box drives reload/stop through it.
 *
 * The config comes from [RealitySingBoxConfig]; [platform] ([SingBoxPlatformInterface])
 * provides the tun fd and socket protection.
 */
class RealityEngine(
    private val platform: PlatformInterface,
    /** App-private dir for sing-box working files (e.g. context.filesDir/singbox). */
    private val baseDir: String,
    private val onServiceStop: () -> Unit,
) : CommandServerHandler {

    private var commandServer: CommandServer? = null
    @Volatile private var currentConfig: String? = null

    /** Start (or hot-reload) the tunnel with [config] from [RealitySingBoxConfig]. */
    @Synchronized
    fun start(config: String) {
        ensureSetup()
        Libbox.checkConfig(config) // fail fast on a malformed config
        val server = commandServer ?: CommandServer(this, platform).also {
            it.start()
            commandServer = it
        }
        server.startOrReloadService(config, OverrideOptions())
        currentConfig = config
        Log.i(TAG, "Reality engine: sing-box service started.")
    }

    @Synchronized
    fun stop() {
        val server = commandServer ?: return
        commandServer = null
        currentConfig = null
        try { server.closeService() } catch (e: Exception) { Log.w(TAG, "closeService: ${e.message}") }
        try { server.close() } catch (e: Exception) { /* ignore */ }
        Log.i(TAG, "Reality engine: sing-box service stopped.")
    }

    private fun ensureSetup() {
        if (didSetup) return
        File(baseDir, "work").mkdirs()
        File(baseDir, "temp").mkdirs()
        Libbox.setup(SetupOptions().apply {
            basePath = baseDir
            workingPath = File(baseDir, "work").absolutePath
            tempPath = File(baseDir, "temp").absolutePath
            fixAndroidStack = true
        })
        // Capture sing-box's own stderr (its connection/error logs don't reach
        // logcat) so failures are diagnosable: <baseDir>/stderr.log.
        try {
            Libbox.redirectStderr(File(baseDir, "stderr.log").absolutePath)
        } catch (e: Exception) {
            Log.w(TAG, "redirectStderr failed: ${e.message}")
        }
        didSetup = true
    }

    // --- CommandServerHandler -------------------------------------------------
    override fun serviceReload() {
        val cfg = currentConfig ?: return
        try {
            commandServer?.startOrReloadService(cfg, OverrideOptions())
        } catch (e: Exception) {
            Log.w(TAG, "Reality engine: reload failed: ${e.message}")
        }
    }

    override fun serviceStop() {
        Log.i(TAG, "Reality engine: sing-box requested serviceStop (the box exited).")
        stop()
        onServiceStop()
    }

    /** Android routes via the per-app tun, not a system HTTP proxy. */
    override fun getSystemProxyStatus(): SystemProxyStatus = SystemProxyStatus()

    override fun setSystemProxyEnabled(isEnabled: Boolean) { /* no-op on Android */ }

    override fun writeDebugMessage(message: String) {
        Log.d(TAG, "sing-box: $message")
    }

    companion object {
        private const val TAG = "ZAT"
        // libbox.setup() is process-global; guard so it runs at most once.
        @Volatile private var didSetup = false
    }
}
