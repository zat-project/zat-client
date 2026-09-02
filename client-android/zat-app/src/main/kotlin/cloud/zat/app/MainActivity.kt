package cloud.zat.app

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import zat.manager.vpn.ConnectionState
import zat.manager.vpn.RunDiagnostics
import zat.manager.vpn.VpnManager
import zat.manager.vpn.ZatConnectionState

/**
 * The whole product surface: one screen, one button.
 *
 * Tap → (first time) the system VPN-consent dialog → the library's `fetchRouteAndStartVpn` does
 * everything (bootstrap → rendezvous → two-hop over Reality). The button label + status line are
 * driven purely by [ZatConnectionState] — the app holds no connection logic of its own.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var button: Button
    private lateinit var status: TextView

    /** The system VPN-consent result: on OK, actually start the tunnel. */
    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                startTunnel()
            } else {
                status.text = getString(R.string.status_permission_denied)
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // P1.1 · say which build this is, once, at startup. Two reasons, and the second is why it is
        // a log line rather than a bare constant: (a) a user's log tells us exactly what they are
        // running, which is the difference between debugging a real fault and guessing; (b) R8 strips
        // an unused field, so a stamp nobody reads does not survive into the artifact users install —
        // which is precisely what happened on the first attempt, and release-check caught it.
        android.util.Log.i("ZAT", "ZAT build ${BuildConfig.GIT_COMMIT}")
        installSnapshotFreshnessStore()
        setContentView(R.layout.activity_main)
        button = findViewById(R.id.connectButton)
        status = findViewById(R.id.statusText)
        findViewById<TextView>(R.id.inviteLink).setOnClickListener { showInviteDialog() }
        // #46: the tester's report, on a LONG-PRESS of the status line. Not a visible link, because a
        // permanent "diagnostics" affordance is noise for an ordinary user and one more thing on a
        // screenshot; a tester we have told will find it, and nobody else has to.
        status.setOnLongClickListener { showRunReport(); true }

        button.setOnClickListener {
            when (ZatConnectionState.state.value) {
                ConnectionState.DISCONNECTED, ConnectionState.ERROR -> connect()
                else -> disconnect()
            }
        }

        // Drive the UI from the live tunnel state (no polling, no broadcast plumbing).
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                ZatConnectionState.state.collect(::render)
            }
        }
    }

    private fun connect() {
        // `null` = the VPN permission is already granted; else show the system consent first.
        val consent = VpnManager.prepareVpn(this)
        if (consent != null) vpnConsent.launch(consent) else startTunnel()
    }

    private fun startTunnel() {
        VpnManager.setVpnEnabled(this, true)
        VpnManager.fetchRouteAndStartVpn(this, trigger = "user-tap")
    }

    private fun disconnect() {
        VpnManager.setVpnEnabled(this, false)
        VpnManager.stopVpn(this)
    }

    private fun render(state: ConnectionState) {
        val (label, statusText) = when (state) {
            ConnectionState.DISCONNECTED -> R.string.connect to R.string.status_disconnected
            ConnectionState.CONNECTING -> R.string.disconnect to R.string.status_connecting
            ConnectionState.CONNECTED -> R.string.disconnect to R.string.status_connected
            ConnectionState.RECONNECTING -> R.string.disconnect to R.string.status_reconnecting
            ConnectionState.ERROR -> R.string.connect to R.string.status_error
        }
        button.setText(label)
        status.setText(statusText)
    }

    // --- Invite-graph (P3.1c): paste a received tier credential, and create an invitation to share. ---

    /** Paste/edit YOUR credential (saved for presentation on match) + create an invitation to share. */
    /**
     * #46 — what happened on the last attempt, in a form a tester can screenshot or read aloud.
     *
     * Channel NUMBERS only. The URLs are semi-secret and a screenshot may travel over a monitored
     * messenger; an index tells us everything we need and a censor nothing it did not already have.
     * Nothing here identifies the user, and failure reasons are CLASSES rather than messages, which
     * could otherwise carry a host.
     */
    private fun showRunReport() {
        val r = RunDiagnostics.snapshot()
        val lines = buildList {
            add(getString(R.string.diag_intro))
            add("")
            add(
                if (r.workingChannels.isEmpty()) getString(R.string.diag_none)
                else getString(R.string.diag_working, r.workingRouteNumbers.joinToString("، "))
            )
            val failed = r.channels.filter { !it.ok }
            if (failed.isNotEmpty()) {
                add(getString(R.string.diag_failed, failed.joinToString("، ") { "${it.index + 1} (${it.reason})" }))
            }
            add(getString(R.string.diag_source, r.source.name.lowercase()))
            if (r.peerRefreshed) add(getString(R.string.diag_peer_refresh))
            add(getString(R.string.diag_stage, r.stage))
            // The dissolution scoreboard, in the tester's own report: how much this connection
            // needed US. A count, never an address — and from inside a censored country it is the
            // most interesting number on the page, because whatever still depends on the broker is
            // exactly what a censor gets to attack.
            add(getString(R.string.diag_broker, zat.manager.vpn.BrokerReliance.total()))
            add("")
            // The one-liner exists for the case where sending a screenshot is itself risky and the
            // tester reads it over a call instead. ASCII, terse, retypable.
            add(r.oneLine())
        }
        val text = lines.joinToString(System.lineSeparator())
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.diag_title)
            .setMessage(text)
            .setPositiveButton(R.string.diag_copy) { _, _ ->
                val cm = getSystemService(android.content.ClipboardManager::class.java)
                cm?.setPrimaryClip(android.content.ClipData.newPlainText("zat", text))
                android.widget.Toast.makeText(this, R.string.diag_copied, android.widget.Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton(R.string.diag_close, null)
            .show()
    }

    private fun showInviteDialog() {
        val input = EditText(this).apply {
            setText(VpnManager.inviteCredential(this@MainActivity) ?: "")
            hint = getString(R.string.invite_credential_hint)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.invite_title)
            .setMessage(R.string.invite_message)
            .setView(input)
            .setPositiveButton(R.string.invite_save) { _, _ ->
                VpnManager.setInviteCredential(this, input.text.toString())
                toast(getString(R.string.invite_saved))
            }
            .setNeutralButton(R.string.invite_create) { _, _ ->
                VpnManager.setInviteCredential(this, input.text.toString()) // save any edit first
                createInvitation()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Mint a child invitation from the stored credential (off the main thread) + show it to share. */
    private fun createInvitation() {
        if (VpnManager.inviteCredential(this) == null) {
            toast(getString(R.string.invite_need_credential))
            return
        }
        toast(getString(R.string.invite_creating))
        lifecycleScope.launch {
            val child = withContext(Dispatchers.IO) { VpnManager.mintInvitation(this@MainActivity) }
            if (child != null) showCredentialToShare(child) else toast(getString(R.string.invite_failed))
        }
    }

    /** Show a minted invitation in a read-only field with a Copy-to-clipboard action. */
    private fun showCredentialToShare(credential: String) {
        val field = EditText(this).apply {
            setText(credential)
            keyListener = null // read-only but selectable
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.invite_share_title)
            .setMessage(R.string.invite_share_message)
            .setView(field)
            .setPositiveButton(R.string.invite_copy) { _, _ ->
                val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("ZAT invitation", credential))
                toast(getString(R.string.invite_copied))
            }
            .setNegativeButton(R.string.close, null)
            .show()
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    /**
     * A9: give the bootstrap resolver somewhere durable to keep its freshness mark.
     *
     * The resolver refuses a snapshot older than the newest it has already accepted — that is what
     * stops anyone who controls a channel or a stale CDN cache from pinning this client to an old
     * bridge list. The mark only means something if it OUTLIVES the process, because "app closed
     * overnight" is exactly the window such an attack wants. Without this call it degrades to
     * in-memory, which protects a session and forgets on restart.
     *
     * Ordinary prefs, not encrypted: this is a public timestamp from a public artifact. Its integrity
     * is what matters (a local attacker who could rewrite it could rewrite the APK), and it holds
     * nothing about the user.
     */
    private fun installSnapshotFreshnessStore() {
        val prefs = getSharedPreferences("zat_bootstrap", MODE_PRIVATE)
        zat.manager.vpn.BootstrapResolver.installFreshnessStore(
            object : zat.manager.vpn.BootstrapResolver.FreshnessStore {
                override fun read(): Long = prefs.getLong("snapshot_high_water", 0L)
                override fun write(value: Long) {
                    prefs.edit().putLong("snapshot_high_water", value).apply()
                }

                // The last snapshot this device verified — kept so a total channel block does not
                // finish a user who has connected before. Public data (it is on six public channels,
                // identical for everyone), so this does not touch the standing rule that the user's
                // own route history stays in memory.
                override fun readSnapshot(): String? = prefs.getString("snapshot_last_good", null)
                override fun writeSnapshot(body: String) {
                    prefs.edit().putString("snapshot_last_good", body).apply()
                }
            },
        )
    }
}
