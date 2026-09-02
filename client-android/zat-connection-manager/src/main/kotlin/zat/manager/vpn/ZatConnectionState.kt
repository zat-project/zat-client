package zat.manager.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The LIVE state of the ZAT tunnel — what a one-button UI shows.
 *
 * Distinct from [VpnManager.isVpnEnabled], which persists the user's *intent* (the toggle). This is
 * the moment-to-moment reality the service reports.
 */
enum class ConnectionState {
    /** No tunnel; the button says "Connect". */
    DISCONNECTED,

    /** A start was requested; resolving bootstrap / matching / bringing the engine up. */
    CONNECTING,

    /** The tunnel engine is up and carrying traffic. */
    CONNECTED,

    /** The tunnel was up but a volunteer/engine churned; auto-re-matching without user action. */
    RECONNECTING,

    /** A start failed with no path left (e.g. every bootstrap channel failed). */
    ERROR,
}

/**
 * Process-wide, observable connection state that [ZatVpnService] updates at its transitions and any
 * UI collects (`ZatConnectionState.state.collectAsState()`). Kept in the library so the state has a
 * single source of truth regardless of which UI (the one-button app, the desktop, a test host)
 * drives it — no broadcast/receiver plumbing in the UI.
 */
object ZatConnectionState {
    private val _state = MutableStateFlow(ConnectionState.DISCONNECTED)

    /** The live tunnel state. Collect it to drive the button label + status line. */
    val state: StateFlow<ConnectionState> = _state.asStateFlow()

    /** Called by [ZatVpnService] at each transition; a repeat of the current value is a no-op. */
    fun set(next: ConnectionState) {
        _state.value = next
    }
}
