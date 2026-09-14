import Foundation

/// A cache owned by the helper, not a synchronous call into Virtualization.
/// The control thread can report stale observations when the VM queue is stuck.
final class VMRuntimeStatus {
    private let lock = NSLock()
    private var state = "creating"
    private var observedAt = ProcessInfo.processInfo.systemUptime
    private var heartbeatAt: Double? = nil
    private var refreshPending = false
    private var lastError: String? = nil

    func observed(state: String, error: String? = nil) {
        lock.lock(); defer { lock.unlock() }
        self.state = state; observedAt = ProcessInfo.processInfo.systemUptime
        if let error { lastError = error }
    }

    func beginRefresh() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if refreshPending { return false }
        refreshPending = true; return true
    }

    func refreshed(state: String) {
        lock.lock(); defer { lock.unlock() }
        self.state = state
        heartbeatAt = ProcessInfo.processInfo.systemUptime
        observedAt = heartbeatAt!
        refreshPending = false
    }

    func snapshot() -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        return ["state": state, "observed_at": observedAt,
                "heartbeat_at": heartbeatAt.map { $0 as Any } ?? NSNull(),
                "refresh_pending": refreshPending, "last_error": lastError as Any? ?? NSNull()]
    }
}
