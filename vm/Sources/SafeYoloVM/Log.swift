import Foundation

/// Simple timestamped stderr logger for the helper process's bridges.
///
/// Intentionally minimal: ISO-8601-ish timestamp + label + message. Mirrors
/// the format the Python side uses (`logging.basicConfig(fmt="%(asctime)s
/// %(name)s %(levelname)s %(message)s")`) so logs from both halves grep
/// together cleanly.
///
/// Not a logger framework — just a `fputs` wrapper. The helper runs in a
/// constrained process (sandboxed, detached) and we don't need log levels,
/// rotation, or async dispatch; we need "when did this happen, in which
/// component, with which agent + flow id" in a form a future operator can
/// read.
enum Log {

    /// Evaluated once at process start. Set SAFEYOLO_VM_DEBUG=1 to enable
    /// high-frequency per-flow accept logs. `done` and `warn` lines are
    /// always emitted — they carry the load-bearing diagnostic info
    /// (byte counts, duration, errors) and are low enough volume to
    /// stay on in production.
    static let debugEnabled: Bool = {
        guard let v = ProcessInfo.processInfo.environment["SAFEYOLO_VM_DEBUG"] else {
            return false
        }
        return v == "1" || v.lowercased() == "true"
    }()

    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        f.timeZone = TimeZone(identifier: "UTC")
        return f
    }()

    static func info(_ label: String, _ message: String) {
        let ts = formatter.string(from: Date())
        fputs("\(ts) [\(label)] \(message)\n", stderr)
    }

    /// Verbose events (per-flow accept, per-chunk counters, etc.) that
    /// only make sense when SAFEYOLO_VM_DEBUG=1.
    static func debug(_ label: String, _ message: String) {
        guard debugEnabled else { return }
        let ts = formatter.string(from: Date())
        fputs("\(ts) [\(label)] DEBUG \(message)\n", stderr)
    }

    static func warn(_ label: String, _ message: String) {
        let ts = formatter.string(from: Date())
        fputs("\(ts) [\(label)] WARN \(message)\n", stderr)
    }
}
