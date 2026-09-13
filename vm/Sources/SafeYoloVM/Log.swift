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
    private static let relayWriter = RelayLogWriter()

    /// A blocked log recipient must not stall socket pumps or their cleanup.
    static func relay(_ label: String, _ message: String) {
        relayWriter.append(label: label, message: message)
    }

    static var droppedRelayMessages: UInt64 { relayWriter.droppedCount }

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

/// Bounded diagnostic buffering on a dedicated thread. It holds no relay or VM
/// state while writing. Drops are counted and reported when the recipient resumes.
private final class RelayLogWriter {
    private let condition = NSCondition()
    private var pending: [(Date, String, String)] = []
    private var dropped: UInt64 = 0
    private var unreportedDrops: UInt64 = 0
    private var started = false

    var droppedCount: UInt64 {
        condition.lock(); defer { condition.unlock() }; return dropped
    }

    func append(label: String, message: String) {
        condition.lock()
        if !started {
            started = true
            let thread = Thread { [self] in run() }
            thread.name = "safeyolo.relay.log"
            thread.start()
        }
        if pending.count < 1024 { pending.append((Date(), label, message)) }
        else { dropped += 1; unreportedDrops += 1 }
        condition.signal(); condition.unlock()
    }

    private func run() {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        formatter.timeZone = TimeZone(identifier: "UTC")
        while true {
            condition.lock()
            while pending.isEmpty { condition.wait() }
            let batch = pending; pending.removeAll(keepingCapacity: true)
            let lost = unreportedDrops; unreportedDrops = 0
            condition.unlock()
            if lost > 0 { write("[relay-log] dropped=\(lost) (recipient was slower than relay completions)\n") }
            for (date, label, message) in batch {
                write("\(formatter.string(from: date)) [\(label)] \(message)\n")
            }
        }
    }

    private func write(_ message: String) {
        // Avoid stdio's shared lock while the recipient is blocked.
        let bytes = Array(message.utf8)
        bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(STDERR_FILENO, buffer.baseAddress! + offset, buffer.count - offset)
                if count > 0 { offset += count }
                else if count < 0 && errno == EINTR { continue }
                else { break }
            }
        }
    }
}
