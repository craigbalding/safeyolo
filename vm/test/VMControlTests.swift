import Foundation
import Darwin

let helperVersion = "control-test"

@main
struct VMControlTests {
    static func wait(_ description: String, _ predicate: () -> Bool) {
        let deadline = ProcessInfo.processInfo.systemUptime + 3
        while !predicate() {
            precondition(ProcessInfo.processInfo.systemUptime < deadline, description)
            usleep(1000)
        }
    }

    static func connect(_ path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        precondition(fd >= 0)
        var timeout = timeval(tv_sec: 3, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout)))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout)))
        var address = try RelaySocket.address(path)
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        precondition(result == 0, "control connect errno=\(errno)")
        return fd
    }

    static func request(_ path: String, _ value: [String: Any]) throws -> [String: Any] {
        let fd = try connect(path)
        defer { Darwin.close(fd) }
        var data = try JSONSerialization.data(withJSONObject: value)
        data.append(10)
        precondition(data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!, $0.count) } == data.count)
        var response = Data()
        var buffer = [UInt8](repeating: 0, count: 16384)
        while response.last != 10 {
            let count = Darwin.read(fd, &buffer, buffer.count)
            precondition(count > 0 && response.count < 2 * 1024 * 1024, "bounded control response")
            response.append(contentsOf: buffer.prefix(count))
        }
        return try JSONSerialization.jsonObject(with: response) as! [String: Any]
    }

    static func pair() -> (RelayEndpoint, Int32) {
        var fds: [Int32] = [-1, -1]
        precondition(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        return (RelayEndpoint(fd: fds[0]), fds[1])
    }

    static func main() throws {
        signal(SIGPIPE, SIG_IGN)
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("control-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let path = folder.appendingPathComponent("c.sock").path
        let ledger = RelayLedger()
        let runtime = VMRuntimeStatus()
        runtime.refreshed(state: "running")
        let proxy = try SocketRelayLoop(kind: "proxy", ledger: ledger)
        let shell = try SocketRelayLoop(kind: "shell", ledger: ledger)
        let control = try VMControl(path: path, ledger: ledger, runtime: runtime,
            refreshVM: {}, wakeRelays: { proxy.wake(); shell.wake() })
        control.start()
        var peerFDs: [Int32] = []
        var ids: [UInt64] = []
        for index in 0..<3 {
            let (endpoint, peer) = pair()
            peerFDs.append(peer)
            ids.append((index == 2 ? shell : proxy).accept(endpoint))
        }

        // Deliberately do not start the relay threads. Ownership is registered,
        // but none of their work can execute. Control must still reply promptly.
        let stalledClient = try connect(path)
        var brace: UInt8 = 123
        precondition(Darwin.write(stalledClient, &brace, 1) == 1)
        let started = ProcessInfo.processInfo.systemUptime
        let status = try request(path, ["operation": "status"])
        precondition(ProcessInfo.processInfo.systemUptime - started < 0.5)
        precondition(status["active"] as? Int == 3)
        precondition(status["relay_fd_count"] as? Int == 3)
        precondition(status["accepted_shell_pending"] as? Int == 1)
        precondition(status["health"] as? String == "relay_executor_not_progressing")
        let dump = try request(path, ["operation": "dump"])
        precondition((dump["oldest_relays"] as? [[String: Any]])?.count == 3)
        precondition(dump["relays_truncated"] as? Bool == false)
        precondition((dump["control_events"] as? [[String: Any]])?.count == 2)
        print("PASS status and hang dump while relay executors cannot run and another client stalls")

        let page = try request(path, ["operation": "relays", "limit": 1])
        precondition((page["relays"] as? [[String: Any]])?.count == 1)
        precondition(page["next_after"] as? Int == Int(ids[0]))
        let bad = try request(path, ["operation": "cancel", "instance": "old", "ids": ids])
        precondition(bad["ok"] as? Bool == false)
        let malformed = try request(path, ["operation": "cancel", "instance": control.instance, "ids": [true]])
        precondition(malformed["ok"] as? Bool == false)
        precondition(!FileManager.default.fileExists(atPath: path + ".audit.jsonl"))
        precondition(ledger.snapshot().active.count == 3)
        do {
            _ = try VMControl(path: path, ledger: ledger, runtime: runtime, refreshVM: {}, wakeRelays: {})
            preconditionFailure("live control path was replaced")
        } catch { /* Correct: another helper must not steal this path. */ }

        let cancelled = try request(path, ["operation": "cancel", "instance": control.instance,
            "ids": ids, "reason": "test deliberately unscheduled relays"])
        precondition(cancelled["closed"] as? Bool == false)
        precondition(cancelled["queued_ids"] as? [UInt64] == ids)
        precondition(ledger.snapshot().active.count == 3, "queued cancellation reported completion prematurely")
        proxy.start(); shell.start()
        wait("cancelled relays released after their owners run") { ledger.snapshot().active.isEmpty }
        var byte: UInt8 = 0
        for fd in peerFDs { precondition(Darwin.read(fd, &byte, 1) == 0); Darwin.close(fd) }
        let audit = try String(contentsOfFile: path + ".audit.jsonl", encoding: .utf8)
        let event = try JSONSerialization.jsonObject(with: Data(audit.utf8)) as! [String: Any]
        precondition(event["instance"] as? String == control.instance)
        precondition(event["ids"] as? [UInt64] == ids)
        precondition(event["uid"] as? UInt32 == geteuid())
        var auditInfo = stat()
        precondition(lstat(path + ".audit.jsonl", &auditInfo) == 0 && auditInfo.st_mode & 0o777 == 0o600)
        print("PASS paging, stale-instance refusal, live-path ownership and audited cancellation")

        // The first partial request expires independently of all other clients.
        precondition(Darwin.read(stalledClient, &byte, 1) == 0)
        Darwin.close(stalledClient)
        let final = try request(path, ["operation": "status"])
        precondition(final["active"] as? Int == 0 && final["relay_fd_count"] as? Int == 0)
        precondition((final["vm"] as? [String: Any])?["state"] as? String == "running")
        proxy.stop(); shell.stop(); control.stop()
        wait("relay threads stop") { proxy.isStopped && shell.isStopped }
        wait("control listener removed") { !FileManager.default.fileExists(atPath: path) }
        print("PASS control client deadline, relay FD baseline and control shutdown")
    }
}
