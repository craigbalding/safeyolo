import Foundation
import Darwin

/// One newline-delimited JSON request and response per private host connection.
/// This thread never waits for a VM/relay executor or uses the global GCD pool.
final class VMControl {
    private struct Request: Decodable {
        let operation: String
        let instance: String?
        let ids: [UInt64]?
        let after: UInt64?
        let limit: Int?
        let reason: String?
    }

    private final class Client {
        let endpoint: RelayEndpoint
        let uid: uid_t
        let accepted = ProcessInfo.processInfo.systemUptime
        var input = Data()
        var output = Data()
        var answered = false
        init(endpoint: RelayEndpoint, uid: uid_t) { self.endpoint = endpoint; self.uid = uid }
    }

    let instance = UUID().uuidString
    let startedAt = Date().timeIntervalSince1970
    private let startedUptime = ProcessInfo.processInfo.systemUptime
    private let path: String
    private let listener: RelayEndpoint
    private let pathLock: RelayEndpoint
    private let ledger: RelayLedger
    private let runtime: VMRuntimeStatus
    private let refreshVM: () -> Void
    private let wakeRelays: () -> Void
    private var clients: [Int32: Client] = [:]
    private var nextRefresh = 0.0
    private var recentEvents: [[String: Any]] = []
    private var stalledLoops: Set<String> = []
    private let stopLock = NSLock()
    private var stopping = false

    init(path: String, ledger: RelayLedger, runtime: VMRuntimeStatus,
         refreshVM: @escaping () -> Void, wakeRelays: @escaping () -> Void) throws {
        self.path = path; self.ledger = ledger; self.runtime = runtime
        self.refreshVM = refreshVM; self.wakeRelays = wakeRelays
        let lockFD = open(path + ".lock", O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard lockFD >= 0 else { throw RelaySocket.posix("open control lock") }
        pathLock = RelayEndpoint(fd: lockFD)
        var info = stat()
        guard fstat(lockFD, &info) == 0, info.st_uid == geteuid(),
              info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o077 == 0 else {
            throw NSError(domain: "VMControl", code: 1, userInfo: [NSLocalizedDescriptionKey: "control lock must be an owned private regular file"])
        }
        guard flock(lockFD, LOCK_EX | LOCK_NB) == 0 else { throw RelaySocket.posix("control already owned by another helper") }
        listener = try RelaySocket.socket()
        try Self.removeStaleSocket(path)
        var address = try RelaySocket.address(path)
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listener.fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else { throw RelaySocket.posix("control bind") }
        guard chmod(path, 0o600) == 0, Darwin.listen(listener.fd, 32) == 0 else {
            throw RelaySocket.posix("control listen")
        }
    }

    private static func removeStaleSocket(_ path: String) throws {
        var info = stat()
        if lstat(path, &info) != 0 {
            if errno == ENOENT { return }
            throw RelaySocket.posix("control path stat")
        }
        guard info.st_mode & S_IFMT == S_IFSOCK, info.st_uid == geteuid() else {
            throw NSError(domain: "VMControl", code: 1, userInfo: [NSLocalizedDescriptionKey: "control path is not an owned socket"])
        }
        let probe = try RelaySocket.socket()
        var address = try RelaySocket.address(path)
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(probe.fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result != 0, errno == ECONNREFUSED else {
            throw NSError(domain: "VMControl", code: 2, userInfo: [NSLocalizedDescriptionKey: "control socket already has a listener or cannot be safely replaced"])
        }
        guard unlink(path) == 0 else { throw RelaySocket.posix("remove stale control socket") }
    }

    func start() {
        let thread = Thread { [self] in run() }
        thread.name = "safeyolo.vm.control"
        thread.start()
    }

    func stop() { stopLock.lock(); stopping = true; stopLock.unlock() }

    private func shouldStop() -> Bool { stopLock.lock(); defer { stopLock.unlock() }; return stopping }

    private func run() {
        while !shouldStop() {
            let now = ProcessInfo.processInfo.systemUptime
            if now >= nextRefresh {
                refreshVM(); monitorRelays(now: now); nextRefresh = now + 0.5
            }
            for (fd, client) in clients where now - client.accepted >= 2 { client.endpoint.close(); clients.removeValue(forKey: fd) }
            var descriptors = [pollfd(fd: listener.fd, events: Int16(POLLIN), revents: 0)]
            for client in clients.values {
                descriptors.append(pollfd(fd: client.endpoint.fd, events: Int16(client.answered ? POLLOUT : POLLIN), revents: 0))
            }
            if poll(&descriptors, nfds_t(descriptors.count), 100) < 0 {
                if errno == EINTR { continue }
                event("control_poll_error", detail: RelaySocket.posix("poll").localizedDescription); break
            }
            for descriptor in descriptors where descriptor.revents != 0 {
                if descriptor.fd == listener.fd { acceptReady(); continue }
                guard let client = clients[descriptor.fd] else { continue }
                if descriptor.revents & Int16(POLLERR | POLLNVAL) != 0 { close(client); continue }
                if client.answered { writeReady(client) } else { readReady(client) }
            }
        }
        for client in clients.values { client.endpoint.close() }
        clients.removeAll(); listener.close()
        unlink(path)
        pathLock.close()
    }

    private func close(_ client: Client) { clients.removeValue(forKey: client.endpoint.fd); client.endpoint.close() }

    private func acceptReady() {
        for _ in 0..<32 {
            let fd = Darwin.accept(listener.fd, nil, nil)
            if fd < 0 { return }
            let endpoint = RelayEndpoint(fd: fd)
            do {
                try RelaySocket.nonblocking(fd)
                var uid: uid_t = 0; var gid: gid_t = 0
                guard getpeereid(fd, &uid, &gid) == 0, uid == geteuid() || uid == 0 else { endpoint.close(); continue }
                clients[fd] = Client(endpoint: endpoint, uid: uid)
            } catch { endpoint.close() }
        }
    }

    private func readReady(_ client: Client) {
        var bytes = [UInt8](repeating: 0, count: 4096)
        let count = Darwin.read(client.endpoint.fd, &bytes, bytes.count)
        if count < 0 {
            if errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK { close(client) }
            return
        }
        if count == 0 { close(client); return }
        client.input.append(contentsOf: bytes.prefix(count))
        if client.input.count > 65536 { respond(client, error: "control request exceeds 64 KiB"); return }
        guard let newline = client.input.firstIndex(of: 10) else { return }
        do {
            let request = try JSONDecoder().decode(Request.self, from: client.input.prefix(upTo: newline))
            let response = try execute(request, uid: client.uid)
            respond(client, payload: response)
        } catch { respond(client, error: error.localizedDescription) }
    }

    private func respond(_ client: Client, payload: [String: Any] = [:], error: String? = nil) {
        var response = payload
        response["schema_version"] = 1; response["instance"] = instance
        response["ok"] = error == nil
        if let error { response["error"] = error }
        do { client.output = try JSONSerialization.data(withJSONObject: response, options: [.sortedKeys]) }
        catch { client.output = Data("{\"ok\":false,\"error\":\"encoding failure\"}".utf8) }
        client.output.append(10); client.answered = true; client.input.removeAll()
    }

    private func writeReady(_ client: Client) {
        let count = client.output.withUnsafeBytes { Darwin.write(client.endpoint.fd, $0.baseAddress!, $0.count) }
        if count > 0 {
            client.output.removeFirst(count)
            if client.output.isEmpty { close(client) }
        } else if count < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK { close(client) }
    }

    private func object<T: Encodable>(_ value: T) throws -> Any {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        return try JSONSerialization.jsonObject(with: encoder.encode(value))
    }

    private func execute(_ request: Request, uid: uid_t) throws -> [String: Any] {
        switch request.operation {
        case "status": return try status()
        case "relays":
            let records = ledger.snapshot().active.sorted { $0.id < $1.id }
            let limit = request.limit ?? 128
            guard (1...256).contains(limit) else { throw invalid("page limit must be 1...256") }
            let page = Array(records.filter { $0.id > (request.after ?? 0) }.prefix(limit))
            let more = records.contains { $0.id > (page.last?.id ?? request.after ?? 0) }
            return ["relays": try object(page), "total": records.count,
                    "next_after": more ? (page.last?.id as Any? ?? NSNull()) : NSNull()]
        case "dump":
            event("hang_dump_requested", detail: "uid=\(uid)")
            var dump = try status()
            let active = ledger.snapshot().active.sorted { $0.acceptedAt < $1.acceptedAt }
            dump["oldest_relays"] = try object(Array(active.prefix(256)))
            dump["relays_truncated"] = active.count > 256
            dump["recent_relays"] = try object(ledger.snapshot().recent)
            event("hang_dump_completed", detail: "uid=\(uid)")
            dump["control_events"] = recentEvents
            return dump
        case "cancel":
            guard request.instance == instance else { throw invalid("helper instance changed; list relays again") }
            guard let ids = request.ids, !ids.isEmpty else { throw invalid("cancel requires explicit flow IDs") }
            let reason = request.reason ?? "operator request"
            guard reason.utf8.count <= 1024 else { throw invalid("cancellation reason exceeds 1024 bytes") }
            let active = Set(ledger.snapshot().active.map(\.id))
            let selected = Array(Set(ids).intersection(active)).sorted()
            let action = UUID().uuidString
            try audit(["event": "relay_cancel_requested", "action_id": action,
                       "instance": instance, "uid": uid, "helper_pid": getpid(),
                       "ids": selected, "reason": reason, "time": Date().timeIntervalSince1970])
            let queued = ledger.cancel(ids: selected)
            wakeRelays()
            event("relay_cancel_requested", detail: "action=\(action) uid=\(uid) count=\(queued.count)")
            return ["action_id": action, "queued_ids": queued, "closed": false,
                    "message": "cancellation queued; observe relay removal to confirm closure"]
        default: throw invalid("unknown control operation")
        }
    }

    private func status() throws -> [String: Any] {
        let now = ProcessInfo.processInfo.systemUptime
        let snapshot = ledger.snapshot()
        let loops = ledger.loopStatuses()
        var counts: [String: Int] = [:]
        var phases: [String: Int] = [:]
        for record in snapshot.active {
            counts[record.kind, default: 0] += 1; phases[record.phase, default: 0] += 1
        }
        let unhealthy = loops.filter { $0.state != "running" || now - $0.lastTurn > 1 }
        let queuedShell = snapshot.active.filter { $0.kind == "shell" && $0.phase == "accepted" }
        let agent = ((path as NSString).lastPathComponent as NSString).deletingPathExtension
        return ["agent": agent, "helper": BuildIdentity.current, "pid": getpid(), "started_at": startedAt,
                "uptime_seconds": now - startedUptime, "monotonic_now": now,
                "vm": runtime.snapshot(), "loops": try object(loops),
                "counts_by_kind": counts, "counts_by_phase": phases,
                "accepted": snapshot.accepted, "completed": snapshot.completed,
                "failed": snapshot.failed, "high_water": snapshot.highWater,
                "active": snapshot.active.count, "relay_fd_count": snapshot.active.reduce(0) { $0 + ($1.incomingFD >= 0 ? 1 : 0) + ($1.outgoingFD == nil ? 0 : 1) },
                "control_client_count": clients.count,
                "control_owned_fd_count": clients.count + 2,
                "accepted_shell_pending": queuedShell.count,
                "oldest_active_age_seconds": snapshot.active.map { now - $0.acceptedAt }.max() ?? 0,
                "relay_log_messages_dropped": Log.droppedRelayMessages,
                "health": unhealthy.isEmpty ? "responsive" : "relay_executor_not_progressing",
                "unresponsive_loops": unhealthy.map(\.kind),
                "recent_errors": try object(snapshot.recent.filter { $0.error != nil })]
    }

    private func event(_ name: String, detail: String) {
        recentEvents.append(["event": name, "detail": detail, "time": Date().timeIntervalSince1970])
        if recentEvents.count > 64 { recentEvents.removeFirst(recentEvents.count - 64) }
    }

    private func monitorRelays(now: Double) {
        let stalled = Set(ledger.loopStatuses().filter {
            $0.state == "stopped" || now - $0.lastTurn > 1
        }.map(\.kind))
        if stalled == stalledLoops { return }
        let name = stalled.isEmpty ? "relay_executor_recovered" : "relay_executor_not_progressing"
        let detail = "loops=\(stalled.sorted().joined(separator: ","))"
        event(name, detail: detail)
        Log.relay("vm-control", "event=\(name) \(detail)")
        stalledLoops = stalled
    }

    private func audit(_ value: [String: Any]) throws {
        var bytes = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        bytes.append(10)
        let fd = open(path + ".audit.jsonl", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw RelaySocket.posix("open cancellation audit") }
        defer { Darwin.close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else {
            throw invalid("cancellation audit must be an operator-owned private regular file")
        }
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(fd, buffer.baseAddress! + offset, buffer.count - offset)
                if count > 0 { offset += count }
                else if count < 0 && errno == EINTR { continue }
                else { throw RelaySocket.posix("write cancellation audit") }
            }
        }
    }

    private func invalid(_ message: String) -> NSError {
        NSError(domain: "VMControl", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
