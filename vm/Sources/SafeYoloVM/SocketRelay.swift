import Foundation
import Darwin

/// A socket is closed by its owner exactly once. VZ endpoints supply the
/// framework's close method; their borrowed file descriptor is never closed
/// directly by the relay. The closure also retains the VZ connection.
final class RelayEndpoint {
    let fd: Int32
    private var release: (() -> Void)?

    init(fd: Int32, release: (() -> Void)? = nil) {
        self.fd = fd
        self.release = release ?? { Darwin.close(fd) }
    }

    func close() {
        guard let release else { return }
        self.release = nil
        release()
    }

    deinit { close() }
}

struct RelayRecord: Codable {
    let id: UInt64
    let kind: String
    let acceptedAt: Double
    var phase = "accepted"
    var bytesIn: UInt64 = 0
    var bytesOut: UInt64 = 0
    var bufferedIn = 0
    var bufferedOut = 0
    var lastProgress: Double
    var error: String? = nil
}

/// Short, data-only critical sections. Diagnostics never synchronously query a
/// VM queue or a relay thread. Accepted sockets appear here before scheduling.
final class RelayLedger {
    private let lock = NSLock()
    private var sequence: UInt64 = 0
    private var active: [UInt64: RelayRecord] = [:]
    private var cancelled: Set<UInt64> = []
    private var recent: [RelayRecord] = []
    private var completed: UInt64 = 0
    private var failed: UInt64 = 0
    private var highWater = 0

    func accept(kind: String) -> RelayRecord {
        lock.lock(); defer { lock.unlock() }
        sequence += 1
        let now = ProcessInfo.processInfo.systemUptime
        let record = RelayRecord(id: sequence, kind: kind, acceptedAt: now, lastProgress: now)
        active[record.id] = record
        highWater = max(highWater, active.count)
        return record
    }

    func update(_ record: RelayRecord) {
        lock.lock(); defer { lock.unlock() }
        if active[record.id] != nil { active[record.id] = record }
    }

    func finish(_ record: RelayRecord) {
        lock.lock(); defer { lock.unlock() }
        guard active.removeValue(forKey: record.id) != nil else { return }
        cancelled.remove(record.id)
        completed += 1
        if record.error != nil { failed += 1 }
        recent.append(record)
        if recent.count > 64 { recent.removeFirst(recent.count - 64) }
    }

    @discardableResult
    func cancel(ids: [UInt64]) -> [UInt64] {
        lock.lock(); defer { lock.unlock() }
        let found = ids.filter { active[$0] != nil }
        cancelled.formUnion(found)
        return found
    }

    func isCancelled(_ id: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return cancelled.contains(id)
    }

    func snapshot() -> (active: [RelayRecord], recent: [RelayRecord], accepted: UInt64,
                        completed: UInt64, failed: UInt64, highWater: Int) {
        lock.lock(); defer { lock.unlock() }
        return (Array(active.values), recent, sequence, completed, failed, highWater)
    }
}

enum RelaySocket {
    static func nonblocking(_ fd: Int32) throws {
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
              fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw posix("fcntl") }
        var one: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout.size(ofValue: one))) == 0 else {
            throw posix("SO_NOSIGPIPE")
        }
    }

    static func address(_ path: String) throws -> sockaddr_un {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = path.utf8CString
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard bytes.count <= capacity else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(ENAMETOOLONG))
        }
        withUnsafeMutablePointer(to: &address.sun_path) {
            $0.withMemoryRebound(to: CChar.self, capacity: capacity) { target in
                bytes.withUnsafeBufferPointer { target.update(from: $0.baseAddress!, count: bytes.count) }
            }
        }
        return address
    }

    static func posix(_ operation: String) -> NSError {
        let code = errno
        return NSError(domain: NSPOSIXErrorDomain, code: Int(code), userInfo: [
            NSLocalizedDescriptionKey: "\(operation): \(String(cString: strerror(code)))"
        ])
    }

    static func socket() throws -> RelayEndpoint {
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw posix("socket") }
        let endpoint = RelayEndpoint(fd: fd)
        try nonblocking(fd)
        return endpoint
    }
}

/// One nonblocking poll thread per traffic class. No flow holds a worker while
/// waiting for another worker, and no long-lived read consumes a GCD thread.
final class SocketRelayLoop {
    private final class Flow {
        var record: RelayRecord
        let incoming: RelayEndpoint
        var outgoing: RelayEndpoint?
        var connecting = false
        var incomingEOF = false
        var outgoingEOF = false
        var incomingWriteClosed = false
        var outgoingWriteClosed = false
        var toOutgoing = Data()
        var toIncoming = Data()
        var finished = false

        init(record: RelayRecord, incoming: RelayEndpoint) {
            self.record = record; self.incoming = incoming
        }
    }

    private enum Command {
        case accept(Flow, String?)
        case connected(UInt64, RelayEndpoint?, String?)
    }

    let kind: String
    let ledger: RelayLedger
    private let establishmentTimeout: Double
    private let drainTimeout: Double
    private let commandLock = NSLock()
    private var commands: [Command] = []
    private var stopping = false
    private var stopped = false
    private var wakeRead: Int32 = -1
    private var wakeWrite: Int32 = -1
    private var thread: Thread?
    private var flows: [UInt64: Flow] = [:] // Relay thread only from here down.
    private var listener: RelayEndpoint?
    private var acceptRetryAt = 0.0
    private var onAccept: ((UInt64) -> Void)?
    private var scratch = [UInt8](repeating: 0, count: 65536)

    deinit {
        if wakeRead >= 0 { Darwin.close(wakeRead) }
        if wakeWrite >= 0 { Darwin.close(wakeWrite) }
    }

    init(kind: String, ledger: RelayLedger, establishmentTimeout: Double = 10,
         drainTimeout: Double = 10) throws {
        self.kind = kind; self.ledger = ledger
        self.establishmentTimeout = establishmentTimeout; self.drainTimeout = drainTimeout
        var pipeFDs: [Int32] = [-1, -1]
        guard pipe(&pipeFDs) == 0 else { throw RelaySocket.posix("wake pipe") }
        wakeRead = pipeFDs[0]; wakeWrite = pipeFDs[1]
        for fd in pipeFDs {
            guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0, fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else {
                let error = RelaySocket.posix("wake pipe fcntl")
                Darwin.close(wakeRead); Darwin.close(wakeWrite)
                wakeRead = -1; wakeWrite = -1
                throw error
            }
        }
    }

    /// Configure a shell listener before starting its thread.
    func listen(path: String, onAccept: @escaping (UInt64) -> Void) throws {
        let endpoint = try RelaySocket.socket()
        var address = try RelaySocket.address(path)
        // Caller owns the private per-agent path; preserve existing stale-path cleanup.
        unlink(path)
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(endpoint.fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else { throw RelaySocket.posix("bind") }
        guard chmod(path, 0o600) == 0, Darwin.listen(endpoint.fd, 128) == 0 else {
            throw RelaySocket.posix("listen")
        }
        listener = endpoint; self.onAccept = onAccept
    }

    func start() {
        thread = Thread { [self] in run() }
        thread?.name = "safeyolo.\(kind).relay"
        thread?.start()
    }

    @discardableResult
    func accept(_ incoming: RelayEndpoint, unixPath: String? = nil) -> UInt64 {
        let record = ledger.accept(kind: kind)
        let flow = Flow(record: record, incoming: incoming)
        commandLock.lock()
        if stopping {
            commandLock.unlock()
            incoming.close(); flow.record.phase = "closed"; flow.record.error = "relay stopped"
            ledger.finish(flow.record)
        } else {
            commands.append(.accept(flow, unixPath)); wakeLocked(); commandLock.unlock()
        }
        return record.id
    }

    func connected(id: UInt64, endpoint: RelayEndpoint?, error: String? = nil) {
        commandLock.lock()
        if stopping {
            commandLock.unlock(); endpoint?.close()
        } else {
            commands.append(.connected(id, endpoint, error)); wakeLocked(); commandLock.unlock()
        }
    }

    func wake() {
        commandLock.lock(); defer { commandLock.unlock() }
        if wakeWrite >= 0 { wakeLocked() }
    }

    func stop() {
        commandLock.lock(); defer { commandLock.unlock() }
        stopping = true
        if wakeWrite >= 0 { wakeLocked() }
    }

    var isStopped: Bool {
        commandLock.lock(); defer { commandLock.unlock() }; return stopped
    }

    private func wakeLocked() {
        var byte: UInt8 = 1
        _ = Darwin.write(wakeWrite, &byte, 1) // EAGAIN means a wake is already pending.
    }

    private func close(_ flow: Flow, error: String? = nil) {
        guard !flow.finished else { return }
        flow.finished = true
        if error != nil {
            shutdown(flow.incoming.fd, SHUT_RDWR)
            if let outgoing = flow.outgoing { shutdown(outgoing.fd, SHUT_RDWR) }
        }
        flow.incoming.close(); flow.outgoing?.close()
        flow.toIncoming.removeAll(); flow.toOutgoing.removeAll()
        flow.record.phase = "closed"; flow.record.error = error
        flow.record.bufferedIn = 0; flow.record.bufferedOut = 0
        ledger.finish(flow.record)
        Log.relay("\(kind)-relay", "done flow=\(flow.record.id) bytes_in=\(flow.record.bytesIn) bytes_out=\(flow.record.bytesOut) error=\(error ?? "none")")
    }

    private func receiveCommands() -> Bool {
        commandLock.lock()
        let pending = commands; commands.removeAll(keepingCapacity: true)
        let shouldStop = stopping
        commandLock.unlock()
        for command in pending {
            switch command {
            case .accept(let flow, let unixPath):
                flows[flow.record.id] = flow
                if ProcessInfo.processInfo.systemUptime - flow.record.acceptedAt >= establishmentTimeout {
                    close(flow, error: "relay establishment timed out"); continue
                }
                do {
                    try RelaySocket.nonblocking(flow.incoming.fd)
                    flow.record.phase = "connecting"
                    if let unixPath { try connectUnix(flow, path: unixPath) }
                } catch { close(flow, error: error.localizedDescription) }
            case .connected(let id, let endpoint, let error):
                guard let flow = flows[id], !flow.finished else { endpoint?.close(); continue }
                if ProcessInfo.processInfo.systemUptime - flow.record.acceptedAt >= establishmentTimeout {
                    endpoint?.close(); close(flow, error: "relay establishment timed out"); continue
                }
                guard let endpoint else { close(flow, error: error ?? "vsock connection failed"); continue }
                flow.outgoing = endpoint
                do {
                    try RelaySocket.nonblocking(endpoint.fd)
                    flow.record.phase = "active"
                    flow.record.lastProgress = ProcessInfo.processInfo.systemUptime
                } catch { close(flow, error: error.localizedDescription) }
            }
        }
        return shouldStop
    }

    private func connectUnix(_ flow: Flow, path: String) throws {
        let endpoint = try RelaySocket.socket()
        flow.outgoing = endpoint
        var address = try RelaySocket.address(path)
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(endpoint.fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if result == 0 {
            flow.record.phase = "active"
        } else if errno == EINPROGRESS {
            flow.connecting = true
        } else {
            throw RelaySocket.posix("upstream connect")
        }
    }

    private func finishConnect(_ flow: Flow) {
        guard let outgoing = flow.outgoing else { return }
        var code: Int32 = 0
        var size = socklen_t(MemoryLayout.size(ofValue: code))
        if getsockopt(outgoing.fd, SOL_SOCKET, SO_ERROR, &code, &size) != 0 {
            close(flow, error: RelaySocket.posix("connect status").localizedDescription)
        } else if code != 0 {
            close(flow, error: "upstream connect: \(String(cString: strerror(code)))")
        } else {
            flow.connecting = false; flow.record.phase = "active"
            flow.record.lastProgress = ProcessInfo.processInfo.systemUptime
        }
    }

    private func acceptReady() {
        guard let listener else { return }
        // Bound each turn so an accept burst cannot postpone existing relays.
        for _ in 0..<64 {
            let fd = Darwin.accept(listener.fd, nil, nil)
            if fd < 0 {
                if errno == EINTR { continue }
                if errno != EAGAIN && errno != EWOULDBLOCK {
                    acceptRetryAt = ProcessInfo.processInfo.systemUptime + 0.1
                    Log.relay(kind, RelaySocket.posix("accept").localizedDescription)
                }
                break
            }
            let id = accept(RelayEndpoint(fd: fd))
            onAccept?(id)
        }
    }

    private func events(_ flow: Flow, incoming: Bool) -> Int16 {
        if !incoming && flow.connecting { return Int16(POLLOUT) }
        var result: Int16 = 0
        let eof = incoming ? flow.incomingEOF : flow.outgoingEOF
        let readBuffer = incoming ? flow.toOutgoing.count : flow.toIncoming.count
        let writeBuffer = incoming ? flow.toIncoming.count : flow.toOutgoing.count
        if !eof && readBuffer < 65536 { result |= Int16(POLLIN) }
        if writeBuffer > 0 { result |= Int16(POLLOUT) }
        return result
    }

    private func transfer(_ flow: Flow, incoming: Bool, events: Int16) {
        guard !flow.finished, let endpoint = incoming ? flow.incoming : flow.outgoing else { return }
        if events & Int16(POLLNVAL) != 0 { close(flow, error: "invalid relay descriptor"); return }
        if !incoming && flow.connecting {
            if events != 0 { finishConnect(flow) }
            return
        }
        if events & Int16(POLLOUT) != 0 {
            let buffer = incoming ? flow.toIncoming : flow.toOutgoing
            if !buffer.isEmpty {
                let n = buffer.withUnsafeBytes { Darwin.write(endpoint.fd, $0.baseAddress!, $0.count) }
                if n > 0 {
                    if incoming { flow.toIncoming.removeFirst(n); flow.record.bytesOut += UInt64(n) }
                    else { flow.toOutgoing.removeFirst(n); flow.record.bytesIn += UInt64(n) }
                    flow.record.lastProgress = ProcessInfo.processInfo.systemUptime
                } else if n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK {
                    close(flow, error: RelaySocket.posix("write").localizedDescription); return
                }
            }
        }
        let eof = incoming ? flow.incomingEOF : flow.outgoingEOF
        let available = 65536 - (incoming ? flow.toOutgoing.count : flow.toIncoming.count)
        if !eof && available > 0 && events & Int16(POLLIN | POLLHUP | POLLERR) != 0 {
            let n = Darwin.read(endpoint.fd, &scratch, available)
            if n > 0 {
                if incoming { flow.toOutgoing.append(contentsOf: scratch.prefix(n)) }
                else { flow.toIncoming.append(contentsOf: scratch.prefix(n)) }
                flow.record.lastProgress = ProcessInfo.processInfo.systemUptime
            } else if n == 0 {
                if incoming { flow.incomingEOF = true } else { flow.outgoingEOF = true }
                flow.record.lastProgress = ProcessInfo.processInfo.systemUptime
            } else if errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK {
                close(flow, error: RelaySocket.posix("read").localizedDescription)
            }
        }
    }

    private func advance(_ flow: Flow, now: Double) {
        guard !flow.finished else { return }
        if ledger.isCancelled(flow.record.id) { close(flow, error: "cancelled"); return }
        if flow.outgoing == nil || flow.connecting {
            if now - flow.record.acceptedAt >= establishmentTimeout {
                close(flow, error: "relay establishment timed out")
            }
        } else {
            if flow.incomingEOF && flow.toOutgoing.isEmpty && !flow.outgoingWriteClosed {
                shutdown(flow.outgoing!.fd, SHUT_WR); flow.outgoingWriteClosed = true
            }
            if flow.outgoingEOF && flow.toIncoming.isEmpty && !flow.incomingWriteClosed {
                shutdown(flow.incoming.fd, SHUT_WR); flow.incomingWriteClosed = true
            }
            if flow.incomingEOF && flow.outgoingEOF {
                flow.record.phase = "draining"
                if flow.toIncoming.isEmpty && flow.toOutgoing.isEmpty { close(flow); return }
                if now - flow.record.lastProgress >= drainTimeout { close(flow, error: "relay drain timed out"); return }
            } else if flow.incomingEOF || flow.outgoingEOF {
                // A legitimate half-closed stream may still await a response.
                // Do not impose an idle/lifetime limit on that live direction.
                flow.record.phase = "half_closed"
            }
        }
        flow.record.bufferedIn = flow.toOutgoing.count
        flow.record.bufferedOut = flow.toIncoming.count
        ledger.update(flow.record)
    }

    private func run() {
        while true {
            if receiveCommands() { break }
            let now = ProcessInfo.processInfo.systemUptime
            for flow in flows.values { advance(flow, now: now) }
            flows = flows.filter { !$0.value.finished }
            var descriptors = [pollfd(fd: wakeRead, events: Int16(POLLIN), revents: 0)]
            var owners: [(Flow?, Bool)] = [(nil, false)]
            if let listener, now >= acceptRetryAt {
                descriptors.append(pollfd(fd: listener.fd, events: Int16(POLLIN), revents: 0))
                owners.append((nil, true))
            }
            for flow in flows.values {
                for incoming in [true, false] {
                    guard let endpoint = incoming ? flow.incoming : flow.outgoing else { continue }
                    let interest = events(flow, incoming: incoming)
                    if interest == 0 { continue } // Do not spin on a consumed EOF/HUP.
                    descriptors.append(pollfd(fd: endpoint.fd, events: interest, revents: 0))
                    owners.append((flow, incoming))
                }
            }
            let result = poll(&descriptors, nfds_t(descriptors.count), 100)
            if result < 0 {
                if errno == EINTR { continue }
                Log.warn(kind, RelaySocket.posix("poll").localizedDescription); break
            }
            for i in descriptors.indices where descriptors[i].revents != 0 {
                if i == 0 {
                    while Darwin.read(wakeRead, &scratch, scratch.count) > 0 {}
                } else if let flow = owners[i].0 {
                    transfer(flow, incoming: owners[i].1, events: descriptors[i].revents)
                } else { acceptReady() }
            }
        }
        for flow in flows.values { close(flow, error: "relay stopped") }
        flows.removeAll(); listener?.close(); listener = nil
        commandLock.lock()
        // A failed poll can stop the thread without a prior stop() call.
        stopping = true
        let pending = commands; commands.removeAll()
        Darwin.close(wakeRead); Darwin.close(wakeWrite)
        wakeRead = -1; wakeWrite = -1
        commandLock.unlock()
        for command in pending {
            switch command {
            case .accept(let flow, _): close(flow, error: "relay stopped")
            case .connected(_, let endpoint, _): endpoint?.close()
            }
        }
        commandLock.lock(); stopped = true; commandLock.unlock()
    }
}
