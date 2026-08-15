import Foundation
import Virtualization

/// Listens on a vsock port for guest-initiated connections and relays
/// each one bidirectionally to a Unix domain socket on the host.
///
/// The upstream UDS is bound by mitmproxy's per-agent UnixInstance;
/// identity comes from the socket filename (<ip>_<agent>.sock) which
/// mitmproxy parses at bind. This relay is a dumb vsock↔UDS pump —
/// one process per VM, no TCP logic, no knowledge of mitmproxy.
///
///   Guest: curl → guest-forwarder → vsock
///   Host:  safeyolo-vm → UDS <sockets_dir>/<ip>_<agent>.sock
///          (mitmproxy UnixInstance listens here)
class VSockProxyRelay: NSObject, VZVirtioSocketListenerDelegate {

    static let PROXY_PORT: UInt32 = 1080
    private static let LABEL = "proxy-relay"
    private static let firstByteTimeoutMs: Int32 = {
        let key = "SAFEYOLO_PROXY_FIRST_BYTE_TIMEOUT_MS"
        guard let raw = ProcessInfo.processInfo.environment[key] else {
            return 30_000
        }
        guard let parsed = Int32(raw), parsed >= 0 else {
            Log.warn(LABEL, "\(key)=\(raw) is invalid; using 30000")
            return 30_000
        }
        return parsed
    }()

    private let vm: VZVirtualMachine
    private let queue: DispatchQueue
    private let socketPath: String
    private let agent: String
    // Hold a strong reference to the listener. VZVirtioSocketDevice's
    // setSocketListener(_:forPort:) isn't documented to retain the
    // listener, and a locally-scoped one disappears as soon as the
    // start() async block returns — the delegate method never fires.
    private var listener: VZVirtioSocketListener?
    // Monotonic per-process flow id so per-hop logs grep together.
    private let flowCounter = FlowCounter()

    init(vm: VZVirtualMachine, queue: DispatchQueue, socketPath: String) {
        self.vm = vm
        self.queue = queue
        self.socketPath = socketPath
        // Derive agent name from the per-agent socket path
        // (<dir>/<ip>_<agent>.sock). Log-only; relay forwards bytes
        // regardless of identity.
        let stem = ((socketPath as NSString).lastPathComponent
                    as NSString).deletingPathExtension
        if let underscore = stem.firstIndex(of: "_") {
            self.agent = String(stem[stem.index(after: underscore)...])
        } else {
            self.agent = stem
        }
        super.init()
    }

    /// Start listening for guest connections on the vsock proxy port.
    func start() {
        queue.async { [self] in
            guard let device = vm.socketDevices.first as? VZVirtioSocketDevice else {
                Log.warn(Self.LABEL, "no vsock device found on VM")
                return
            }
            let lst = VZVirtioSocketListener()
            lst.delegate = self
            self.listener = lst
            device.setSocketListener(lst, forPort: VSockProxyRelay.PROXY_PORT)
            Log.info(Self.LABEL,
                     "listen vsock=\(VSockProxyRelay.PROXY_PORT) agent=\(agent) upstream=unix:\(socketPath) first_byte_timeout_ms=\(Self.firstByteTimeoutMs)")
        }
    }

    // MARK: - VZVirtioSocketListenerDelegate

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        let flow = flowCounter.next()
        Log.debug(Self.LABEL,
                  "accept flow=\(flow) agent=\(agent) src=vsock:\(VSockProxyRelay.PROXY_PORT)")
        let thread = Thread { [self] in
            relay(flow: flow, vsockConnection: connection)
        }
        thread.name = "safeyolo.proxy-relay.\(agent).\(flow)"
        thread.start()
        return true
    }

    // MARK: - Relay

    private func relay(flow: Int, vsockConnection: VZVirtioSocketConnection) {
        let started = Date()
        let vsockFD = vsockConnection.fileDescriptor

        var firstBuf = [UInt8](repeating: 0, count: 65536)
        let firstBytes: Int
        switch Self.readFirstBytes(vsockFD: vsockFD, buf: &firstBuf, timeoutMs: Self.firstByteTimeoutMs) {
        case .data(let count):
            firstBytes = count
        case .timeout:
            let durationMs = Int(Date().timeIntervalSince(started) * 1000)
            Log.info(Self.LABEL,
                     "idle_timeout flow=\(flow) agent=\(agent) first_byte_timeout_ms=\(Self.firstByteTimeoutMs) duration_ms=\(durationMs)")
            close(vsockFD)
            return
        case .closed:
            let durationMs = Int(Date().timeIntervalSince(started) * 1000)
            Log.debug(Self.LABEL,
                      "closed_before_first_byte flow=\(flow) agent=\(agent) duration_ms=\(durationMs)")
            close(vsockFD)
            return
        case .failed(let message):
            Log.warn(Self.LABEL,
                     "flow=\(flow) read first byte: \(message)")
            close(vsockFD)
            return
        }

        // Open a fresh UDS client connection for this flow. Mitmproxy's
        // UnixInstance accepts on <socketPath> and parses the attribution
        // IP / agent name from its own filename — this relay never
        // touches identity. Deliberately do this only after the guest has
        // sent request bytes; browser preconnect/restore sockets that stay
        // idle should not occupy a mitmproxy UDS connection.
        let udsFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard udsFD >= 0 else {
            Log.warn(Self.LABEL,
                     "flow=\(flow) socket(AF_UNIX): \(String(cString: strerror(errno)))")
            close(vsockFD)
            return
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = socketPath.utf8CString
        let sunPathCapacity = MemoryLayout.size(ofValue: addr.sun_path)
        if pathBytes.count > sunPathCapacity {
            Log.warn(Self.LABEL,
                     "flow=\(flow) socket path too long (\(pathBytes.count) > \(sunPathCapacity)): \(socketPath)")
            close(udsFD)
            close(vsockFD)
            return
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { tuplePtr in
            tuplePtr.withMemoryRebound(to: CChar.self, capacity: sunPathCapacity) { dst in
                pathBytes.withUnsafeBufferPointer { src in
                    dst.update(from: src.baseAddress!, count: pathBytes.count)
                }
            }
        }

        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                connect(udsFD, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connectResult == 0 else {
            Log.warn(Self.LABEL,
                     "flow=\(flow) connect(unix:\(socketPath)): \(String(cString: strerror(errno)))")
            close(udsFD)
            close(vsockFD)
            return
        }

        guard Self.writeAll(udsFD, buf: &firstBuf, count: firstBytes) else {
            Log.warn(Self.LABEL,
                     "flow=\(flow) write first bytes to upstream: \(String(cString: strerror(errno)))")
            close(udsFD)
            close(vsockFD)
            return
        }

        // Per-flow poll loop on this dedicated relay thread. Browser restore
        // can create many long-lived idle CONNECT tunnels; using the shared
        // global DispatchQueue for blocking reads lets those tunnels starve
        // unrelated new proxy flows. One thread per live flow keeps that
        // blocking isolated without multiplying each tunnel into separate
        // pump threads.
        let (moreInbound, bytesOutbound) = Self.relayBidirectional(vsockFD: vsockFD, udsFD: udsFD)
        let bytesInbound = firstBytes + moreInbound

        let durationMs = Int(Date().timeIntervalSince(started) * 1000)
        Log.info(Self.LABEL,
                 "done flow=\(flow) agent=\(agent) bytes_in=\(bytesInbound) bytes_out=\(bytesOutbound) duration_ms=\(durationMs)")

        // vsockFD is owned by vsockConnection (the function parameter —
        // held alive by Swift's stack frame throughout this call). The
        // UDS fd is ours to close explicitly.
        close(udsFD)
    }

    private enum FirstReadResult {
        case data(Int)
        case timeout
        case closed
        case failed(String)
    }

    private static func readFirstBytes(vsockFD: Int32, buf: inout [UInt8], timeoutMs: Int32) -> FirstReadResult {
        let deadline = timeoutMs > 0
            ? Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
            : nil

        while true {
            let pollTimeout: Int32
            if let deadline {
                let remainingMs = Int32(max(0, Int(deadline.timeIntervalSinceNow * 1000)))
                pollTimeout = remainingMs
            } else {
                pollTimeout = -1
            }

            var fd = pollfd(fd: vsockFD, events: Int16(POLLIN), revents: 0)
            let ready = poll(&fd, nfds_t(1), pollTimeout)
            if ready == 0 {
                return .timeout
            }
            if ready < 0 {
                if errno == EINTR { continue }
                return .failed(String(cString: strerror(errno)))
            }

            if (fd.revents & Int16(POLLNVAL)) != 0 {
                return .failed("poll(POLLNVAL)")
            }
            if (fd.revents & Int16(POLLERR)) != 0 {
                return .failed("poll(POLLERR)")
            }

            let n = read(vsockFD, &buf, buf.count)
            if n > 0 {
                return .data(n)
            }
            if n == 0 {
                return .closed
            }
            if errno == EINTR {
                continue
            }
            return .failed(String(cString: strerror(errno)))
        }
    }

    private static func relayBidirectional(vsockFD: Int32, udsFD: Int32) -> (Int, Int) {
        var buf = [UInt8](repeating: 0, count: 65536)
        var bytesInbound = 0  // vsock → uds (client request)
        var bytesOutbound = 0 // uds → vsock (proxy response)
        var vsockReadable = true
        var udsReadable = true
        let readableEvents = Int16(POLLIN | POLLHUP | POLLERR | POLLNVAL)

        while vsockReadable || udsReadable {
            var fds = [
                pollfd(fd: vsockFD, events: vsockReadable ? Int16(POLLIN) : 0, revents: 0),
                pollfd(fd: udsFD, events: udsReadable ? Int16(POLLIN) : 0, revents: 0),
            ]

            let ready = poll(&fds, nfds_t(fds.count), -1)
            if ready < 0 {
                if errno == EINTR { continue }
                break
            }

            if vsockReadable && (fds[0].revents & readableEvents) != 0 {
                let n = read(vsockFD, &buf, buf.count)
                if n > 0 {
                    if writeAll(udsFD, buf: &buf, count: n) {
                        bytesInbound += n
                    } else {
                        vsockReadable = false
                        shutdown(udsFD, SHUT_WR)
                    }
                } else if n == 0 || errno != EINTR {
                    vsockReadable = false
                    shutdown(udsFD, SHUT_WR)
                }
            }

            if udsReadable && (fds[1].revents & readableEvents) != 0 {
                let n = read(udsFD, &buf, buf.count)
                if n > 0 {
                    if writeAll(vsockFD, buf: &buf, count: n) {
                        bytesOutbound += n
                    } else {
                        udsReadable = false
                        shutdown(vsockFD, SHUT_WR)
                    }
                } else if n == 0 || errno != EINTR {
                    udsReadable = false
                    shutdown(vsockFD, SHUT_WR)
                }
            }
        }

        return (bytesInbound, bytesOutbound)
    }

    private static func writeAll(_ dstFD: Int32, buf: inout [UInt8], count: Int) -> Bool {
        var written = 0
        return buf.withUnsafeBufferPointer { ptr in
            while written < count {
                let w = Darwin.write(dstFD, ptr.baseAddress! + written, count - written)
                if w > 0 {
                    written += w
                    continue
                }
                if w < 0 && errno == EINTR {
                    continue
                }
                return false
            }
            return true
        }
    }

}

/// Thread-safe monotonic counter used to stamp flow ids.
///
/// Swift 5.x doesn't ship atomics in the standard library, and a
/// DispatchQueue-guarded Int is plenty for this hot path (a handful
/// of connections per second at most).
final class FlowCounter {
    private var value = 0
    private let queue = DispatchQueue(label: "safeyolo.flow-counter")

    func next() -> Int {
        queue.sync {
            value += 1
            return value
        }
    }
}
