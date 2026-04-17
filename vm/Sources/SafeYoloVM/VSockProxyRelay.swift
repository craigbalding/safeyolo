import Foundation
import Virtualization

/// Listens on a vsock port for guest-initiated connections and relays
/// each one bidirectionally to a Unix domain socket on the host.
///
/// Architecture symmetry with Linux: the host-side proxy_bridge owns
/// identity (binds upstream TCP source to the agent's attribution IP)
/// and policy (routing to local mitmproxy, team proxy, or peer agents).
/// This relay is a dumb vsock↔UDS pump — one process per VM, no TCP
/// logic, no knowledge of mitmproxy.
///
///   Guest: curl → guest-forwarder → vsock
///   Host:  safeyolo-vm → UDS <sockets_dir>/<name>.sock
///   Host:  proxy_bridge → TCP mitmproxy (Linux-and-macOS shared code)
class VSockProxyRelay: NSObject, VZVirtioSocketListenerDelegate {

    static let PROXY_PORT: UInt32 = 1080
    private static let LABEL = "proxy-relay"

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
        // (<dir>/<name>.sock). Cheap and avoids a new CLI flag.
        self.agent = ((socketPath as NSString).lastPathComponent
                      as NSString).deletingPathExtension
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
                     "listen vsock=\(VSockProxyRelay.PROXY_PORT) agent=\(agent) upstream=unix:\(socketPath)")
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
        DispatchQueue.global(qos: .default).async { [self] in
            relay(flow: flow, vsockConnection: connection)
        }
        return true
    }

    // MARK: - Relay

    private func relay(flow: Int, vsockConnection: VZVirtioSocketConnection) {
        let started = Date()
        let vsockFD = vsockConnection.fileDescriptor

        // Open a fresh UDS client connection for this flow. The bridge
        // accepts on <socketPath>, binds the upstream TCP source to the
        // agent's attribution IP, and connects to mitmproxy. Identity is
        // stamped by which per-agent UDS the bridge accepted from —
        // this relay never touches the attribution IP or the TCP port.
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

        // Bidirectional pump via DispatchGroup — symmetric fix to
        // VSockShellBridge's race. Thread.isExecuting has a window
        // between start() and actual scheduling where both can read
        // false, making the while-loop return early and tear the fds
        // down under a pump that hadn't yet begun reading.
        let group = DispatchGroup()
        let bgQueue = DispatchQueue.global(qos: .default)

        var bytesInbound = 0  // vsock → uds (client request)
        var bytesOutbound = 0 // uds → vsock (proxy response)

        group.enter()
        bgQueue.async {
            defer { group.leave() }
            bytesInbound = Self.forwardData(from: vsockFD, to: udsFD)
            shutdown(udsFD, SHUT_WR)
        }
        group.enter()
        bgQueue.async {
            defer { group.leave() }
            bytesOutbound = Self.forwardData(from: udsFD, to: vsockFD)
            shutdown(vsockFD, SHUT_WR)
        }
        group.wait()

        let durationMs = Int(Date().timeIntervalSince(started) * 1000)
        Log.info(Self.LABEL,
                 "done flow=\(flow) agent=\(agent) bytes_in=\(bytesInbound) bytes_out=\(bytesOutbound) duration_ms=\(durationMs)")

        // vsockFD is owned by vsockConnection (the function parameter —
        // held alive by Swift's stack frame throughout this call). The
        // UDS fd is ours to close explicitly.
        close(udsFD)
    }

    private static func forwardData(from srcFD: Int32, to dstFD: Int32) -> Int {
        var buf = [UInt8](repeating: 0, count: 65536)
        var total = 0
        while true {
            let n = read(srcFD, &buf, buf.count)
            if n <= 0 { break }
            var written = 0
            buf.withUnsafeBufferPointer { ptr in
                while written < n {
                    let w = Darwin.write(dstFD, ptr.baseAddress! + written, n - written)
                    if w <= 0 { return }
                    written += w
                }
            }
            if written < n { break }
            total += written
        }
        return total
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
