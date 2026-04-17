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

    private let vm: VZVirtualMachine
    private let queue: DispatchQueue
    private let socketPath: String
    // Hold a strong reference to the listener. VZVirtioSocketDevice's
    // setSocketListener(_:forPort:) isn't documented to retain the
    // listener, and a locally-scoped one disappears as soon as the
    // start() async block returns — the delegate method never fires.
    private var listener: VZVirtioSocketListener?

    init(vm: VZVirtualMachine, queue: DispatchQueue, socketPath: String) {
        self.vm = vm
        self.queue = queue
        self.socketPath = socketPath
        super.init()
    }

    /// Start listening for guest connections on the vsock proxy port.
    func start() {
        queue.async { [self] in
            guard let device = vm.socketDevices.first as? VZVirtioSocketDevice else {
                fputs("[proxy-relay] No vsock device found\n", stderr)
                return
            }
            let lst = VZVirtioSocketListener()
            lst.delegate = self
            self.listener = lst
            device.setSocketListener(lst, forPort: VSockProxyRelay.PROXY_PORT)
            fputs("[proxy-relay] Listening on vsock port \(VSockProxyRelay.PROXY_PORT) -> unix:\(socketPath)\n", stderr)
        }
    }

    // MARK: - VZVirtioSocketListenerDelegate

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        // Accept and relay in a background thread
        DispatchQueue.global(qos: .default).async { [self] in
            relay(vsockConnection: connection)
        }
        return true
    }

    // MARK: - Relay

    private func relay(vsockConnection: VZVirtioSocketConnection) {
        let vsockFD = vsockConnection.fileDescriptor

        // Open a fresh UDS client connection for this flow. The bridge
        // accepts on <socketPath>, binds the upstream TCP source to the
        // agent's attribution IP, and connects to mitmproxy. Identity is
        // stamped by which per-agent UDS the bridge accepted from —
        // this relay never touches the attribution IP or the TCP port.
        let udsFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard udsFD >= 0 else {
            fputs("[proxy-relay] socket(AF_UNIX) failed: \(String(cString: strerror(errno)))\n", stderr)
            close(vsockFD)
            return
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = socketPath.utf8CString
        // sun_path is a fixed-size C array; copy byte-by-byte into the
        // tuple-backed field via withUnsafeMutablePointer reinterpretation.
        // Fail early if the path is longer than the OS limit (104 on
        // Darwin) — connect() would fail in a less clear way otherwise.
        let sunPathCapacity = MemoryLayout.size(ofValue: addr.sun_path)
        if pathBytes.count > sunPathCapacity {
            fputs("[proxy-relay] socket path too long (\(pathBytes.count) > \(sunPathCapacity)): \(socketPath)\n", stderr)
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
            fputs("[proxy-relay] connect to unix:\(socketPath) failed: \(String(cString: strerror(errno)))\n", stderr)
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
        group.enter()
        bgQueue.async {
            defer { group.leave() }
            Self.forwardData(from: vsockFD, to: udsFD)
            shutdown(udsFD, SHUT_WR)
        }
        group.enter()
        bgQueue.async {
            defer { group.leave() }
            Self.forwardData(from: udsFD, to: vsockFD)
            shutdown(vsockFD, SHUT_WR)
        }
        group.wait()

        // vsockFD is owned by vsockConnection (the function parameter —
        // held alive by Swift's stack frame throughout this call). The
        // UDS fd is ours to close explicitly.
        close(udsFD)
    }

    private static func forwardData(from srcFD: Int32, to dstFD: Int32) {
        var buf = [UInt8](repeating: 0, count: 65536)
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
        }
    }
}
