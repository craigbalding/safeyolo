import Foundation
import Virtualization

/// Reverses VSockProxyRelay: accepts connections on a host UDS and
/// forwards each one bidirectionally to a vsock port in the guest.
///
/// Enables `safeyolo agent shell` (and any SSH-shaped tooling) to reach
/// a VM that has no network interface. The guest runs a python bridge
/// on the matching vsock port forwarding to its local sshd; the
/// host-side caller uses `ssh -o ProxyCommand='nc -U <socket>'`.
///
///   Host:  ssh → nc -U shell.sock → safeyolo-vm (this bridge)
///   VZ:    vsock:<port>
///   Guest: guest-shell-bridge vsock:<port> → TCP:127.0.0.1:22 → sshd
class VSockShellBridge {

    static let SHELL_PORT: UInt32 = 2220
    private static let LABEL = "shell-bridge"

    private let vm: VZVirtualMachine
    private let queue: DispatchQueue
    private let socketPath: String
    private let agent: String
    private var listenFD: Int32 = -1
    private var acceptThread: Thread?
    private let flowCounter = FlowCounter()

    init(vm: VZVirtualMachine, queue: DispatchQueue, socketPath: String) {
        self.vm = vm
        self.queue = queue
        self.socketPath = socketPath
        self.agent = ((socketPath as NSString).lastPathComponent
                      as NSString).deletingPathExtension
    }

    /// Bind + listen on the host UDS and start an accept loop.
    func start() throws {
        // Stale file from a crashed instance
        unlink(socketPath)

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw VMConfigurationError.invalidConfiguration(
                "shell-bridge socket(): \(String(cString: strerror(errno)))"
            )
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = socketPath.utf8CString
        let cap = MemoryLayout.size(ofValue: addr.sun_path)
        if bytes.count > cap {
            close(fd)
            throw VMConfigurationError.invalidConfiguration(
                "shell-bridge socket path too long (\(bytes.count) > \(cap)): \(socketPath)"
            )
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { tuplePtr in
            tuplePtr.withMemoryRebound(to: CChar.self, capacity: cap) { dst in
                bytes.withUnsafeBufferPointer { src in
                    dst.update(from: src.baseAddress!, count: bytes.count)
                }
            }
        }

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(fd, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else {
            let err = String(cString: strerror(errno))
            close(fd)
            throw VMConfigurationError.invalidConfiguration(
                "shell-bridge bind(\(socketPath)): \(err)"
            )
        }
        // 0600: only the operator can dial the shell bridge from the host.
        // The UDS path is also under the operator's config dir (mode 0700).
        chmod(socketPath, 0o600)

        guard listen(fd, 32) == 0 else {
            let err = String(cString: strerror(errno))
            close(fd)
            throw VMConfigurationError.invalidConfiguration(
                "shell-bridge listen(): \(err)"
            )
        }

        listenFD = fd
        Log.info(Self.LABEL,
                 "listen agent=\(agent) src=unix:\(socketPath) upstream=vsock:\(VSockShellBridge.SHELL_PORT)")

        acceptThread = Thread { [self] in acceptLoop() }
        acceptThread?.start()
    }

    private func acceptLoop() {
        while true {
            var peer = sockaddr_un()
            var peerLen = socklen_t(MemoryLayout<sockaddr_un>.size)
            let clientFD = withUnsafeMutablePointer(to: &peer) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    accept(listenFD, sa, &peerLen)
                }
            }
            if clientFD < 0 {
                if errno == EINTR { continue }
                Log.warn(Self.LABEL,
                         "accept(): \(String(cString: strerror(errno)))")
                return
            }
            let flow = flowCounter.next()
            Log.debug(Self.LABEL,
                      "accept flow=\(flow) agent=\(agent) src=unix:\(socketPath)")
            // Hand off vsock dial + pump to a worker thread so accept()
            // stays ready for the next connection.
            DispatchQueue.global(qos: .default).async { [self] in
                relay(flow: flow, udsFD: clientFD)
            }
        }
    }

    private func relay(flow: Int, udsFD: Int32) {
        let started = Date()

        guard let device = vm.socketDevices.first as? VZVirtioSocketDevice else {
            Log.warn(Self.LABEL, "flow=\(flow) no vsock device on VM")
            close(udsFD)
            return
        }

        // VZVirtioSocketDevice.connect is async; block on a semaphore so
        // each accept's worker thread stays linear and easy to reason
        // about. Timeout is implicit in VZ's own connect handling.
        let sem = DispatchSemaphore(value: 0)
        var vsockConn: VZVirtioSocketConnection? = nil
        var connErr: Error? = nil

        queue.async {
            device.connect(toPort: VSockShellBridge.SHELL_PORT) { result in
                switch result {
                case .success(let conn):
                    vsockConn = conn
                case .failure(let err):
                    connErr = err
                }
                sem.signal()
            }
        }
        sem.wait()

        guard let conn = vsockConn else {
            Log.warn(Self.LABEL,
                     "flow=\(flow) vsock connect port=\(VSockShellBridge.SHELL_PORT) failed: \(connErr?.localizedDescription ?? "unknown")")
            close(udsFD)
            return
        }

        let vsockFD = conn.fileDescriptor

        // Use a DispatchGroup so the parent thread reliably waits for
        // both pumps to finish. Thread.isExecuting has a race window
        // between start() and the thread actually scheduling — the
        // while-loop can see false-false before either pump begins and
        // return, releasing `conn` and closing the backing vsock fd
        // underneath the pumps (→ EBADF on read).
        let group = DispatchGroup()
        let bgQueue = DispatchQueue.global(qos: .default)

        var bytesInbound = 0  // uds → vsock (ssh client → sshd)
        var bytesOutbound = 0 // vsock → uds (sshd → ssh client)

        group.enter()
        bgQueue.async {
            defer { group.leave() }
            bytesInbound = VSockShellBridge.forwardData(from: udsFD, to: vsockFD)
            shutdown(vsockFD, SHUT_WR)
        }
        group.enter()
        bgQueue.async {
            defer { group.leave() }
            bytesOutbound = VSockShellBridge.forwardData(from: vsockFD, to: udsFD)
            shutdown(udsFD, SHUT_WR)
        }
        group.wait()

        let durationMs = Int(Date().timeIntervalSince(started) * 1000)
        Log.info(Self.LABEL,
                 "done flow=\(flow) agent=\(agent) bytes_in=\(bytesInbound) bytes_out=\(bytesOutbound) duration_ms=\(durationMs)")

        _ = conn  // explicit reference at function end to defeat any
                  // over-eager ARC release optimisation.
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
