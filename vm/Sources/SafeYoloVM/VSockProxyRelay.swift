import Foundation
import Virtualization

/// Listens on a vsock port for guest-initiated connections and relays
/// each one bidirectionally to a TCP endpoint (mitmproxy).
///
/// The guest runs a forwarder: localhost:8080 → vsock:PROXY_PORT.
/// This relay accepts the vsock connection and forwards to mitmproxy.
/// One hop between the VM boundary and the proxy.
class VSockProxyRelay: NSObject, VZVirtioSocketListenerDelegate {

    static let PROXY_PORT: UInt32 = 1080

    private let vm: VZVirtualMachine
    private let queue: DispatchQueue
    private let proxyHost: String
    private let proxyPort: UInt16

    init(vm: VZVirtualMachine, queue: DispatchQueue,
         proxyHost: String = "127.0.0.1", proxyPort: UInt16 = 8080) {
        self.vm = vm
        self.queue = queue
        self.proxyHost = proxyHost
        self.proxyPort = proxyPort
        super.init()
    }

    /// Start listening for guest connections on the vsock proxy port.
    func start() {
        queue.async { [self] in
            guard let device = vm.socketDevices.first as? VZVirtioSocketDevice else {
                fputs("[proxy-relay] No vsock device found\n", stderr)
                return
            }
            let listener = VZVirtioSocketListener()
            listener.delegate = self
            device.setSocketListener(listener, forPort: VSockProxyRelay.PROXY_PORT)
            fputs("[proxy-relay] Listening on vsock port \(VSockProxyRelay.PROXY_PORT) -> \(proxyHost):\(proxyPort)\n", stderr)
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

        // Connect to mitmproxy
        let tcpFD = socket(AF_INET, SOCK_STREAM, 0)
        guard tcpFD >= 0 else {
            fputs("[proxy-relay] socket() failed: \(String(cString: strerror(errno)))\n", stderr)
            close(vsockFD)
            return
        }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = proxyPort.bigEndian
        inet_pton(AF_INET, proxyHost, &addr.sin_addr)

        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                connect(tcpFD, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connectResult == 0 else {
            fputs("[proxy-relay] connect to \(proxyHost):\(proxyPort) failed: \(String(cString: strerror(errno)))\n", stderr)
            close(tcpFD)
            close(vsockFD)
            return
        }

        // Bidirectional relay using select()
        let t1 = Thread {
            Self.forwardData(from: vsockFD, to: tcpFD)
            shutdown(tcpFD, SHUT_WR)
        }
        let t2 = Thread {
            Self.forwardData(from: tcpFD, to: vsockFD)
            shutdown(vsockFD, SHUT_WR)
        }
        t1.start()
        t2.start()

        // Wait for both directions to finish
        // (Threads are detached; we rely on the FD close to terminate them)
        // Use a simple polling approach since Foundation Threads aren't joinable
        while t1.isExecuting || t2.isExecuting {
            Thread.sleep(forTimeInterval: 0.1)
        }

        close(tcpFD)
        close(vsockFD)
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
