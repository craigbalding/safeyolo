import Foundation
import Virtualization

/// Guest vsock:1080 → the existing per-agent proxy UDS. Attribution remains
/// entirely in that listener; this class forwards bytes without inspecting them.
final class VSockProxyRelay: NSObject, VZVirtioSocketListenerDelegate {
    static let PROXY_PORT: UInt32 = 1080
    private let vm: VZVirtualMachine
    private let queue: DispatchQueue
    private let socketPath: String
    private var listener: VZVirtioSocketListener?
    let loop: SocketRelayLoop

    init(vm: VZVirtualMachine, queue: DispatchQueue, socketPath: String, ledger: RelayLedger) throws {
        self.vm = vm; self.queue = queue; self.socketPath = socketPath
        loop = try SocketRelayLoop(kind: "proxy", ledger: ledger)
        super.init()
    }

    func start() {
        loop.start()
        queue.async { [self] in
            guard let device = vm.socketDevices.first as? VZVirtioSocketDevice else {
                Log.warn("proxy-relay", "no vsock device found on VM"); loop.stop(); return
            }
            let listener = VZVirtioSocketListener()
            listener.delegate = self
            self.listener = listener
            device.setSocketListener(listener, forPort: Self.PROXY_PORT)
            Log.info("proxy-relay", "listen vsock=\(Self.PROXY_PORT) upstream=unix:\(socketPath)")
        }
    }

    func listener(_ listener: VZVirtioSocketListener,
                  shouldAcceptNewConnection connection: VZVirtioSocketConnection,
                  from socketDevice: VZVirtioSocketDevice) -> Bool {
        // Register ownership before returning to VZ, including work not yet
        // scheduled on the relay thread. Never close the framework-owned FD.
        let endpoint = RelayEndpoint(fd: connection.fileDescriptor) { connection.close() }
        loop.accept(endpoint, unixPath: socketPath)
        return true
    }

    func stop() {
        loop.stop()
        queue.async { [self] in
            if let device = vm.socketDevices.first as? VZVirtioSocketDevice {
                device.removeSocketListener(forPort: Self.PROXY_PORT)
            }
            listener = nil
        }
    }
}
