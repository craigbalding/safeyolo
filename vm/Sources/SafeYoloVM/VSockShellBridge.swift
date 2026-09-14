import Foundation
import Virtualization

/// Host shell UDS → guest vsock:2220 → guest bridge → sshd. Its nonblocking
/// relay thread is independent of all proxy work and generic GCD workers.
final class VSockShellBridge {
    static let SHELL_PORT: UInt32 = 2220
    private let vm: VZVirtualMachine
    private let queue: DispatchQueue
    private let socketPath: String
    let loop: SocketRelayLoop

    init(vm: VZVirtualMachine, queue: DispatchQueue, socketPath: String, ledger: RelayLedger) throws {
        self.vm = vm; self.queue = queue; self.socketPath = socketPath
        let agent = ((socketPath as NSString).lastPathComponent as NSString).deletingPathExtension
        loop = try SocketRelayLoop(kind: "shell", ledger: ledger, agent: agent)
    }

    func start() throws {
        try loop.listen(path: socketPath) { [weak self] id in
            guard let self else { return }
            // Both device lookup and connect belong to the VM queue. An absent
            // callback cannot hold a worker or outlive the relay's deadline.
            queue.async { [self] in
                guard let device = self.vm.socketDevices.first as? VZVirtioSocketDevice else {
                    self.loop.connected(id: id, endpoint: nil, error: "no vsock device on VM"); return
                }
                device.connect(toPort: Self.SHELL_PORT) { [loop = self.loop] result in
                    switch result {
                    case .success(let connection):
                        let endpoint = RelayEndpoint(fd: connection.fileDescriptor) { connection.close() }
                        loop.connected(id: id, endpoint: endpoint)
                    case .failure(let error):
                        loop.connected(id: id, endpoint: nil, error: "vsock connect: \(error)")
                    }
                }
            }
        }
        loop.start()
        Log.info("shell-bridge", "listen src=unix:\(socketPath) upstream=vsock:\(Self.SHELL_PORT)")
    }

    func stop() { loop.stop() }
}
