import Foundation
import Darwin

@main
struct SocketRelayTests {
    static func wait(_ description: String, timeout: Double = 3, _ predicate: () -> Bool) {
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while !predicate() {
            precondition(ProcessInfo.processInfo.systemUptime < deadline, description)
            usleep(1000)
        }
    }

    static func pair() -> (RelayEndpoint, Int32) {
        var fds: [Int32] = [-1, -1]
        precondition(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        var timeout = timeval(tv_sec: 3, tv_usec: 0)
        for fd in fds {
            precondition(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout))) == 0)
            precondition(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout))) == 0)
        }
        return (RelayEndpoint(fd: fds[0]), fds[1])
    }

    static func send(_ fd: Int32, _ bytes: Data) {
        var offset = 0
        bytes.withUnsafeBytes { ptr in
            while offset < ptr.count {
                let n = Darwin.write(fd, ptr.baseAddress! + offset, ptr.count - offset)
                precondition(n > 0, "test write failed errno=\(errno)")
                offset += n
            }
        }
    }

    static func receive(_ fd: Int32, count: Int) -> Data {
        var bytes = Data()
        var scratch = [UInt8](repeating: 0, count: 8192)
        while bytes.count < count {
            let n = Darwin.read(fd, &scratch, min(scratch.count, count - bytes.count))
            precondition(n > 0, "test read failed errno=\(errno), received=\(bytes.count)")
            bytes.append(contentsOf: scratch.prefix(n))
        }
        return bytes
    }

    static func fdCount() -> Int {
        (0..<4096).reduce(0) { $0 + (fcntl(Int32($1), F_GETFD) >= 0 ? 1 : 0) }
    }

    static func main() throws {
        signal(SIGPIPE, SIG_IGN)
        var limit = rlimit(rlim_cur: 4096, rlim_max: 4096)
        precondition(setrlimit(RLIMIT_NOFILE, &limit) == 0)
        let baseline = fdCount()
        let ledger = RelayLedger()
        let proxy = try SocketRelayLoop(kind: "proxy", ledger: ledger, establishmentTimeout: 0.15, drainTimeout: 0.15)
        let shell = try SocketRelayLoop(kind: "shell", ledger: ledger, establishmentTimeout: 0.15, drainTimeout: 0.15)
        proxy.start(); shell.start()

        // Neither acceptance nor a framework callback is required to execute
        // a GCD child. Leave hundreds of idle proxy sockets open throughout.
        var held: [Int32] = []
        var ids: [UInt64] = []
        for _ in 0..<300 {
            let (a, client) = pair(); let (b, server) = pair()
            let id = proxy.accept(a); proxy.connected(id: id, endpoint: b)
            held += [client, server]; ids.append(id)
        }
        wait("all proxy flows active") { ledger.snapshot().active.filter { $0.phase == "active" }.count == 300 }
        for _ in 0..<20 {
            let (a, client) = pair(); let (b, server) = pair()
            let id = shell.accept(a); shell.connected(id: id, endpoint: b)
            send(server, Data("SSH-2.0-test\r\n".utf8))
            precondition(receive(client, count: 14) == Data("SSH-2.0-test\r\n".utf8))
            shutdown(client, SHUT_WR); shutdown(server, SHUT_WR)
            wait("shell flow completed") { !ledger.snapshot().active.contains { $0.id == id } }
            Darwin.close(client); Darwin.close(server)
        }
        print("PASS 300 held proxy flows plus repeated shell progress")

        // An idle SSH client can close its UDS while the guest sends no more
        // bytes. Release that shell's VZ endpoint without requiring remote EOF.
        let (departed, departedClient) = pair(); let (idleGuest, idleServer) = pair()
        let departedID = shell.accept(departed); shell.connected(id: departedID, endpoint: idleGuest)
        wait("idle shell connected") { ledger.snapshot().active.contains { $0.id == departedID && $0.phase == "active" } }
        Darwin.close(departedClient)
        wait("closed shell client releases its endpoint") { !ledger.snapshot().active.contains { $0.id == departedID } }
        var departedByte: UInt8 = 0
        precondition(Darwin.read(idleServer, &departedByte, 1) == 0)
        Darwin.close(idleServer)
        print("PASS fully closed idle shell client releases the guest endpoint")

        let (a, client) = pair(); let (b, server) = pair()
        let id = shell.accept(a); shell.connected(id: id, endpoint: b)
        let payload = Data((0..<(4 * 1024 * 1024)).map { UInt8($0 % 251) })
        let finished = DispatchSemaphore(value: 0)
        Thread {
            send(client, payload); shutdown(client, SHUT_WR); finished.signal()
        }.start()
        // Wait for evidenced backpressure, then prove that draining the slow
        // recipient resumes the original payload without drops or corruption.
        wait("bounded buffer reached") {
            ledger.snapshot().active.contains { $0.id == id && $0.bufferedIn == 65536 }
        }
        precondition(receive(server, count: payload.count) == payload)
        precondition(finished.wait(timeout: .now() + 3) == .success)
        var byte: UInt8 = 0
        precondition(Darwin.read(server, &byte, 1) == 0, "request half-close not propagated")
        // A request EOF must not cut off the subsequent response.
        send(server, Data("response after EOF".utf8)); shutdown(server, SHUT_WR)
        precondition(receive(client, count: 18) == Data("response after EOF".utf8))
        precondition(Darwin.read(client, &byte, 1) == 0)
        wait("half-close drains both directions") { !ledger.snapshot().active.contains { $0.id == id } }
        Darwin.close(client); Darwin.close(server)
        print("PASS backpressure, partial writes, 4 MiB integrity and half-close response")

        let (waiting, peer) = pair()
        let pendingID = shell.accept(waiting)
        wait("missing VZ callback times out") { ledger.snapshot().recent.contains { $0.id == pendingID && $0.error == "relay establishment timed out" } }
        precondition(Darwin.read(peer, &byte, 1) == 0)
        Darwin.close(peer)
        let (late, latePeer) = pair()
        shell.connected(id: pendingID, endpoint: late)
        precondition(Darwin.read(latePeer, &byte, 1) == 0, "late callback endpoint leaked")
        Darwin.close(latePeer)
        print("PASS absent and late VZ callbacks release endpoints")

        // Cancel before the owner thread ever runs, then deliver a successful
        // callback after it stops. Neither endpoint may escape cleanup.
        let delayed = try SocketRelayLoop(kind: "delayed", ledger: ledger)
        let (delayedEndpoint, delayedPeer) = pair()
        let delayedID = delayed.accept(delayedEndpoint)
        precondition(ledger.snapshot().active.contains { $0.id == delayedID && $0.phase == "accepted" })
        ledger.cancel(ids: [delayedID]); delayed.start()
        precondition(Darwin.read(delayedPeer, &byte, 1) == 0)
        Darwin.close(delayedPeer)
        delayed.stop(); wait("delayed loop stopped") { delayed.isStopped }
        let (afterStop, afterStopPeer) = pair()
        delayed.connected(id: delayedID, endpoint: afterStop)
        precondition(Darwin.read(afterStopPeer, &byte, 1) == 0)
        Darwin.close(afterStopPeer)
        print("PASS accepted ownership before scheduling and callback after stop")

        let (drainIncoming, drainClient) = pair(); let (drainOutgoing, drainServer) = pair()
        var smallBuffer: Int32 = 1024
        precondition(setsockopt(drainOutgoing.fd, SOL_SOCKET, SO_SNDBUF, &smallBuffer, socklen_t(MemoryLayout.size(ofValue: smallBuffer))) == 0)
        let drainID = shell.accept(drainIncoming); shell.connected(id: drainID, endpoint: drainOutgoing)
        shutdown(drainServer, SHUT_WR)
        send(drainClient, Data(repeating: 42, count: 32768)); shutdown(drainClient, SHUT_WR)
        wait("both-EOF stalled drain expires") {
            ledger.snapshot().recent.contains { $0.id == drainID && $0.error == "relay drain timed out" }
        }
        Darwin.close(drainClient); Darwin.close(drainServer)
        print("PASS bounded teardown when both readers reached EOF and recipient will not drain")

        let (failed, failedPeer) = pair()
        let failedID = proxy.accept(failed, unixPath: "/nonexistent-safeyolo-relay-test.sock")
        wait("failed upstream closed") { ledger.snapshot().recent.contains { $0.id == failedID && $0.error != nil } }
        precondition(Darwin.read(failedPeer, &byte, 1) == 0); Darwin.close(failedPeer)

        precondition(ledger.cancel(ids: ids).count == 300)
        proxy.wake()
        wait("cancellation removes every held flow") { ledger.snapshot().active.isEmpty }
        for fd in held { precondition(Darwin.read(fd, &byte, 1) == 0); Darwin.close(fd) }
        precondition(ledger.cancel(ids: ids).isEmpty, "cancelled flow resurrected")

        // A full stderr pipe must not block a relay's cancellation path.
        var logPipe: [Int32] = [-1, -1]
        precondition(pipe(&logPipe) == 0)
        let savedError = dup(STDERR_FILENO)
        precondition(savedError >= 0 && dup2(logPipe[1], STDERR_FILENO) >= 0)
        Darwin.close(logPipe[1])
        let message = String(repeating: "x", count: 2048)
        for _ in 0..<5000 { Log.relay("backpressure-test", message) }
        wait("log overflow visible") { Log.droppedRelayMessages > 0 }
        let (loggedEndpoint, loggedPeer) = pair()
        let loggedID = shell.accept(loggedEndpoint)
        ledger.cancel(ids: [loggedID]); shell.wake()
        wait("cleanup with blocked logs") { ledger.snapshot().active.isEmpty }
        precondition(Darwin.read(loggedPeer, &byte, 1) == 0)
        Darwin.close(loggedPeer)
        precondition(dup2(savedError, STDERR_FILENO) >= 0)
        Darwin.close(savedError); Darwin.close(logPipe[0])
        print("PASS stderr backpressure cannot block relay cancellation")

        proxy.stop(); shell.stop()
        wait("both relay threads stopped") { proxy.isStopped && shell.isStopped }
        precondition(fdCount() == baseline, "descriptor count did not return to baseline")
        print("PASS cancellation, failed upstream, thread stop and exact FD baseline")
    }
}
