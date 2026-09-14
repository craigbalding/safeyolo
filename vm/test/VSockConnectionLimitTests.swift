import Foundation
import Darwin

@main
struct VSockConnectionLimitTests {
    static func main() {
        let limit = VSockConnectionLimit(maximum: 6)
        var callbacks: [VSockConnectionLimit.Completion] = []
        var endpoints: [RelayEndpoint] = []
        var rejected = 0
        var closed = 0
        let completion: VSockConnectionLimit.Completion = { result in
            switch result {
            case .success(let endpoint): endpoints.append(endpoint)
            case .failure(let error):
                precondition((error as NSError).code == Int(EBUSY))
                rejected += 1
            }
        }
        for _ in 0..<7 {
            limit.connect(start: { callbacks.append($0) }, completion: completion)
        }
        precondition(callbacks.count == 6 && rejected == 1, "pending connects exceed limit")
        callbacks[0](.success(RelayEndpoint(fd: -1) { closed += 1 }))
        limit.connect(start: { _ in preconditionFailure("active connection lost its slot") }, completion: completion)
        precondition(rejected == 2)
        endpoints[0].close(); endpoints[0].close()
        precondition(closed == 1, "endpoint closed more than once")
        limit.connect(start: { callbacks.append($0) }, completion: completion)
        precondition(callbacks.count == 7, "closed connection did not release slot")
        print("PASS six pending/active connections, rejection before start, closure and reuse")

        let failed = VSockConnectionLimit(maximum: 1)
        for _ in 0..<3 {
            failed.connect(start: { $0(.failure(NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNREFUSED)))) },
                completion: { result in
                    guard case .failure(let error) = result else { preconditionFailure("unexpected success") }
                    precondition((error as NSError).code == Int(ECONNREFUSED), "failure leaked admission slot")
                })
        }
        print("PASS failed connection releases its slot")

        let terminal = VSockConnectionLimit(maximum: 1)
        let pending = VSockConnectionWait()
        var late: VSockConnectionLimit.Completion!
        terminal.connect(start: { late = $0 }, completion: pending.complete)
        precondition(pending.wait(timeout: .now()) == nil)
        terminal.connect(start: { _ in preconditionFailure("timeout released an unresolved VZ attempt") }, completion: completion)
        let beforeLate = closed
        late(.success(RelayEndpoint(fd: -1) { closed += 1 }))
        precondition(closed == beforeLate + 1, "late connection was retained")
        let retry = VSockConnectionWait()
        terminal.connect(start: { $0(.success(RelayEndpoint(fd: -1) { closed += 1 })) }, completion: retry.complete)
        let connected = retry.wait(timeout: .now())
        precondition(connected != nil, "late cleanup did not release slot")
        connected?.close()
        print("PASS terminal timeout retains capacity until late callback closes its endpoint")

        let simultaneous = VSockConnectionLimit(maximum: 6)
        let lock = NSLock()
        var started = 0
        var refused = 0
        var concurrentCallbacks: [VSockConnectionLimit.Completion] = []
        DispatchQueue.concurrentPerform(iterations: 100) { _ in
            simultaneous.connect(start: { callback in
                lock.lock(); defer { lock.unlock() }
                started += 1; concurrentCallbacks.append(callback)
            }, completion: { result in
                guard case .failure(let error) = result else { preconditionFailure("unexpected success") }
                if (error as NSError).code == Int(EBUSY) {
                    lock.lock(); refused += 1; lock.unlock()
                }
            })
        }
        precondition(started == 6 && refused == 94, "concurrent callers oversubscribed admission")
        for callback in concurrentCallbacks {
            callback(.failure(NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNREFUSED))))
        }
        print("PASS concurrent admission cannot oversubscribe the limit")

        // Complete remaining attempts so the test also checks late failures.
        for callback in callbacks.dropFirst() {
            callback(.failure(NSError(domain: NSPOSIXErrorDomain, code: Int(EBUSY))))
        }
    }
}
