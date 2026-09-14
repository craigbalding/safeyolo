import Foundation
import Darwin

/// Admission happens before calling VZ. Pending callbacks retain their slot
/// even if the caller times out or cancels; only failure or endpoint closure
/// releases it. The framework must call its completion exactly once.
final class VSockConnectionLimit {
    typealias Completion = (Result<RelayEndpoint, Error>) -> Void
    private let lock = NSLock()
    private let maximum: Int
    private var used = 0

    init(maximum: Int) {
        precondition(maximum > 0)
        self.maximum = maximum
    }

    func connect(start: (@escaping Completion) -> Void, completion: @escaping Completion) {
        lock.lock()
        guard used < maximum else {
            lock.unlock()
            completion(.failure(NSError(domain: NSPOSIXErrorDomain, code: Int(EBUSY),
                userInfo: [NSLocalizedDescriptionKey: "vsock connection limit reached (\(maximum))"])))
            return
        }
        used += 1
        lock.unlock()
        start { [self] result in
            switch result {
            case .success(let endpoint):
                let owned = RelayEndpoint(fd: endpoint.fd) {
                    endpoint.close()
                    self.release()
                }
                completion(.success(owned))
            case .failure(let error):
                release()
                completion(.failure(error))
            }
        }
    }

    private func release() {
        lock.lock(); defer { lock.unlock() }
        used -= 1
        precondition(used >= 0)
    }
}

/// The terminal has a synchronous caller and an asynchronous VZ callback.
/// Synchronise the handoff and close a result arriving after the caller leaves.
final class VSockConnectionWait {
    private let lock = NSLock()
    private let ready = DispatchSemaphore(value: 0)
    private var finished = false
    private var endpoint: RelayEndpoint?

    func complete(_ result: Result<RelayEndpoint, Error>) {
        let connection = try? result.get()
        lock.lock()
        if finished {
            lock.unlock()
            connection?.close()
            return
        }
        endpoint = connection
        ready.signal()
        lock.unlock()
    }

    func wait(timeout: DispatchTime) -> RelayEndpoint? {
        _ = ready.wait(timeout: timeout)
        lock.lock(); defer { lock.unlock() }
        finished = true
        let result = endpoint
        endpoint = nil
        return result
    }
}
