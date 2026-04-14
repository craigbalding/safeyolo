import Foundation
import Virtualization
import CryptoKit

/// Snapshot / restore helpers for `VZVirtualMachine`, using the macOS 14
/// `saveMachineStateTo` / `restoreMachineStateFrom` APIs.
///
/// macOS 14 minimum is enforced by `Package.swift`'s `platforms:` block —
/// no per-call `@available` checks needed here or at call sites.
///
/// Layout: a snapshot is a single file at the user-supplied path, with a
/// sibling sidecar at `<path>.meta.json` holding the hardware fingerprint
/// (memory, cpus, kernel/initrd hashes, helper version). On restore the
/// caller must pass the same `--kernel/--initrd/--memory/--cpus` values
/// that were used when saving — VZ enforces config equality at the framework
/// level, but the sidecar lets us refuse with a clear error *before*
/// invoking VZ.
enum VMSnapshot {

    enum Error: Swift.Error, LocalizedError {
        case saveFailed(Swift.Error)
        case restoreFailed(Swift.Error)
        case pauseFailed(Swift.Error)
        case resumeFailed(Swift.Error)
        case sidecarMissing(URL)
        case sidecarParseFailed(Swift.Error)
        case fingerprintMismatch(String)

        var errorDescription: String? {
            switch self {
            case .saveFailed(let e):           return "save failed: \(e.localizedDescription)"
            case .restoreFailed(let e):        return "restore failed: \(e.localizedDescription)"
            case .pauseFailed(let e):          return "pause failed: \(e.localizedDescription)"
            case .resumeFailed(let e):         return "resume failed: \(e.localizedDescription)"
            case .sidecarMissing(let url):     return "snapshot sidecar missing: \(url.path)"
            case .sidecarParseFailed(let e):   return "snapshot sidecar parse failed: \(e.localizedDescription)"
            case .fingerprintMismatch(let m):  return "snapshot/host hardware fingerprint mismatch (\(m))"
            }
        }
    }

    /// Hardware fingerprint + restore-time identity stored alongside the
    /// snapshot file. The fingerprint fields are checked at restore time
    /// for an early, clear mismatch error. The machineIdentifier is the
    /// base64-encoded VZGenericMachineIdentifier dataRepresentation —
    /// VZ requires the restored VM to have the SAME machine identifier
    /// it had at save time, so we serialize it here and the restoring
    /// process reads it back BEFORE building the VM config.
    struct Fingerprint: Codable, Equatable {
        var schema: Int = 1
        var memoryMB: Int
        var cpus: Int
        var kernelSHA256: String
        var initrdSHA256: String
        var vmHelperVersion: String
        var machineIdentifier: String  // base64
    }

    // MARK: - Save (pause → write → clone-disk → resume)

    /// Take a snapshot of the running VM and write it to `url`. Optionally
    /// clones the rootfs disk image to `rootfsCloneURL` while the VM is
    /// still paused — VZ requires the rootfs at restore time to be
    /// byte-identical to its state at save time, so a clone snapshotted
    /// at the same moment as the memory state is the only safe way to
    /// ensure restorability after the VM continues running and modifies
    /// the live disk.
    ///
    /// Resumes the VM unconditionally on the way out — even on save failure
    /// — so we never leave the VM stuck in `.paused`.
    ///
    /// Sidecar metadata is written *after* a successful save; if save fails
    /// the sidecar is not written and the snapshot file is deleted.
    static func save(
        vm: VZVirtualMachine,
        queue: DispatchQueue,
        toURL url: URL,
        rootfsURL: URL,
        rootfsCloneURL: URL?,
        fingerprint: Fingerprint
    ) throws {
        // 1. Pause
        try runSync(queue: queue) { done in
            vm.pause { result in
                switch result {
                case .success:        done(nil)
                case .failure(let e): done(Error.pauseFailed(e))
                }
            }
        }

        // 2. Save — capture any error but always attempt to resume.
        var saveError: Swift.Error?
        do {
            try runSync(queue: queue) { done in
                vm.saveMachineStateTo(url: url) { err in
                    if let e = err { done(Error.saveFailed(e)) }
                    else            { done(nil) }
                }
            }
        } catch {
            saveError = error
        }

        // 3. Clone the rootfs while the VM is still paused (and only if
        // save succeeded — pointless otherwise). Uses APFS's clonefile()
        // syscall via FileManager — instant, copy-on-write. The clone
        // captures the exact disk state that pairs with the saved memory
        // state. Restore must use this clone, not the live rootfs.
        var cloneError: Swift.Error?
        if saveError == nil, let cloneURL = rootfsCloneURL {
            do {
                if FileManager.default.fileExists(atPath: cloneURL.path) {
                    try FileManager.default.removeItem(at: cloneURL)
                }
                try FileManager.default.copyItem(at: rootfsURL, to: cloneURL)
            } catch {
                cloneError = Error.saveFailed(error)
            }
        }

        // 4. Resume — must run even if save/clone failed, otherwise VM is stuck paused.
        let resumeError: Swift.Error? = {
            do {
                try runSync(queue: queue) { done in
                    vm.resume { result in
                        switch result {
                        case .success:        done(nil)
                        case .failure(let e): done(Error.resumeFailed(e))
                        }
                    }
                }
                return nil
            } catch {
                return error
            }
        }()

        // Save/clone errors take precedence over resume errors — a failed
        // save+resumed-VM is recoverable; a failed resume after successful
        // save indicates VM corruption that we want surfaced.
        if let e = saveError {
            // Best-effort cleanup: don't leave a partial snapshot file
            // around to confuse a later restore attempt.
            try? FileManager.default.removeItem(at: url)
            throw e
        }
        if let e = cloneError {
            try? FileManager.default.removeItem(at: url)
            throw e
        }
        if let e = resumeError { throw e }

        // 5. Sidecar
        try writeSidecar(fingerprint: fingerprint, snapshotURL: url)
    }

    // MARK: - Restore (validate → restore → resume)

    /// Restore a not-yet-started VM from `url` and resume it. The caller
    /// must construct `vm` with the exact same hardware config (kernel,
    /// initrd, memory, cpu count) that was used at save time. The sidecar
    /// is checked first so a hardware mismatch is reported clearly without
    /// going through VZ's lower-level error.
    static func restore(
        vm: VZVirtualMachine,
        queue: DispatchQueue,
        fromURL url: URL,
        expectedFingerprint: Fingerprint
    ) throws {
        try validateSidecar(expected: expectedFingerprint, snapshotURL: url)

        try runSync(queue: queue) { done in
            vm.restoreMachineStateFrom(url: url) { err in
                if let e = err { done(Error.restoreFailed(e)) }
                else            { done(nil) }
            }
        }

        try runSync(queue: queue) { done in
            vm.resume { result in
                switch result {
                case .success:        done(nil)
                case .failure(let e): done(Error.resumeFailed(e))
                }
            }
        }
    }

    // MARK: - Sidecar I/O

    static func sidecarURL(for snapshotURL: URL) -> URL {
        snapshotURL.appendingPathExtension("meta.json")
    }

    static func writeSidecar(fingerprint: Fingerprint, snapshotURL: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(fingerprint)
        try data.write(to: sidecarURL(for: snapshotURL), options: .atomic)
    }

    static func validateSidecar(expected: Fingerprint, snapshotURL: URL) throws {
        let url = sidecarURL(for: snapshotURL)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw Error.sidecarMissing(url)
        }
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw Error.sidecarParseFailed(error)
        }
        let actual: Fingerprint
        do {
            actual = try JSONDecoder().decode(Fingerprint.self, from: data)
        } catch {
            throw Error.sidecarParseFailed(error)
        }
        if actual != expected {
            var diffs: [String] = []
            if actual.schema != expected.schema             { diffs.append("schema=\(actual.schema)≠\(expected.schema)") }
            if actual.memoryMB != expected.memoryMB         { diffs.append("memoryMB=\(actual.memoryMB)≠\(expected.memoryMB)") }
            if actual.cpus != expected.cpus                 { diffs.append("cpus=\(actual.cpus)≠\(expected.cpus)") }
            if actual.kernelSHA256 != expected.kernelSHA256 { diffs.append("kernel_sha changed") }
            if actual.initrdSHA256 != expected.initrdSHA256 { diffs.append("initrd_sha changed") }
            if actual.vmHelperVersion != expected.vmHelperVersion {
                diffs.append("vm_helper=\(actual.vmHelperVersion)≠\(expected.vmHelperVersion)")
            }
            if actual.machineIdentifier != expected.machineIdentifier {
                diffs.append("machine_identifier changed")
            }
            throw Error.fingerprintMismatch(diffs.joined(separator: ", "))
        }
    }

    // MARK: - SHA256

    /// Streaming SHA256 of a file — safe for large kernels/initrds.
    static func sha256(ofFileAt path: String) throws -> String {
        let url = URL(fileURLWithPath: NSString(string: path).expandingTildeInPath)
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        var hasher = SHA256()
        let chunkSize = 1 << 20  // 1 MiB
        while true {
            let chunk = handle.readData(ofLength: chunkSize)
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Private: completion-handler → sync helper

    /// Run a queue-dispatched async operation synchronously. The operation
    /// must call `done(nil)` on success or `done(error)` on failure.
    /// Mirrors the `DispatchSemaphore` pattern in `VMRunner.start()`.
    private static func runSync(
        queue: DispatchQueue,
        _ op: @escaping (@escaping (Swift.Error?) -> Void) -> Void
    ) throws {
        let semaphore = DispatchSemaphore(value: 0)
        var captured: Swift.Error?
        queue.async {
            op { err in
                captured = err
                semaphore.signal()
            }
        }
        semaphore.wait()
        if let err = captured { throw err }
    }
}
