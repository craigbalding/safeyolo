import Darwin
import Foundation
import Virtualization

/// Temporary #1042 backend experiment. Use only an owned disposable instance.
/// The host creates a private SAFEYOLO_1042_PROOF_DIR with kept/startup/live/
/// readonly directories. Native mount validation supplies extra0=kept and
/// extra1=startup at boot. Only the explicitly exported children reach the VM.
/// The host writes a fixed step number, then reads the applied step. Neither
/// file is shared with the guest. This is not a production control operation.
final class LiveShareProof1042 {
    private let directory: URL
    private let vm: VZVirtualMachine
    private var timer: DispatchSourceTimer?
    private var applied = 0

    static func prepare(_ configuration: VZVirtualMachineConfiguration) throws -> URL? {
        guard let path = ProcessInfo.processInfo.environment["SAFEYOLO_1042_PROOF_DIR"] else { return nil }
        let directory = URL(fileURLWithPath: path, isDirectory: true)
        guard path.hasPrefix("/") else { throw failure("proof directory must be absolute") }
        let devices = configuration.directorySharingDevices.compactMap { $0 as? VZVirtioFileSystemDeviceConfiguration }
        guard let device = devices.first(where: { $0.tag == "extra0" }),
              let share = device.share as? VZSingleDirectoryShare,
              share.directory.url.standardizedFileURL.path == directory.appendingPathComponent("kept").standardizedFileURL.path,
              let startup = devices.first(where: { $0.tag == "extra1" })?.share as? VZSingleDirectoryShare,
              startup.directory.url.standardizedFileURL.path == directory.appendingPathComponent("startup").standardizedFileURL.path else {
            throw failure("proof requires extra0=kept and extra1=startup from this owned directory")
        }
        // This is the startup prerequisite under test. A multiple-directory
        // device exposes names, not their host parent directory.
        device.share = VZMultipleDirectoryShare(directories: ["kept": share.directory])
        return directory
    }

    init(directory: URL, vm: VZVirtualMachine, queue: DispatchQueue) {
        self.directory = directory
        self.vm = vm
        let timer = DispatchSource.makeTimerSource(queue: queue)
        self.timer = timer
        timer.schedule(deadline: .now() + .milliseconds(100), repeating: .milliseconds(100))
        timer.setEventHandler { [self] in advance() }
        timer.resume()
    }

    private static func failure(_ message: String) -> NSError {
        NSError(domain: "LiveShareProof1042", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    // The timer runs on the VM queue. All runtime device reads and share
    // assignments therefore use the queue required by Virtualization.framework.
    private func advance() {
        guard vm.state == .running,
              let contents = try? String(contentsOf: directory.appendingPathComponent("step"), encoding: .utf8),
              let step = Int(contents.trimmingCharacters(in: .whitespacesAndNewlines)),
              step == applied + 1 else { return }
        do {
            let devices = vm.directorySharingDevices.compactMap { $0 as? VZVirtioFileSystemDevice }
            guard let exports = devices.first(where: { $0.tag == "extra0" }),
                  let startup = devices.first(where: { $0.tag == "extra1" }) else {
                throw Self.failure("runtime devices are missing")
            }
            let shared = { (name: String, readOnly: Bool) in
                VZSharedDirectory(url: self.directory.appendingPathComponent(name), readOnly: readOnly)
            }
            var names = ["kept"]
            switch step {
            case 1...12:
                var directories = ["kept": shared("kept", false)]
                if [1, 2, 4, 6, 8, 10].contains(step) {
                    directories["live"] = shared("live", false)
                    names.append("live")
                }
                if (2...11).contains(step) {
                    directories["readonly"] = shared("readonly", true)
                    names.append("readonly")
                }
                exports.share = VZMultipleDirectoryShare(directories: directories)
            case 13:
                startup.share = nil
                names = []
            case 14:
                // Separately test converting an existing single-share device
                // after its guest mount was safely removed. No device hot-plug.
                startup.share = VZMultipleDirectoryShare(directories: [
                    "startup": shared("startup", false), "late": shared("live", false),
                ])
                names = ["startup", "late"]
            case 15:
                startup.share = nil
                names = []
            default:
                throw Self.failure("unknown proof step")
            }
            let observation: [String: Any] = ["step": step, "runtime_device": step < 13 ? "extra0" : "extra1",
                                             "names": names, "helper_pid": getpid()]
            let data = try JSONSerialization.data(withJSONObject: observation, options: [.sortedKeys])
            try data.write(to: directory.appendingPathComponent("applied.json"), options: .atomic)
            applied = step
        } catch {
            let observation: [String: Any] = ["step": step, "error": error.localizedDescription,
                                             "helper_pid": getpid()]
            if let data = try? JSONSerialization.data(withJSONObject: observation, options: [.sortedKeys]) {
                try? data.write(to: directory.appendingPathComponent("failed.json"), options: .atomic)
            }
            Log.warn("live-share-proof-1042", error.localizedDescription)
            timer?.cancel()
        }
    }
}
