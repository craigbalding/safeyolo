import Foundation
import Virtualization

/// Updates only ordinary extra exports on existing runtime devices.
final class ExtraDirectories {
    static let tag = "safeyolo-extra"
    private struct Entry {
        let path: String
        let readOnly: Bool
        let directory: VZSharedDirectory
    }
    private let vm: VZVirtualMachine
    private let queue: DispatchQueue
    private var entries: [String: Entry] = [:]

    init(vm: VZVirtualMachine, queue: DispatchQueue) {
        self.vm = vm; self.queue = queue
    }

    func request(_ request: ExtraDirectoryRequest,
                 completion: @escaping ([String: Any]?, String?) -> Void) {
        queue.async { [self] in
            do { completion(try execute(request), nil) }
            catch { completion(nil, error.localizedDescription) }
        }
    }

    private func invalid(_ message: String) -> Error {
        NSError(domain: "ExtraDirectories", code: 1,
                userInfo: [NSLocalizedDescriptionKey: message])
    }

    private func execute(_ request: ExtraDirectoryRequest) throws -> [String: Any] {
        guard vm.state == .running else { throw invalid("VM is not running; no export was changed") }
        let devices = vm.directorySharingDevices.compactMap { $0 as? VZVirtioFileSystemDevice }
        let live = devices.first { $0.tag == Self.tag }
        if request.operation == "add" {
            guard let live else {
                throw invalid("VM has no prepared extra-directory device; use an explicit future stop/start with the current helper")
            }
            guard let id = request.id, id.count == 32,
                  id.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                  let path = request.hostPath, path.hasPrefix("/"), let readOnly = request.readOnly else {
                throw invalid("extra export requires an ID, absolute directory and explicit access mode")
            }
            let url = URL(fileURLWithPath: path).resolvingSymlinksInPath().standardizedFileURL
            let values = try url.resourceValues(forKeys: [.isDirectoryKey])
            guard values.isDirectory == true, url.path == path else {
                throw invalid("extra export source changed or is not a resolved directory")
            }
            if let previous = entries[id] {
                guard previous.path == path, previous.readOnly == readOnly else {
                    throw invalid("extra export ID already selects another directory or mode")
                }
            } else {
                var next = entries
                next[id] = Entry(path: path, readOnly: readOnly,
                    directory: VZSharedDirectory(url: url, readOnly: readOnly))
                // Keep every unchanged VZSharedDirectory object. Recreating an
                // existing object can invalidate its guest bind mount.
                live.share = VZMultipleDirectoryShare(directories: next.mapValues(\.directory))
                entries = next
            }
        } else if request.operation == "remove" {
            if let tag = request.tag {
                guard tag.hasPrefix("extra"), !tag.dropFirst(5).isEmpty,
                      tag.dropFirst(5).allSatisfy(\.isNumber),
                      let device = devices.first(where: { $0.tag == tag }) else {
                    throw invalid("ordinary startup extra-directory device is missing")
                }
                device.share = nil
            } else {
                guard let live, let id = request.id else { throw invalid("extra export device or ID is missing") }
                var next = entries
                next.removeValue(forKey: id)
                live.share = VZMultipleDirectoryShare(directories: next.mapValues(\.directory))
                entries = next
            }
        } else if request.operation != "list" {
            throw invalid("unknown extra-directory operation")
        }
        return ["prepared": live != nil,
            "exports": entries.sorted { $0.key < $1.key }.map { id, entry in
                ["id": id, "host_path": entry.path, "read_only": entry.readOnly] as [String: Any]
            },
            "startup_tags": devices.filter { $0.tag.hasPrefix("extra") && $0.share != nil }.map(\.tag)]
    }
}
