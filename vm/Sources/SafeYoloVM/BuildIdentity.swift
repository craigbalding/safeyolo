import Foundation
import MachO
import Security

/// Build metadata is embedded in the signed executable, independent of its path.
/// Direct `swift build` remains usable and reports an unmanaged build explicitly.
enum BuildIdentity {
    static let current: [String: Any] = capture()

    private static func embedded() -> [String: Any] {
        guard let header = _dyld_get_image_header(0) else { return [:] }
        let header64 = UnsafeRawPointer(header).assumingMemoryBound(to: mach_header_64.self)
        var size: UInt = 0
        guard let bytes = getsectiondata(header64, "__TEXT", "__sy_build", &size) else { return [:] }
        let data = Data(bytes: bytes, count: Int(size))
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
    }

    private static func capture() -> [String: Any] {
        var identity = embedded()
        identity["schema_version"] = 1
        identity["helper_version"] = helperVersion
        identity["version"] = identity["version"] ?? "unknown"
        identity["git_sha"] = identity["git_sha"] ?? "unknown"
        identity["git_dirty"] = identity["git_dirty"] ?? NSNull()
        identity["build_profile"] = identity["build_profile"] ?? "unmanaged"
        identity["swift_compiler"] = identity["swift_compiler"] ?? "unknown"
        identity["optimization"] = identity["optimization"] ?? "unknown"
        identity["symbols"] = identity["symbols"] ?? "unknown"
        #if arch(arm64)
        identity["architecture"] = "arm64"
        #elseif arch(x86_64)
        identity["architecture"] = "x86_64"
        #else
        identity["architecture"] = "unknown"
        #endif
        identity["get_task_allow"] = NSNull()
        identity["hardened_runtime"] = NSNull()

        var code: SecCode?
        let selfStatus = SecCodeCopySelf([], &code)
        guard selfStatus == errSecSuccess, let code else {
            identity["signature_error"] = selfStatus
            return identity
        }
        var signingInfo: CFDictionary?
        // SecCode.h explicitly accepts a dynamic SecCode object here. The Swift
        // import exposes only SecStaticCode, so preserve the underlying CF object.
        let status = SecCodeCopySigningInformation(
            unsafeBitCast(code, to: SecStaticCode.self),
            SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSDynamicInformation),
            &signingInfo
        )
        guard status == errSecSuccess, let info = signingInfo as? [String: Any],
              let flags = info[kSecCodeInfoStatus as String] as? UInt32 else {
            identity["signature_error"] = status
            return identity
        }
        // Dynamic csflags describe this running process even if its disk file
        // is subsequently re-signed. CS_GET_TASK_ALLOW=0x4, CS_RUNTIME=0x10000.
        identity["get_task_allow"] = flags & 0x4 != 0
        identity["hardened_runtime"] = flags & 0x10000 != 0
        return identity
    }

    static var summary: String {
        let value = current
        let debug = (value["get_task_allow"] as? Bool).map { $0 ? "yes" : "no" } ?? "unknown"
        let dirty = (value["git_dirty"] as? Bool).map { $0 ? "dirty" : "clean" } ?? "unknown"
        return "safeyolo-vm \(helperVersion) safeyolo=\(value["version"]!) git=\(value["git_sha"]!) tree=\(dirty) profile=\(value["build_profile"]!) arch=\(value["architecture"]!) debuggable=\(debug)"
    }

    static func printVersion(json: Bool) {
        if json {
            do {
                let data = try JSONSerialization.data(withJSONObject: current, options: [.sortedKeys])
                print(String(decoding: data, as: UTF8.self))
            } catch {
                fputs("Error: cannot encode VM helper identity: \(error)\n", stderr)
                exit(1)
            }
        } else {
            print(summary)
        }
    }
}
