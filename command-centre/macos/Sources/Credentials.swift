import Foundation
import Security

private let keychainService = "io.safeyolo.command-centre"

protocol CredentialStore {
    func load(account: String) throws -> String?
    func store(account: String, token: String) throws
    func delete(account: String) throws
}

struct NativeKeychainStore: CredentialStore {
    func load(account: String) throws -> String? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        try check(status, operation: "read")
        guard let data = result as? Data,
              let token = String(data: data, encoding: .utf8)
        else {
            throw CredentialError.invalidKeychainValue
        }
        return token
    }

    func store(account: String, token: String) throws {
        let value = Data(token.utf8)
        let query = baseQuery(account: account)
        let update = [kSecValueData as String: value]
        let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        if updateStatus != errSecItemNotFound {
            try check(updateStatus, operation: "replace")
        }

        var addition = query
        addition[kSecValueData as String] = value
        try check(SecItemAdd(addition as CFDictionary, nil), operation: "store")
    }

    func delete(account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound {
            return
        }
        try check(status, operation: "delete")
    }

    private func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
        ]
    }

    private func check(_ status: OSStatus, operation: String) throws {
        guard status != errSecSuccess else {
            return
        }
        let detail = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        throw CredentialError.keychain(operation: operation, detail: detail)
    }
}

struct LoadedCredential {
    enum Source: String {
        case keychain
        case file
    }

    let instanceID: String
    let token: String
    let source: Source
    let warning: String?
}

struct LocalCredentialLoader {
    let configDirectory: URL
    let keychain: any CredentialStore

    static func live() -> LocalCredentialLoader {
        let environment = ProcessInfo.processInfo.environment
        let configDirectory: URL
        if let override = environment["SAFEYOLO_CONFIG_DIR"], !override.isEmpty {
            configDirectory = URL(fileURLWithPath: override, isDirectory: true)
        } else {
            configDirectory = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".safeyolo", isDirectory: true)
        }
        return LocalCredentialLoader(
            configDirectory: configDirectory,
            keychain: NativeKeychainStore()
        )
    }

    func load() throws -> LoadedCredential {
        let instanceID = try readValue(
            at: configDirectory.appendingPathComponent("data/coord/instance_id"),
            label: "SafeYolo instance ID"
        )
        var warning: String?
        do {
            if let token = try keychain.load(account: instanceID), !token.isEmpty {
                return LoadedCredential(
                    instanceID: instanceID,
                    token: token,
                    source: .keychain,
                    warning: nil
                )
            }
        } catch {
            warning = error.localizedDescription
        }

        let token = try readValue(
            at: configDirectory.appendingPathComponent("data/admin_token"),
            label: "local Admin API credential"
        )
        do {
            try keychain.store(account: instanceID, token: token)
        } catch {
            warning = error.localizedDescription
        }
        return LoadedCredential(
            instanceID: instanceID,
            token: token,
            source: .file,
            warning: warning
        )
    }

    private func readValue(at url: URL, label: String) throws -> String {
        let value: String
        do {
            value = try String(contentsOf: url, encoding: .utf8)
                .trimmingCharacters(in: .whitespacesAndNewlines)
        } catch {
            throw CredentialError.unavailable("\(label) is unavailable at \(url.path)")
        }
        guard !value.isEmpty else {
            throw CredentialError.unavailable("\(label) is empty at \(url.path)")
        }
        return value
    }
}

enum CredentialError: LocalizedError {
    case unavailable(String)
    case invalidKeychainValue
    case keychain(operation: String, detail: String)

    var errorDescription: String? {
        switch self {
        case .unavailable(let message):
            return message
        case .invalidKeychainValue:
            return "The Keychain credential is not valid UTF-8"
        case .keychain(let operation, let detail):
            return "Could not \(operation) the Admin API credential in Keychain: \(detail)"
        }
    }
}
