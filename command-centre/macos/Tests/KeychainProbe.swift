import Foundation

@main
struct KeychainProbe {
    static func main() throws {
        let store = NativeKeychainStore()
        let account = "sy-native-keychain-probe-\(UUID().uuidString)"
        let first = UUID().uuidString
        let replacement = UUID().uuidString
        defer { try? store.delete(account: account) }

        let initiallyMissing = try store.load(account: account)
        precondition(initiallyMissing == nil)
        try store.store(account: account, token: first)
        let loadedFirst = try store.load(account: account)
        precondition(loadedFirst == first)
        try store.store(account: account, token: replacement)
        let loadedReplacement = try store.load(account: account)
        precondition(loadedReplacement == replacement)
        try store.delete(account: account)
        let deleted = try store.load(account: account)
        precondition(deleted == nil)
        print("keychain-probe: PASS operations=store,retrieve,replace,delete")
    }
}
