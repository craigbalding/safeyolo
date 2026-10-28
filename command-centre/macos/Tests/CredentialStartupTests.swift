import AppKit
import Foundation
import SwiftUI

private enum SyntheticCredentialError: LocalizedError {
    case refused
    var errorDescription: String? { "Synthetic Keychain refusal" }
}

private final class HeldCredentialStore: CredentialStore, @unchecked Sendable {
    private let lock = NSLock()
    private var tokens: [String: String]
    private var reads: [String] = []
    private var writes: [String] = []
    private var returnedReads = 0
    private var returnedWrites = 0
    let readGate: DispatchSemaphore?
    let writeGate: DispatchSemaphore?
    let refuseRead: Bool
    let refuseWrite: Bool

    init(tokens: [String: String] = [:], holdRead: Bool = false, holdWrite: Bool = false,
         refuseRead: Bool = false, refuseWrite: Bool = false) {
        self.tokens = tokens
        self.readGate = holdRead ? DispatchSemaphore(value: 0) : nil
        self.writeGate = holdWrite ? DispatchSemaphore(value: 0) : nil
        self.refuseRead = refuseRead
        self.refuseWrite = refuseWrite
    }

    var readAccounts: [String] { lock.withLock { reads } }
    var writeAccounts: [String] { lock.withLock { writes } }
    var readsFinished: Int { lock.withLock { returnedReads } }
    var writesFinished: Int { lock.withLock { returnedWrites } }
    func token(_ account: String) -> String? { lock.withLock { tokens[account] } }

    func load(account: String) throws -> String? {
        precondition(!Thread.isMainThread, "Native reads must not run on the main thread")
        lock.withLock { reads.append(account) }
        defer { lock.withLock { returnedReads += 1 } }
        // Test-only ceiling catches a caller deadlock without leaving a worker held.
        if let readGate { precondition(readGate.wait(timeout: .now() + 8) == .success) }
        if refuseRead { throw SyntheticCredentialError.refused }
        return token(account)
    }

    func store(account: String, token: String) throws {
        precondition(!Thread.isMainThread, "Native writes must not run on the main thread")
        lock.withLock { writes.append(account) }
        defer { lock.withLock { returnedWrites += 1 } }
        if let writeGate { precondition(writeGate.wait(timeout: .now() + 8) == .success) }
        if refuseWrite { throw SyntheticCredentialError.refused }
        lock.withLock { tokens[account] = token }
    }

    func delete(account: String) throws { _ = lock.withLock { tokens.removeValue(forKey: account) } }
}

private final class MemoryConnectionProfiles: ConnectionProfileStore {
    var profile: RemoteConnectionProfile?
    var saved: [RemoteConnectionProfile] = []
    init(_ profile: RemoteConnectionProfile? = nil) { self.profile = profile }
    func load() throws -> RemoteConnectionProfile? { profile }
    func save(_ profile: RemoteConnectionProfile) throws { self.profile = profile; saved.append(profile) }
    func delete() throws { profile = nil }
}

private final class HeldVerification: @unchecked Sendable {
    private let lock = NSLock()
    private var reached = false
    let gate = DispatchSemaphore(value: 0)
    var started: Bool { lock.withLock { reached } }
    func hold() {
        lock.withLock { reached = true }
        precondition(gate.wait(timeout: .now() + 8) == .success)
    }
}

extension ModelTests {
    @MainActor
    static func testCredentialStartup() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("commander-credentials-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("data"), withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: root)
            StubURLProtocol.responsesByPath = [:]
            StubURLProtocol.requestHandler = nil
        }
        try Data("sy-file-test\n".utf8).write(to: root.appendingPathComponent("data/instance_id"))
        try Data("synthetic-file-token\n".utf8).write(to: root.appendingPathComponent("data/admin_token"))
        try await testHeldReadAndFileUse(root)
        try await testRejectedFilePreservesKeychain(root)
        try await testRejectedFilePreservesConnection(root)
        try await testLateFileVerification(root)
        try await testCredentialReturnsAndMissingFile(root)
        try Data("synthetic-file-token\n".utf8).write(to: root.appendingPathComponent("data/admin_token"))
        try await testSavedProfileIdentity(root)
        try await testRemoteImportAndNewSelection(root)
        try await testRemoteVerificationRefusal(root)
        try await testLateRemoteVerification(root)
        try await testConcurrentInstances(root)
    }

    @MainActor
    private static func credentialUntil(file: StaticString = #fileID, line: UInt = #line, _ condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(4)
        while !condition(), Date() < deadline { try await Task.sleep(for: .milliseconds(5)) }
        precondition(condition(), "Credential caller did not reach the expected state", file: file, line: line)
    }

    private static func credentialSnapshot(_ instance: String) {
        StubURLProtocol.requestHandler = nil
        StubURLProtocol.failuresRemaining = 0
        StubURLProtocol.responsesByPath = [
            "/admin/instance": (200, Data("{\"schema_version\":1,\"safeyolo_instance_id\":\"\(instance)\",\"command_centre_events\":{\"enabled\":false}}".utf8)),
            "/admin/agents": (200, Data(#"{"agents":[]}"#.utf8)),
            "/admin/approvals": (200, Data(#"{"approvals":[]}"#.utf8)),
        ]
    }

    @MainActor
    private static func credentialController(_ root: URL, _ store: HeldCredentialStore,
                                             _ profiles: MemoryConnectionProfiles = MemoryConnectionProfiles()) -> CommandCentreController {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: config)
        return CommandCentreController(presenter: ApprovalWindowPresenter(), securityNotifier: SecurityNotificationPresenter(),
            keychain: store, profileStore: profiles, verifier: RemoteConnectionVerifier(session: session),
            localCredentialDirectory: root, session: session)
    }

    @MainActor
    private static func settingsViews(_ window: NSWindow) -> [NSView] {
        var pending = [window.contentView!]
        var views: [NSView] = []
        while let view = pending.popLast() { views.append(view); pending.append(contentsOf: view.subviews) }
        return views
    }

    @MainActor
    private static func testHeldReadAndFileUse(_ root: URL) async throws {
        credentialSnapshot("sy-file-test")
        let store = HeldCredentialStore(tokens: ["sy-file-test": "synthetic-keychain-token"], holdRead: true, holdWrite: true)
        let controller = credentialController(root, store)
        defer { controller.stop(); store.readGate?.signal(); store.writeGate?.signal() }
        controller.start(commandLine: CommandLineConfiguration(adminURL: "http://127.0.0.1:19190", eventsURL: "ws://127.0.0.1:19191/admin/events"))
        try await credentialUntil { store.readAccounts == ["sy-file-test"] }
        precondition(controller.localConnection.client == nil && controller.localConnection.startupError == nil)
        precondition(controller.localConnection.credentialStatus?.contains("Waiting for Keychain") == true)
        let settings = ConnectionSettingsWindowPresenter()
        settings.show(controller: controller)
        let window = NSApp.windows.first { $0.title == "SafeYolo Connection" }!
        defer { window.close() }
        var heartbeat = false
        DispatchQueue.main.async { heartbeat = true }
        try await credentialUntil {
            window.contentView!.layoutSubtreeIfNeeded()
            window.displayIfNeeded()
            return heartbeat && settingsViews(window).filter { $0.canBecomeKeyView }.count >= 4
        }
        let content = window.contentView!
        precondition(content.fittingSize.height <= content.bounds.height + 1, "Settings actions must fit outside the scrolling form")
        precondition(settingsViews(window).contains { $0 is NSScrollView }, "Settings and returned errors must remain reachable")
        controller.localConnection.useCredentialFile()
        try await credentialUntil { controller.localConnection.client?.adminConnected == true && store.writeAccounts.count == 1 }
        precondition(StubURLProtocol.observedAuthorization == "Bearer synthetic-file-token")
        precondition(store.readsFinished == 0 && store.writesFinished == 0, "Connection must precede held read and import returns")
        precondition(controller.localConnection.credentialStatus?.contains("Credential loaded for this session") == true)
        let connected = controller.localConnection.client
        store.readGate?.signal()
        try await credentialUntil { store.readsFinished == 1 }
        try await Task.sleep(for: .milliseconds(50))
        precondition(controller.localConnection.client === connected, "Late Keychain read must not replace the selected file connection")
        controller.stop()
        store.writeGate?.signal()
        try await credentialUntil { store.writesFinished == 1 }
        try await Task.sleep(for: .milliseconds(50))
        precondition(controller.localConnection.client == nil && controller.localConnection.credentialStatus == nil, "Late import must not revive a disconnected client")
        print("credential-callers: held native read/import, main heartbeat, rendered settings, matching-file connection and late disconnect PASS")
    }

    @MainActor
    private static func testRejectedFilePreservesKeychain(_ root: URL) async throws {
        let refusals: [(name: String, error: String, response: () throws -> (Int, Data))] = [
            ("HTTP refusal", "403", { (403, Data()) }),
            ("backend identity", "expected sy-file-test", {
                (200, Data(#"{"schema_version":1,"safeyolo_instance_id":"sy-other-backend"}"#.utf8))
            }),
            ("transport error", URLError(.cannotConnectToHost).localizedDescription, {
                throw URLError(.cannotConnectToHost)
            }),
        ]
        for refusal in refusals {
            credentialSnapshot("sy-file-test")
            let responses = StubURLProtocol.responsesByPath
            StubURLProtocol.requestHandler = { request in
                if request.url!.path == "/admin/instance",
                   request.value(forHTTPHeaderField: "Authorization") == "Bearer synthetic-file-token" {
                    return try refusal.response()
                }
                return responses[request.url!.path] ?? (404, Data())
            }
            let store = HeldCredentialStore(tokens: ["sy-file-test": "synthetic-keychain-token"], holdRead: true)
            let controller = credentialController(root, store)
            defer { controller.stop(); store.readGate?.signal(); StubURLProtocol.requestHandler = nil }
            controller.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
            try await credentialUntil { store.readAccounts == ["sy-file-test"] }
            controller.localConnection.useCredentialFile()
            try await credentialUntil { controller.localConnection.startupError?.contains(refusal.error) == true }
            precondition(controller.localConnection.client == nil && controller.localConnection.credentialStatus == nil)
            precondition(store.writeAccounts.isEmpty && store.token("sy-file-test") == "synthetic-keychain-token",
                         "Rejected file credentials must not replace a saved token")
            store.readGate?.signal()
            try await credentialUntil { store.readsFinished == 1 && controller.localConnection.client?.adminConnected == true }
            precondition(controller.localConnection.client?.instanceID == "sy-file-test" && controller.localConnection.startupError == nil,
                         "File verification failure must leave the pending native read usable")
            precondition(StubURLProtocol.observedAuthorization == "Bearer synthetic-keychain-token")
            precondition(store.writeAccounts.isEmpty && store.token("sy-file-test") == "synthetic-keychain-token")
            controller.stop()
            print("credential-callers: rejected file \(refusal.name), saved token and pending Keychain recovery PASS")
        }
    }

    @MainActor
    private static func testRejectedFilePreservesConnection(_ root: URL) async throws {
        credentialSnapshot("sy-file-test")
        let responses = StubURLProtocol.responsesByPath
        StubURLProtocol.requestHandler = { request in
            if request.url!.path == "/admin/instance",
               request.value(forHTTPHeaderField: "Authorization") == "Bearer synthetic-file-token" {
                return (403, Data())
            }
            return responses[request.url!.path] ?? (404, Data())
        }
        let store = HeldCredentialStore(tokens: ["sy-file-test": "synthetic-keychain-token"])
        let controller = credentialController(root, store)
        defer { controller.stop(); StubURLProtocol.requestHandler = nil }
        controller.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        try await credentialUntil { controller.localConnection.client?.adminConnected == true }
        let connected = controller.localConnection.client!
        controller.localConnection.useCredentialFile()
        try await credentialUntil { controller.localConnection.startupError?.contains("403") == true }
        precondition(controller.localConnection.client === connected && connected.adminConnected && connected.connectionState != .stopped,
                     "A rejected file must not stop an authenticated Keychain client")
        precondition(controller.localConnection.credentialStatus == nil && store.writeAccounts.isEmpty)
        precondition(store.token("sy-file-test") == "synthetic-keychain-token")
        let stillAuthenticated = await connected.refreshInstance()
        precondition(stillAuthenticated, "The original client must retain its working credential")
        precondition(StubURLProtocol.observedAuthorization == "Bearer synthetic-keychain-token")
        print("credential-callers: rejected file preserves the authenticated client and saved token PASS")
    }

    @MainActor
    private static func testLateFileVerification(_ root: URL) async throws {
        for disconnect in [false, true] {
            credentialSnapshot("sy-file-test")
            let responses = StubURLProtocol.responsesByPath
            let held = HeldVerification()
            StubURLProtocol.requestHandler = { request in
                if request.url!.path == "/admin/instance",
                   request.value(forHTTPHeaderField: "Authorization") == "Bearer synthetic-file-token" {
                    held.hold()
                }
                return responses[request.url!.path] ?? (404, Data())
            }
            let store = HeldCredentialStore(tokens: ["sy-file-test": "synthetic-keychain-token"])
            let profiles = MemoryConnectionProfiles()
            let controller = credentialController(root, store, profiles)
            defer { controller.stop(); held.gate.signal(); StubURLProtocol.requestHandler = nil }
            controller.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
            try await credentialUntil { controller.localConnection.client?.adminConnected == true }
            let connected = controller.localConnection.client!
            controller.localConnection.useCredentialFile()
            try await credentialUntil { held.started }
            var heartbeat = false
            DispatchQueue.main.async { heartbeat = true }
            try await credentialUntil { heartbeat }
            precondition(controller.localConnection.client === connected && connected.connectionState != .stopped && store.writeAccounts.isEmpty,
                         "An unfinished file check must preserve the working connection")
            if disconnect {
                controller.stop()
            } else {
                // A newer selection uses its own legitimate Keychain read.
                controller.start(commandLine: CommandLineConfiguration(adminURL: "http://newer.example", eventsURL: "ws://newer.example/events"))
                try await credentialUntil { store.readsFinished == 2 && controller.localConnection.client != nil }
            }
            let newer = controller.localConnection.client
            held.gate.signal()
            if !disconnect { try await credentialUntil { newer?.adminConnected == true } }
            try await Task.sleep(for: .milliseconds(100))
            precondition(controller.localConnection.client === newer && controller.localConnection.startupError == nil && controller.localConnection.credentialStatus == nil,
                         "A late verified file must not replace a newer selection or revive a disconnected client")
            precondition(store.writeAccounts.isEmpty && profiles.saved.isEmpty)
            precondition(store.token("sy-file-test") == "synthetic-keychain-token")
            print("credential-callers: held file verification, main heartbeat and late \(disconnect ? "disconnect" : "selection") PASS")
        }
    }

    @MainActor
    private static func testCredentialReturnsAndMissingFile(_ root: URL) async throws {
        credentialSnapshot("sy-file-test")
        let keychain = HeldCredentialStore(tokens: ["sy-file-test": "synthetic-keychain-token"])
        let controller = credentialController(root, keychain)
        defer { controller.stop() }
        controller.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        try await credentialUntil { controller.localConnection.client?.adminConnected == true }
        precondition(StubURLProtocol.observedAuthorization == "Bearer synthetic-keychain-token")
        precondition(keychain.writeAccounts.isEmpty && controller.localConnection.credentialStatus == nil)
        let keychainClient = controller.localConnection.client
        try Data().write(to: root.appendingPathComponent("data/admin_token"))
        controller.localConnection.useCredentialFile()
        try await credentialUntil { controller.localConnection.startupError?.contains("empty") == true }
        precondition(controller.localConnection.client === keychainClient && keychain.writeAccounts.isEmpty, "An unusable file must not disconnect a working Keychain session")
        try Data("synthetic-file-token\n".utf8).write(to: root.appendingPathComponent("data/admin_token"))
        controller.stop()

        let refusal = HeldCredentialStore(refuseRead: true, refuseWrite: true)
        let fallback = credentialController(root, refusal)
        defer { fallback.stop() }
        fallback.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        try await credentialUntil { fallback.localConnection.client?.adminConnected == true && refusal.writesFinished == 1 && fallback.localConnection.credentialStatus == nil }
        precondition(StubURLProtocol.observedAuthorization == "Bearer synthetic-file-token")
        precondition(fallback.localConnection.startupError?.contains("available for this session") == true)
        fallback.stop()

        try FileManager.default.removeItem(at: root.appendingPathComponent("data/admin_token"))
        let absent = credentialController(root, HeldCredentialStore())
        defer { absent.stop() }
        absent.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        try await credentialUntil { absent.localConnection.startupError != nil }
        precondition(absent.localConnection.client == nil && absent.localConnection.startupError!.contains("unavailable"))
        absent.localConnection.useCredentialFile()
        try await credentialUntil { absent.localConnection.credentialStatus == nil }
        precondition(absent.localConnection.client == nil && absent.localConnection.startupError!.contains("unavailable"))
        print("credential-callers: Keychain hit, returned read/import errors and missing private file PASS")
    }

    @MainActor
    private static func testSavedProfileIdentity(_ root: URL) async throws {
        let profile = RemoteConnectionProfile(friendlyName: "Saved remote", adminURL: "https://remote.example", eventsURL: "wss://remote.example/events", instanceID: "sy-remote-test")
        let profiles = MemoryConnectionProfiles(profile)
        credentialSnapshot(profile.instanceID)
        let store = HeldCredentialStore(tokens: [profile.instanceID: "synthetic-remote-token"], holdRead: true)
        let controller = credentialController(root, store, profiles)
        defer { controller.stop(); store.readGate?.signal() }
        precondition(controller.remoteConnection.restoreRemote())
        try await credentialUntil { store.readAccounts == [profile.instanceID] }
        controller.remoteConnection.useCredentialFile()
        try await credentialUntil { controller.remoteConnection.startupError != nil }
        precondition(controller.remoteConnection.client == nil && controller.remoteConnection.startupError!.contains("expected sy-remote-test"))
        precondition(store.writeAccounts.isEmpty && profiles.profile == profile)
        store.readGate?.signal()
        try await credentialUntil { store.readsFinished == 1 && controller.remoteConnection.client?.adminConnected == true }
        precondition(StubURLProtocol.observedAuthorization == "Bearer synthetic-remote-token", "An invalid file must leave legitimate Keychain access available")
        controller.stop()

        credentialSnapshot(profile.instanceID)
        let saved = credentialController(root, HeldCredentialStore(tokens: [profile.instanceID: "synthetic-remote-token"]), profiles)
        defer { saved.stop() }
        precondition(saved.remoteConnection.restoreRemote())
        try await credentialUntil { saved.remoteConnection.client?.adminConnected == true }
        precondition(saved.remoteConnection.client?.instanceID == profile.instanceID && saved.remoteConnection.connectionName == profile.friendlyName)
        saved.stop()
        let missing = credentialController(root, HeldCredentialStore(), profiles)
        defer { missing.stop() }
        precondition(missing.remoteConnection.restoreRemote())
        try await credentialUntil { missing.remoteConnection.startupError != nil }
        precondition(missing.remoteConnection.client == nil && missing.remoteConnection.startupError!.contains("No Keychain credential"))
        print("credential-callers: saved remote account, mismatched-file refusal, Keychain-only startup and returned missing credential PASS")
    }

    @MainActor
    private static func testRemoteImportAndNewSelection(_ root: URL) async throws {
        credentialSnapshot("sy-remote-test")
        let store = HeldCredentialStore(holdRead: true, holdWrite: true)
        let profiles = MemoryConnectionProfiles()
        let controller = credentialController(root, store, profiles)
        defer { controller.stop(); store.readGate?.signal(); store.writeGate?.signal(); store.writeGate?.signal() }
        controller.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        try await credentialUntil { store.readAccounts.count == 1 }
        var first: Result<RemoteConnectionProfile, Error>?
        controller.configureRemote(RemoteConnectionInput(friendlyName: "First remote", adminURL: "https://remote.example", eventsURL: "wss://remote.example/events", token: "synthetic-first-token")) { first = $0 }
        try await credentialUntil { first != nil && controller.remoteConnection.client?.adminConnected == true && store.writeAccounts.count == 1 }
        _ = try first!.get()
        precondition(profiles.saved.isEmpty && store.writesFinished == 0, "Connect and settings completion cannot wait for optional storage")
        var newer: Result<RemoteConnectionProfile, Error>?
        controller.configureRemote(RemoteConnectionInput(friendlyName: "Newer remote", adminURL: "https://newer.example", eventsURL: "wss://newer.example/events", token: "synthetic-newer-token")) { newer = $0 }
        try await credentialUntil { newer != nil && controller.remoteConnection.client?.adminConnected == true }
        let newerProfile = try newer!.get()
        precondition(controller.remoteProfile == newerProfile, "Settings and terminals must use the current profile while storage is pending")
        store.readGate?.signal()
        store.writeGate?.signal()
        store.writeGate?.signal()
        try await credentialUntil { store.readsFinished == 1 && store.writesFinished == 2 && profiles.profile == newerProfile }
        precondition(controller.remoteConnection.connectionName == "Newer remote" && controller.remoteConnection.client?.instanceID == "sy-remote-test")
        precondition(profiles.saved == [newerProfile] && store.token("sy-remote-test") == "synthetic-newer-token")
        controller.stop()
        print("credential-callers: remote verification, held import, immediate settings completion and newer-selection persistence PASS")
    }

    @MainActor
    private static func testRemoteVerificationRefusal(_ root: URL) async throws {
        credentialSnapshot("sy-remote-test")
        StubURLProtocol.responsesByPath["/admin/instance"] = (403, Data())
        let store = HeldCredentialStore()
        let controller = credentialController(root, store)
        defer { controller.stop() }
        var result: Result<RemoteConnectionProfile, Error>?
        controller.configureRemote(RemoteConnectionInput(friendlyName: "Refused", adminURL: "https://remote.example", eventsURL: "wss://remote.example/events", token: "synthetic-refused-token")) { result = $0 }
        try await credentialUntil { result != nil }
        guard case .failure = result! else { preconditionFailure("A refused backend must not connect") }
        precondition(controller.remoteConnection.client == nil && store.writeAccounts.isEmpty && controller.remoteConnection.startupError?.contains("403") == true)
        precondition(controller.remoteConnection.credentialStatus == nil)
        print("credential-callers: returned backend refusal with usable settings/error state PASS")
    }

    @MainActor
    private static func testLateRemoteVerification(_ root: URL) async throws {
        credentialSnapshot("sy-remote-test")
        let held = HeldVerification()
        StubURLProtocol.requestHandler = { _ in
            held.hold()
            return (200, Data(#"{"schema_version":1,"safeyolo_instance_id":"sy-remote-test"}"#.utf8))
        }
        defer { held.gate.signal(); StubURLProtocol.requestHandler = nil }
        let store = HeldCredentialStore()
        let profiles = MemoryConnectionProfiles()
        let controller = credentialController(root, store, profiles)
        defer { controller.stop() }
        var result: Result<RemoteConnectionProfile, Error>?
        controller.configureRemote(RemoteConnectionInput(friendlyName: "Late remote", adminURL: "https://remote.example", eventsURL: "wss://remote.example/events", token: "synthetic-late-token")) { result = $0 }
        try await credentialUntil { held.started }
        controller.stop()
        held.gate.signal()
        try await credentialUntil { result != nil }
        guard case .failure(let error) = result!, error is CancellationError else {
            preconditionFailure("A superseded verification must report cancellation")
        }
        precondition(controller.remoteConnection.client == nil && controller.remoteConnection.credentialStatus == nil && controller.remoteConnection.startupError == nil)
        precondition(profiles.saved.isEmpty && store.writeAccounts.isEmpty)
        print("credential-callers: late remote verification cannot reconnect or save after disconnect PASS")
    }
}

// Two authenticated endpoints exercise the real controller and URLSession clients.
// Resource names and IDs deliberately overlap across the two instance identities.
private final class ConcurrentInstanceEndpoints: @unchecked Sendable {
    private let lock = NSLock()
    private var requests: [(host: String, path: String, method: String, authorization: String)] = []
    private var remoteStatus = 200
    private var remoteID = "sy-remote-test"
    private var states = ["local": "stopped", "remote": "stopped"]
    private var decisions = ["local": "pending", "remote": "pending"]

    func remote(status: Int = 200, instanceID: String = "sy-remote-test") {
        lock.withLock { remoteStatus = status; remoteID = instanceID }
    }
    var posts: [(host: String, path: String, method: String, authorization: String)] {
        lock.withLock { requests.filter { $0.method == "POST" } }
    }

    func respond(_ request: URLRequest) throws -> (Int, Data) {
        try lock.withLock {
            let host = request.url!.host!
            let path = request.url!.path
            let method = request.httpMethod ?? "GET"
            let auth = request.value(forHTTPHeaderField: "Authorization") ?? ""
            requests.append((host, path, method, auth))
            guard ["127.0.0.1", "remote.example"].contains(host) else { return (404, Data()) }
            let key = host == "remote.example" ? "remote" : "local"
            let token = key == "remote" ? "synthetic-remote-token" : "synthetic-local-token"
            guard auth == "Bearer \(token)" else { return (401, Data()) }
            if key == "remote", remoteStatus != 200 { return (remoteStatus, Data()) }
            func json(_ value: [String: Any]) throws -> (Int, Data) {
                (200, try JSONSerialization.data(withJSONObject: value))
            }
            func agent() -> [String: Any] {
                ["agent_id": "ag-shared", "name": "worker", "sandbox_state": "running",
                 "agent_state": states[key]!, "attachable": true, "exec": true]
            }
            func outcome() -> [String: Any] {
                ["approval_id": "apr-shared", "request_id": "req-shared", "status": decisions[key]!,
                 "effect": "\(key) network access"]
            }
            switch path {
            case "/admin/instance":
                return try json(["schema_version": 1, "safeyolo_instance_id": key == "remote" ? remoteID : "sy-file-test",
                    "host_user": key == "remote" ? "remote-user" : "local-user",
                    "host_executable": "/\(key)/bin/safeyolo", "host_root": "/\(key)/instance",
                    "command_centre_events": ["enabled": false]])
            case "/admin/agents": return try json(["agents": [agent()]])
            case "/admin/approvals":
                let approval: [String: Any] = ["approval_id": "apr-shared", "request_id": "req-shared",
                    "event": "proxy.network_guard", "agent": "worker", "summary": "\(key) network access",
                    "approval": ["required": true, "approval_type": "network_egress", "key": "same-target", "target": "example.test:443"]]
                return try json(["approvals": decisions[key] == "pending" ? [approval] : []])
            case "/admin/approvals/apr-shared":
                if method == "POST" {
                    let stream = request.httpBodyStream
                    stream?.open()
                    defer { stream?.close() }
                    var bytes = [UInt8](repeating: 0, count: 1024)
                    let count = stream?.read(&bytes, maxLength: bytes.count) ?? 0
                    let body = request.httpBody ?? Data(bytes.prefix(max(0, count)))
                    let payload = try JSONSerialization.jsonObject(with: body) as! [String: String]
                    decisions[key] = payload["decision"] == "approve" ? "approved" : "rejected"
                }
                return try json(outcome())
            case "/admin/agents/ag-shared/start", "/admin/agents/ag-shared/stop":
                states[key] = path.hasSuffix("/start") ? "running" : "stopped"
                return try json(agent())
            case "/admin/agents/ag-shared/desktop/present":
                return try json(["url": key == "remote" ? "https://remote.example/desktop" : "http://127.0.0.1:5901/desktop",
                                 "unlock_code": "\(key)-unlock", "agent_id": "ag-shared", "agent": "worker", "reused": false])
            default: return (404, Data())
            }
        }
    }
}

extension ModelTests {
    @MainActor
    private static func testConcurrentInstances(_ root: URL) async throws {
        let endpoints = ConcurrentInstanceEndpoints()
        StubURLProtocol.requestHandler = { try endpoints.respond($0) }
        defer { StubURLProtocol.requestHandler = nil }
        let profile = RemoteConnectionProfile(friendlyName: "Development host", adminURL: "https://remote.example",
            eventsURL: "wss://remote.example/events", instanceID: "sy-remote-test", terminalTarget: "ops@remote.example")
        let profiles = MemoryConnectionProfiles(profile)
        let store = HeldCredentialStore(tokens: ["sy-file-test": "synthetic-local-token", "sy-remote-test": "synthetic-remote-token"])
        let presenter = ApprovalWindowPresenter()
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: config)
        let controller = CommandCentreController(presenter: presenter, securityNotifier: SecurityNotificationPresenter(),
            keychain: store, profileStore: profiles, verifier: RemoteConnectionVerifier(session: session),
            localCredentialDirectory: root, session: session)
        defer { controller.stop() }
        controller.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        try await credentialUntil {
            controller.localConnection.client?.approvals.count == 1 && controller.remoteConnection.client?.approvals.count == 1
                && controller.localConnection.client?.agents.count == 1 && controller.remoteConnection.client?.agents.count == 1
        }
        let local = controller.localConnection.client!
        var remote = controller.remoteConnection.client!
        let localAgent = local.agents[0]
        let remoteAgent = remote.agents[0]
        let localApproval = local.approvals[0]
        let remoteApproval = remote.approvals[0]
        precondition(controller.connections.count == 2 && controller.hasConnectedInstance && controller.hasPendingApprovals)
        precondition(local.instanceID == "sy-file-test" && remote.instanceID == profile.instanceID)
        precondition(localAgent.id == remoteAgent.id && localAgent.name == remoteAgent.name && localApproval.id == remoteApproval.id)
        let windows = NSApp.windows.filter { $0.identifier?.rawValue == "apr-shared" }
        precondition(windows.count == 2 && windows.contains { $0.title.contains("sy-file-test") }
            && windows.contains { $0.title.contains(profile.instanceID) }, "Each instance needs its own labelled approval window")
        let menu = NSHostingController(rootView: CommandCentreMenu(controller: controller, presenter: presenter,
            settingsPresenter: ConnectionSettingsWindowPresenter(), securityPresenter: SecurityEventWindowPresenter(),
            errorPresenter: ErrorWindowPresenter()))
        _ = menu.view
        let localCommand = try controller.localConnection.terminalCommand(localAgent, client: local, action: .shell)
        let remoteCommand = try controller.remoteConnection.terminalCommand(remoteAgent, client: remote, action: .shell)
        precondition(localCommand == "'/local/bin/safeyolo' --root '/local/instance' agent shell --persistent -- 'worker'")
        precondition(remoteCommand.hasPrefix("ssh -t -- 'ops@remote.example' ") && remoteCommand.contains("/remote/bin/safeyolo"))
        do {
            _ = try controller.localConnection.terminalCommand(remoteAgent, client: remote, action: .shell)
            preconditionFailure("A terminal action cannot use another instance's client")
        } catch ClientError.connectionUnavailable {}
        var localStart: Result<AgentInfo, Error>?
        var remoteStop: Result<AgentInfo, Error>?
        local.setRunning(localAgent, running: true) { localStart = $0 }
        remote.setRunning(remoteAgent, running: false) { remoteStop = $0 }
        try await credentialUntil { localStart != nil && remoteStop != nil }
        let started = try localStart!.get()
        let stopped = try remoteStop!.get()
        precondition(started.agentState == "running" && stopped.agentState == "stopped")
        var localDesktop: Result<DesktopPresentation, Error>?
        var remoteDesktop: Result<DesktopPresentation, Error>?
        local.presentDesktop(for: localAgent) { localDesktop = $0 }
        remote.presentDesktop(for: remoteAgent) { remoteDesktop = $0 }
        try await credentialUntil { localDesktop != nil && remoteDesktop != nil }
        let localPresentation = try localDesktop!.get()
        let remotePresentation = try remoteDesktop!.get()
        precondition(localPresentation.url.hasPrefix("http://127.0.0.1:") && remotePresentation.unlockCode == "remote-unlock")
        var localDecision: Result<ResolutionResult, Error>?
        var remoteDecision: Result<ResolutionResult, Error>?
        local.resolve(localApproval, allow: false) { localDecision = $0 }
        remote.resolve(remoteApproval, allow: true) { remoteDecision = $0 }
        try await credentialUntil { localDecision != nil && remoteDecision != nil }
        _ = try localDecision!.get(); _ = try remoteDecision!.get()
        precondition(local.approvalOutcomes["apr-shared"]?.status == "rejected"
            && remote.approvalOutcomes["apr-shared"]?.status == "approved" && !controller.hasPendingApprovals)
        precondition(endpoints.posts.count == 6 && endpoints.posts.allSatisfy {
            $0.authorization == "Bearer synthetic-\($0.host == "remote.example" ? "remote" : "local")-token"
        }, "Each action must use the selected endpoint and its own credential")

        endpoints.remote(status: 503)
        try await credentialUntil { !remote.adminConnected && remote.connectionState == .reconnecting }
        precondition(controller.localConnection.client === local && local.adminConnected && local.agents[0].agentState == "running")
        localStart = nil
        local.setRunning(localAgent, running: false) { localStart = $0 }
        try await credentialUntil { localStart != nil }
        let recoveredLocalStop = try localStart!.get()
        precondition(recoveredLocalStop.agentState == "stopped")
        precondition(remote.approvalOutcomes["apr-shared"]?.status == "approved", "Another instance's failure cannot erase a decision")
        endpoints.remote()
        try await credentialUntil { remote.adminConnected && remote.connectionState == .eventsDisabled }
        precondition(controller.localConnection.client === local && local.adminConnected && remote.approvals.isEmpty)

        endpoints.remote(instanceID: "sy-wrong-instance")
        let mismatchAccepted = await remote.refreshInstance()
        precondition(!mismatchAccepted && !remote.adminConnected)
        let postsBeforeMismatch = endpoints.posts.count
        remoteDecision = nil
        remote.resolve(remoteApproval, allow: false) { remoteDecision = $0 }
        try await credentialUntil { remoteDecision != nil }
        guard case .failure = remoteDecision! else { preconditionFailure("A mismatched instance cannot decide or supply an approval outcome") }
        precondition(endpoints.posts.count == postsBeforeMismatch && local.adminConnected)
        endpoints.remote()
        try await credentialUntil { remote.adminConnected }
        var wrongToken: Result<RemoteConnectionProfile, Error>?
        controller.configureRemote(RemoteConnectionInput(friendlyName: "Wrong credential", adminURL: profile.adminURL,
            eventsURL: profile.eventsURL, token: "synthetic-local-token")) { wrongToken = $0 }
        try await credentialUntil { wrongToken != nil }
        guard case .failure = wrongToken! else { preconditionFailure("A different instance's token must be refused") }
        precondition(controller.localConnection.client === local && local.adminConnected && profiles.profile == profile)
        precondition(store.token(profile.instanceID) == "synthetic-remote-token" && store.writeAccounts.isEmpty)
        precondition(controller.remoteConnection.restoreRemote())
        try await credentialUntil { controller.remoteConnection.client?.agents.count == 1 }
        let replaced = remote
        remote = controller.remoteConnection.client!
        do {
            _ = try controller.remoteConnection.terminalCommand(remoteAgent, client: replaced, action: .attach)
            preconditionFailure("A late terminal callback cannot use a replacement connection")
        } catch ClientError.connectionUnavailable {}
        controller.useLocal()
        try await credentialUntil { controller.localConnection.client?.agents.count == 1 }
        precondition(controller.remoteConnection.client === remote && remote.adminConnected && profiles.profile == profile)
        try controller.removeRemote()
        precondition(controller.connections.count == 1 && controller.localConnection.client?.adminConnected == true && profiles.profile == nil)
        try profiles.save(profile)
        controller.start(commandLine: CommandLineConfiguration(adminURL: "http://127.0.0.1:19190", eventsURL: "ws://127.0.0.1:19191/admin/events"))
        try await credentialUntil { controller.localConnection.client?.agents.count == 1 }
        precondition(controller.connections.count == 1 && controller.remoteConnection.client == nil && profiles.profile == profile)
        print("concurrent-instances: dual controller/client routing, overlapping IDs/windows, credentials, approvals, terminals, reconnect/mismatch isolation and explicit endpoints PASS")

        // An existing remote-only installation must work even without local identity files.
        let remoteOnly = CommandCentreController(presenter: presenter, securityNotifier: SecurityNotificationPresenter(),
            keychain: store, profileStore: profiles, localCredentialDirectory: root.appendingPathComponent("no-local-install"), session: session)
        defer { remoteOnly.stop() }
        remoteOnly.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        try await credentialUntil { remoteOnly.remoteConnection.client?.agents.count == 1 }
        precondition(remoteOnly.localConnection.startupError != nil && remoteOnly.hasConnectedInstance)
        precondition(remoteOnly.remoteConnection.client?.instanceID == profile.instanceID && profiles.profile == profile)
        print("concurrent-instances: existing saved remote remains usable without a local installation PASS")
    }
}
