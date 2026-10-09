import AppKit
import Foundation

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
        try await testCredentialReturnsAndMissingFile(root)
        try Data("synthetic-file-token\n".utf8).write(to: root.appendingPathComponent("data/admin_token"))
        try await testSavedProfileIdentity(root)
        try await testRemoteImportAndNewSelection(root)
        try await testRemoteVerificationRefusal(root)
        try await testLateRemoteVerification(root)
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
        precondition(controller.client == nil && controller.startupError == nil)
        precondition(controller.credentialStatus?.contains("Waiting for Keychain") == true)
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
        controller.useCredentialFile()
        try await credentialUntil { controller.client?.adminConnected == true && store.writeAccounts.count == 1 }
        precondition(StubURLProtocol.observedAuthorization == "Bearer synthetic-file-token")
        precondition(store.readsFinished == 0 && store.writesFinished == 0, "Connection must precede held read and import returns")
        precondition(controller.credentialStatus?.contains("Credential loaded for this session") == true)
        let connected = controller.client
        store.readGate?.signal()
        try await credentialUntil { store.readsFinished == 1 }
        try await Task.sleep(for: .milliseconds(50))
        precondition(controller.client === connected, "Late Keychain read must not replace the selected file connection")
        controller.stop()
        store.writeGate?.signal()
        try await credentialUntil { store.writesFinished == 1 }
        try await Task.sleep(for: .milliseconds(50))
        precondition(controller.client == nil && controller.credentialStatus == nil, "Late import must not revive a disconnected client")
        print("credential-callers: held native read/import, main heartbeat, rendered settings, matching-file connection and late disconnect PASS")
    }

    @MainActor
    private static func testCredentialReturnsAndMissingFile(_ root: URL) async throws {
        credentialSnapshot("sy-file-test")
        let keychain = HeldCredentialStore(tokens: ["sy-file-test": "synthetic-keychain-token"])
        let controller = credentialController(root, keychain)
        defer { controller.stop() }
        controller.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        try await credentialUntil { controller.client?.adminConnected == true }
        precondition(StubURLProtocol.observedAuthorization == "Bearer synthetic-keychain-token")
        precondition(keychain.writeAccounts.isEmpty && controller.credentialStatus == nil)
        let keychainClient = controller.client
        try Data().write(to: root.appendingPathComponent("data/admin_token"))
        controller.useCredentialFile()
        try await credentialUntil { controller.startupError?.contains("empty") == true }
        precondition(controller.client === keychainClient && keychain.writeAccounts.isEmpty, "An unusable file must not disconnect a working Keychain session")
        try Data("synthetic-file-token\n".utf8).write(to: root.appendingPathComponent("data/admin_token"))
        controller.stop()

        let refusal = HeldCredentialStore(refuseRead: true, refuseWrite: true)
        let fallback = credentialController(root, refusal)
        defer { fallback.stop() }
        fallback.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        try await credentialUntil { fallback.client?.adminConnected == true && refusal.writesFinished == 1 && fallback.credentialStatus == nil }
        precondition(StubURLProtocol.observedAuthorization == "Bearer synthetic-file-token")
        precondition(fallback.startupError?.contains("available for this session") == true)
        fallback.stop()

        try FileManager.default.removeItem(at: root.appendingPathComponent("data/admin_token"))
        let absent = credentialController(root, HeldCredentialStore())
        defer { absent.stop() }
        absent.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        try await credentialUntil { absent.startupError != nil }
        precondition(absent.client == nil && absent.startupError!.contains("unavailable"))
        absent.useCredentialFile()
        try await credentialUntil { absent.credentialStatus == nil }
        precondition(absent.client == nil && absent.startupError!.contains("unavailable"))
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
        controller.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        try await credentialUntil { store.readAccounts == [profile.instanceID] }
        controller.useCredentialFile()
        try await credentialUntil { controller.startupError != nil }
        precondition(controller.client == nil && controller.startupError!.contains("expected sy-remote-test"))
        precondition(store.writeAccounts.isEmpty && profiles.profile == profile)
        store.readGate?.signal()
        try await credentialUntil { store.readsFinished == 1 && controller.client?.adminConnected == true }
        precondition(StubURLProtocol.observedAuthorization == "Bearer synthetic-remote-token", "An invalid file must leave legitimate Keychain access available")
        controller.stop()

        credentialSnapshot(profile.instanceID)
        let saved = credentialController(root, HeldCredentialStore(tokens: [profile.instanceID: "synthetic-remote-token"]), profiles)
        defer { saved.stop() }
        saved.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        try await credentialUntil { saved.client?.adminConnected == true }
        precondition(saved.client?.instanceID == profile.instanceID && saved.connectionName == profile.friendlyName)
        saved.stop()
        let missing = credentialController(root, HeldCredentialStore(), profiles)
        defer { missing.stop() }
        missing.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        try await credentialUntil { missing.startupError != nil }
        precondition(missing.client == nil && missing.startupError!.contains("No Keychain credential"))
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
        try await credentialUntil { first != nil && controller.client?.adminConnected == true && store.writeAccounts.count == 1 }
        _ = try first!.get()
        precondition(profiles.saved.isEmpty && store.writesFinished == 0, "Connect and settings completion cannot wait for optional storage")
        var newer: Result<RemoteConnectionProfile, Error>?
        controller.configureRemote(RemoteConnectionInput(friendlyName: "Newer remote", adminURL: "https://newer.example", eventsURL: "wss://newer.example/events", token: "synthetic-newer-token")) { newer = $0 }
        try await credentialUntil { newer != nil && controller.client?.adminConnected == true }
        let newerProfile = try newer!.get()
        precondition(controller.remoteProfile == newerProfile, "Settings and terminals must use the current profile while storage is pending")
        store.readGate?.signal()
        store.writeGate?.signal()
        store.writeGate?.signal()
        try await credentialUntil { store.readsFinished == 1 && store.writesFinished == 2 && profiles.profile == newerProfile }
        precondition(controller.connectionName == "Newer remote" && controller.client?.instanceID == "sy-remote-test")
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
        precondition(controller.client == nil && store.writeAccounts.isEmpty && controller.startupError?.contains("403") == true)
        precondition(controller.credentialStatus == nil)
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
        precondition(controller.client == nil && controller.credentialStatus == nil && controller.startupError == nil)
        precondition(profiles.saved.isEmpty && store.writeAccounts.isEmpty)
        print("credential-callers: late remote verification cannot reconnect or save after disconnect PASS")
    }
}
