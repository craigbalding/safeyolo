import Combine
import Foundation

@MainActor
final class CommandCentreController: ObservableObject {
    @Published private(set) var connections: [CommandCentreConnection] = []
    let localConnection: CommandCentreConnection
    let remoteConnection: CommandCentreConnection
    private var updates: [AnyCancellable] = []

    init(
        presenter: ApprovalWindowPresenter,
        securityNotifier: SecurityNotificationPresenter,
        keychain: any CredentialStore = NativeKeychainStore(),
        profileStore: any ConnectionProfileStore = UserDefaultsConnectionProfileStore(),
        verifier: RemoteConnectionVerifier = RemoteConnectionVerifier(),
        localCredentialDirectory: URL? = nil,
        session: URLSession = .shared
    ) {
        localConnection = CommandCentreConnection(
            id: "local", presenter: presenter, securityNotifier: securityNotifier,
            keychain: keychain, profileStore: profileStore, verifier: verifier,
            localCredentialDirectory: localCredentialDirectory, session: session
        )
        remoteConnection = CommandCentreConnection(
            id: "remote", presenter: presenter, securityNotifier: securityNotifier,
            keychain: keychain, profileStore: profileStore, verifier: verifier,
            localCredentialDirectory: localCredentialDirectory, session: session
        )
        for connection in [localConnection, remoteConnection] {
            updates.append(connection.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() })
        }
    }

    var remoteProfile: RemoteConnectionProfile? { remoteConnection.remoteProfile }
    var hasPendingApprovals: Bool { connections.contains { $0.hasPendingApprovals } }
    var hasSecurityEvents: Bool { connections.contains { $0.hasSecurityEvents } }
    var hasConnectedInstance: Bool { connections.contains { $0.client?.adminConnected == true } }

    func start(commandLine: CommandLineConfiguration = .load()) {
        stop()
        connections = [localConnection]
        localConnection.startLocal(commandLine: commandLine)
        // Explicit endpoints keep their existing selection semantics.
        if commandLine.adminURL == nil || commandLine.eventsURL == nil {
            if remoteConnection.restoreRemote() { connections.append(remoteConnection) }
        }
    }

    func configureRemote(_ input: RemoteConnectionInput,
                         completion: @escaping (Result<RemoteConnectionProfile, Error>) -> Void) {
        if !connections.contains(where: { $0 === remoteConnection }) { connections.append(remoteConnection) }
        remoteConnection.configureRemote(input, completion: completion)
    }

    func useLocal() {
        if !connections.contains(where: { $0 === localConnection }) { connections.insert(localConnection, at: 0) }
        localConnection.startLocal(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
    }

    func removeRemote() throws {
        try remoteConnection.removeRemote()
        connections.removeAll { $0 === remoteConnection }
    }

    func stop() {
        localConnection.stop()
        remoteConnection.stop()
        connections = []
    }
}

@MainActor
final class CommandCentreConnection: ObservableObject, Identifiable {
    let id: String
    @Published private(set) var client: SafeYoloClient?
    @Published private(set) var startupError: String?
    @Published private(set) var connectionName = "Local SafeYolo"
    @Published private(set) var credentialStatus: String?

    private struct SelectedConnection: Sendable {
        let name: String
        let adminURL: String
        let eventsURL: String
        let instanceID: String
        var isLocalConnection = false
        var remoteProfile: RemoteConnectionProfile? = nil
    }

    private let presenter: ApprovalWindowPresenter
    private let securityNotifier: SecurityNotificationPresenter
    private let keychain: any CredentialStore
    private let profileStore: any ConnectionProfileStore
    private let verifier: RemoteConnectionVerifier
    private let localCredentials: LocalCredentialLoader
    private let session: URLSession
    // Serialize writes so an older pending import cannot replace a newer token.
    private let credentialWrites = DispatchQueue(label: "io.safeyolo.command-centre.credential-writes")
    private var connectionAttempt = 0
    private var selectedConnection: SelectedConnection?
    private var clientUpdates: AnyCancellable?
    private var notificationUpdates: AnyCancellable?

    init(
        id: String,
        presenter: ApprovalWindowPresenter,
        securityNotifier: SecurityNotificationPresenter,
        keychain: any CredentialStore = NativeKeychainStore(),
        profileStore: any ConnectionProfileStore = UserDefaultsConnectionProfileStore(),
        verifier: RemoteConnectionVerifier = RemoteConnectionVerifier(),
        localCredentialDirectory: URL? = nil,
        session: URLSession = .shared
    ) {
        self.id = id
        self.connectionName = id == "remote" ? "Remote SafeYolo" : "Local SafeYolo"
        self.presenter = presenter
        self.securityNotifier = securityNotifier
        self.keychain = keychain
        self.profileStore = profileStore
        self.verifier = verifier
        self.localCredentials = LocalCredentialLoader(
            configDirectory: localCredentialDirectory ?? LocalCredentialLoader.live().configDirectory,
            keychain: keychain
        )
        self.session = session
        notificationUpdates = securityNotifier.objectWillChange.sink { [weak self] _ in
            self?.objectWillChange.send()
        }
    }

    var notificationError: String? { securityNotifier.error }

    var remoteProfile: RemoteConnectionProfile? {
        selectedConnection?.remoteProfile ?? (try? profileStore.load())
    }

    var hasPendingApprovals: Bool {
        !(client?.approvals.isEmpty ?? true)
    }

    var hasSecurityEvents: Bool {
        !(client?.securityEvents.isEmpty ?? true)
    }

    func startLocal(commandLine: CommandLineConfiguration) {
        disconnect()
        startupError = nil
        do {
            let loader = localCredentials
            let selection: SelectedConnection
            let load: @Sendable () throws -> LoadedCredential
            if let commandLineAdminURL = commandLine.adminURL,
               let commandLineEventsURL = commandLine.eventsURL
            {
                selection = SelectedConnection(
                    name: "SafeYolo",
                    adminURL: commandLineAdminURL,
                    eventsURL: commandLineEventsURL,
                    instanceID: try localCredentials.instanceID()
                )
                load = { try loader.load() }
            } else {
                selection = SelectedConnection(
                    name: "Local SafeYolo",
                    adminURL: "http://127.0.0.1:9090",
                    eventsURL: "ws://127.0.0.1:9091/admin/events",
                    instanceID: try localCredentials.instanceID(),
                    isLocalConnection: true
                )
                load = { try loader.load() }
            }
            selectedConnection = selection
            connectionName = selection.name
            credentialStatus = "Waiting for Keychain access for \(selection.instanceID). Connection Settings remain available."
            loadCredential(load, for: selection)
        } catch {
            startupError = error.localizedDescription
        }
    }

    func restoreRemote() -> Bool {
        disconnect()
        startupError = nil
        do {
            guard let profile = try profileStore.load() else { return false }
            let selection = SelectedConnection(
                name: profile.friendlyName, adminURL: profile.adminURL,
                eventsURL: profile.eventsURL, instanceID: profile.instanceID,
                remoteProfile: profile
            )
            selectedConnection = selection
            connectionName = selection.name
            credentialStatus = "Waiting for Keychain access for \(selection.instanceID). Connection Settings remain available."
            let keychain = self.keychain
            loadCredential({
                guard let token = try keychain.load(account: profile.instanceID), !token.isEmpty else {
                    throw ConnectionError.missingCredential(profile.instanceID)
                }
                return LoadedCredential(instanceID: profile.instanceID, token: token, source: .keychain, warning: nil)
            }, for: selection)
        } catch {
            startupError = error.localizedDescription
        }
        return true
    }

    var credentialFileInstanceID: String? { selectedConnection?.instanceID }

    func useCredentialFile() {
        guard let selection = selectedConnection else { return }
        startupError = nil
        credentialStatus = "Reading the private credential file for \(selection.instanceID)…"
        let loader = localCredentials
        loadCredential({ try loader.loadFile() }, for: selection)
    }

    private func loadCredential(
        _ load: @escaping @Sendable () throws -> LoadedCredential,
        for selection: SelectedConnection
    ) {
        let attempt = connectionAttempt
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try load() }
            DispatchQueue.main.async { [weak self] in
                guard let self, self.connectionAttempt == attempt else { return }
                self.credentialStatus = nil
                do {
                    let credential = try result.get()
                    let nextClient = try self.credentialClient(selection, credential: credential)
                    if credential.source == .file {
                        self.verifyCredentialFile(selection, credential: credential, client: nextClient, attempt: attempt)
                    } else {
                        self.connect(selection, credential: credential, client: nextClient)
                    }
                } catch {
                    self.startupError = error.localizedDescription
                }
            }
        }
    }

    private func verifyCredentialFile(
        _ selection: SelectedConnection,
        credential: LoadedCredential,
        client nextClient: SafeYoloClient,
        attempt: Int
    ) {
        credentialStatus = "Verifying the private credential file for \(selection.instanceID)…"
        Task { [weak self] in
            let accepted = await nextClient.refreshInstance()
            guard let self, self.connectionAttempt == attempt else {
                nextClient.stop()
                return
            }
            self.credentialStatus = nil
            guard accepted else {
                let detail = nextClient.requestErrors["Instance identity"] ?? "The backend could not be verified."
                self.startupError = "The credential file could not connect to the selected SafeYolo instance: \(detail)"
                nextClient.stop()
                return
            }
            // Only backend acceptance supersedes legitimate Keychain access.
            self.connectionAttempt += 1
            self.connect(selection, credential: credential, client: nextClient)
            self.importCredential(credential, attempt: self.connectionAttempt, profile: selection.remoteProfile)
        }
    }

    func configureRemote(
        _ input: RemoteConnectionInput,
        completion: @escaping (Result<RemoteConnectionProfile, Error>) -> Void
    ) {
        disconnect()
        startupError = nil
        credentialStatus = "Verifying the remote SafeYolo instance…"
        let attempt = connectionAttempt
        verifier.verify(input) { [weak self] result in
            guard let self, self.connectionAttempt == attempt else {
                completion(.failure(CancellationError()))
                return
            }
            self.credentialStatus = nil
            switch result {
            case .success(let profile):
                do {
                    let selection = SelectedConnection(
                        name: profile.friendlyName,
                        adminURL: profile.adminURL,
                        eventsURL: profile.eventsURL,
                        instanceID: profile.instanceID,
                        remoteProfile: profile
                    )
                    let credential = LoadedCredential(
                        instanceID: profile.instanceID,
                        token: input.token,
                        source: .entered,
                        warning: nil
                    )
                    self.selectedConnection = selection
                    let nextClient = try self.credentialClient(selection, credential: credential)
                    self.connect(selection, credential: credential, client: nextClient)
                    self.importCredential(credential, attempt: attempt, profile: profile)
                    completion(.success(profile))
                } catch {
                    self.startupError = error.localizedDescription
                    completion(.failure(error))
                }
            case .failure(let error):
                self.startupError = error.localizedDescription
                completion(.failure(error))
            }
        }
    }

    func removeRemote() throws {
        try profileStore.delete()
        disconnect()
        startupError = nil
    }

    func stop() {
        disconnect()
    }

    private func importCredential(
        _ credential: LoadedCredential,
        attempt: Int,
        profile: RemoteConnectionProfile? = nil
    ) {
        credentialStatus = "Credential loaded for this session. Saving it to Keychain…"
        let keychain = self.keychain
        credentialWrites.async {
            let result = Result { try keychain.store(account: credential.instanceID, token: credential.token) }
            DispatchQueue.main.async { [weak self] in
                guard let self, self.connectionAttempt == attempt else { return }
                self.credentialStatus = nil
                do {
                    try result.get()
                    if let profile { try self.profileStore.save(profile) }
                } catch {
                    self.startupError = "The credential is available for this session. The credential or remote profile could not be saved: \(error.localizedDescription)"
                }
            }
        }
    }

    func openAgentTerminal(_ agent: AgentInfo, client: SafeYoloClient) throws {
        try openTerminal(agent, client: client, action: .attach)
    }

    func openSandboxShell(_ agent: AgentInfo, client: SafeYoloClient) throws {
        try openTerminal(agent, client: client, action: .shell)
    }

    func showWebMITMSignInNotice() {
        securityNotifier.showWebMITMSignInNotice()
    }

    func terminalCommand(_ agent: AgentInfo, client: SafeYoloClient, action: AgentTerminalAction) throws -> String {
        guard self.client === client, client.adminConnected,
              client.instanceID == selectedConnection?.instanceID,
              client.agents.contains(where: { $0.agentID == agent.agentID && $0.name == agent.name }) else {
            throw ClientError.connectionUnavailable
        }
        let remote = selectedConnection?.remoteProfile != nil
            || !["127.0.0.1", "localhost", "::1", "[::1]"].contains(URL(string: selectedConnection?.adminURL ?? "")?.host ?? "")
        return try agentTerminalCommand(
            name: agent.name, remote: remote,
            terminalTarget: selectedConnection?.remoteProfile?.terminalTarget,
            adminURL: selectedConnection?.adminURL,
            hostUser: client.hostUser,
            hostExecutable: client.hostExecutable,
            hostRoot: client.hostRoot,
            hostConfigPath: client.hostConfigPath,
            transport: selectedConnection?.remoteProfile?.transport ?? .tailnet,
            action: action
        )
    }

    private func openTerminal(_ agent: AgentInfo, client: SafeYoloClient, action: AgentTerminalAction) throws {
        let command = try terminalCommand(agent, client: client, action: action)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", """
            on run argv
                tell application "Terminal"
                    activate
                    do script (item 1 of argv)
                end tell
            end run
            """, command]
        let errors = Pipe()
        process.standardError = errors
        try process.run()
        let detail = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "SafeYolo.Terminal", code: Int(process.terminationStatus), userInfo: [
                NSLocalizedDescriptionKey: String(decoding: detail, as: UTF8.self)
            ])
        }
    }

    private func credentialClient(
        _ selection: SelectedConnection,
        credential: LoadedCredential
    ) throws -> SafeYoloClient {
        _ = try validatePinnedInstanceID(actual: credential.instanceID, expected: selection.instanceID)
        return try SafeYoloClient(
            adminURL: selection.adminURL,
            eventsURL: selection.eventsURL,
            token: credential.token,
            expectedInstanceID: credential.instanceID,
            session: session,
            isLocalConnection: selection.isLocalConnection
        )
    }

    private func connect(
        _ selection: SelectedConnection,
        credential: LoadedCredential,
        client nextClient: SafeYoloClient
    ) {
        if let client { presenter.close(instanceID: client.expectedInstanceID) }
        client?.stop()
        let instanceName = "\(selection.name) (\(selection.instanceID))"
        nextClient.onNewApproval = { [weak presenter = self.presenter, weak nextClient] approval in
            guard let presenter, let nextClient else { return }
            presenter.show(approval, client: nextClient, instanceName: instanceName)
        }
        nextClient.onNewSecurityEvent = { [weak securityNotifier = self.securityNotifier] event in
            securityNotifier?.show(event, instanceName: instanceName, instanceID: selection.instanceID)
        }
        clientUpdates = nextClient.objectWillChange.sink { [weak self] _ in
            self?.objectWillChange.send()
        }
        connectionName = selection.name
        startupError = credential.warning
        client = nextClient
        FileHandle.standardError.write(
            Data(
                (
                    "credential_source=\(credential.source.rawValue) " +
                    "instance_id=\(credential.instanceID) connection=\(selection.name)\n"
                ).utf8
            )
        )
        nextClient.start()
    }

    private func disconnect() {
        connectionAttempt += 1
        selectedConnection = nil
        credentialStatus = nil
        if let client { presenter.close(instanceID: client.expectedInstanceID) }
        client?.stop()
        client = nil
        clientUpdates = nil
    }
}

struct CommandLineConfiguration {
    let adminURL: String?
    let eventsURL: String?

    static func load() -> CommandLineConfiguration {
        var adminURL: String?
        var eventsURL: String?
        var arguments = CommandLine.arguments.dropFirst().makeIterator()
        while let argument = arguments.next() {
            switch argument {
            case "--admin-url":
                adminURL = arguments.next()
            case "--events-url":
                eventsURL = arguments.next()
            default:
                break
            }
        }
        return CommandLineConfiguration(adminURL: adminURL, eventsURL: eventsURL)
    }
}
