import Combine
import Foundation

@MainActor
final class CommandCentreController: ObservableObject {
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
    private var remoteTerminal = false

    init(
        presenter: ApprovalWindowPresenter,
        securityNotifier: SecurityNotificationPresenter,
        keychain: any CredentialStore = NativeKeychainStore(),
        profileStore: any ConnectionProfileStore = UserDefaultsConnectionProfileStore(),
        verifier: RemoteConnectionVerifier = RemoteConnectionVerifier(),
        localCredentialDirectory: URL? = nil,
        session: URLSession = .shared
    ) {
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

    func start(commandLine: CommandLineConfiguration = .load()) {
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
            } else if let profile = try profileStore.load() {
                selection = SelectedConnection(
                    name: profile.friendlyName,
                    adminURL: profile.adminURL,
                    eventsURL: profile.eventsURL,
                    instanceID: profile.instanceID,
                    remoteProfile: profile
                )
                let keychain = self.keychain
                load = {
                    guard let token = try keychain.load(account: profile.instanceID), !token.isEmpty else {
                        throw ConnectionError.missingCredential(profile.instanceID)
                    }
                    return LoadedCredential(
                        instanceID: profile.instanceID,
                        token: token,
                        source: .keychain,
                        warning: nil
                    )
                }
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

    func useLocal() throws {
        try profileStore.delete()
        start()
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

    func openAgentTerminal(_ agent: AgentInfo) throws {
        try openTerminal(agent, action: .attach)
    }

    func openSandboxShell(_ agent: AgentInfo) throws {
        try openTerminal(agent, action: .shell)
    }

    func showWebMITMSignInNotice() {
        securityNotifier.showWebMITMSignInNotice()
    }

    private func openTerminal(_ agent: AgentInfo, action: AgentTerminalAction) throws {
        let command = try agentTerminalCommand(
            name: agent.name, remote: remoteTerminal,
            terminalTarget: selectedConnection?.remoteProfile?.terminalTarget,
            adminURL: selectedConnection?.adminURL,
            hostUser: client?.hostUser,
            hostExecutable: client?.hostExecutable,
            hostRoot: client?.hostRoot,
            hostConfigPath: client?.hostConfigPath,
            transport: selectedConnection?.remoteProfile?.transport ?? .tailnet,
            action: action
        )
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
        client?.stop()
        remoteTerminal = selection.remoteProfile != nil
            || !["127.0.0.1", "localhost", "::1"].contains(URL(string: selection.adminURL)?.host ?? "")
        nextClient.onNewApproval = { [weak presenter = self.presenter, weak nextClient] approval in
            guard let presenter, let nextClient else { return }
            presenter.show(approval, client: nextClient)
        }
        nextClient.onNewSecurityEvent = { [weak securityNotifier = self.securityNotifier] event in
            securityNotifier?.show(event)
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
