import Combine
import Foundation

@MainActor
final class CommandCentreController: ObservableObject {
    @Published private(set) var client: SafeYoloClient?
    @Published private(set) var startupError: String?
    @Published private(set) var connectionName = "Local SafeYolo"

    private let presenter: ApprovalWindowPresenter
    private let securityNotifier: SecurityNotificationPresenter
    private let keychain: any CredentialStore
    private let profileStore: any ConnectionProfileStore
    private let verifier: RemoteConnectionVerifier
    private var clientUpdates: AnyCancellable?
    private var notificationUpdates: AnyCancellable?
    private var remoteTerminal = false

    init(
        presenter: ApprovalWindowPresenter,
        securityNotifier: SecurityNotificationPresenter,
        keychain: any CredentialStore = NativeKeychainStore(),
        profileStore: any ConnectionProfileStore = UserDefaultsConnectionProfileStore(),
        verifier: RemoteConnectionVerifier = RemoteConnectionVerifier()
    ) {
        self.presenter = presenter
        self.securityNotifier = securityNotifier
        self.keychain = keychain
        self.profileStore = profileStore
        self.verifier = verifier
        notificationUpdates = securityNotifier.objectWillChange.sink { [weak self] _ in
            self?.objectWillChange.send()
        }
    }

    var notificationError: String? { securityNotifier.error }

    var savedRemoteProfile: RemoteConnectionProfile? {
        try? profileStore.load()
    }

    var hasPendingApprovals: Bool {
        !(client?.approvals.isEmpty ?? true)
    }

    var hasSecurityEvents: Bool {
        !(client?.securityEvents.isEmpty ?? true)
    }

    func start(commandLine: CommandLineConfiguration = .load()) {
        do {
            if let commandLineAdminURL = commandLine.adminURL,
               let commandLineEventsURL = commandLine.eventsURL
            {
                let credential = try LocalCredentialLoader.live().load()
                try connect(
                    name: "SafeYolo",
                    adminURL: commandLineAdminURL,
                    eventsURL: commandLineEventsURL,
                    credential: credential
                )
                return
            }
            if let profile = try profileStore.load() {
                guard let token = try keychain.load(account: profile.instanceID), !token.isEmpty else {
                    throw ConnectionError.missingCredential(profile.instanceID)
                }
                try connect(
                    name: profile.friendlyName,
                    adminURL: profile.adminURL,
                    eventsURL: profile.eventsURL,
                    credential: LoadedCredential(
                        instanceID: profile.instanceID,
                        token: token,
                        source: .keychain,
                        warning: nil
                    )
                )
                remoteTerminal = true
                return
            }
            let credential = try LocalCredentialLoader.live().load()
            try connect(
                name: "Local SafeYolo",
                adminURL: "http://127.0.0.1:9090",
                eventsURL: "ws://127.0.0.1:9091/admin/events",
                credential: credential,
                isLocalConnection: true
            )
        } catch {
            disconnect()
            startupError = error.localizedDescription
        }
    }

    func configureRemote(
        _ input: RemoteConnectionInput,
        completion: @escaping (Result<RemoteConnectionProfile, Error>) -> Void
    ) {
        verifier.verify(input) { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let profile):
                do {
                    try self.keychain.store(account: profile.instanceID, token: input.token)
                    try self.profileStore.save(profile)
                    try self.connect(
                        name: profile.friendlyName,
                        adminURL: profile.adminURL,
                        eventsURL: profile.eventsURL,
                        credential: LoadedCredential(
                            instanceID: profile.instanceID,
                            token: input.token,
                            source: .keychain,
                            warning: nil
                        )
                    )
                    self.remoteTerminal = true
                    completion(.success(profile))
                } catch {
                    completion(.failure(error))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }

    func useLocal() throws {
        try profileStore.delete()
        disconnect()
        start()
    }

    func stop() {
        disconnect()
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
            terminalTarget: savedRemoteProfile?.terminalTarget,
            adminURL: savedRemoteProfile?.adminURL,
            hostUser: client?.hostUser,
            hostPython: client?.hostPython,
            transport: savedRemoteProfile?.transport ?? .tailnet,
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

    private func connect(
        name: String,
        adminURL: String,
        eventsURL: String,
        credential: LoadedCredential,
        isLocalConnection: Bool = false
    ) throws {
        disconnect()
        remoteTerminal = !["127.0.0.1", "localhost", "::1"].contains(URL(string: adminURL)?.host ?? "")
        let nextClient = try SafeYoloClient(
            adminURL: adminURL,
            eventsURL: eventsURL,
            token: credential.token,
            expectedInstanceID: credential.instanceID,
            isLocalConnection: isLocalConnection
        )
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
        connectionName = name
        startupError = credential.warning
        client = nextClient
        FileHandle.standardError.write(
            Data(
                (
                    "credential_source=\(credential.source.rawValue) " +
                    "instance_id=\(credential.instanceID) connection=\(name)\n"
                ).utf8
            )
        )
        nextClient.start()
    }

    private func disconnect() {
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
