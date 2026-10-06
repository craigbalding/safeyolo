import Combine
import Foundation

protocol EventSocket: AnyObject {
    var response: URLResponse? { get }
    var closeCode: URLSessionWebSocketTask.CloseCode { get }
    func resume()
    func sendPing(pongReceiveHandler: @escaping @Sendable (Error?) -> Void)
    func receive() async throws -> URLSessionWebSocketTask.Message
    func cancel(with closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?)
}

extension URLSessionWebSocketTask: EventSocket {}

@MainActor
final class SafeYoloClient: ObservableObject {
    enum ConnectionState: String {
        case connecting = "Connecting…"
        case connected = "Connected"
        case reconnecting = "Reconnecting…"
        case eventsDisabled = "Live events disabled"
        case stopped = "Stopped"
    }

    @Published private(set) var connectionState = ConnectionState.connecting
    @Published private(set) var approvals: [ApprovalEvent] = []
    // Session projections of canonical records. Reconnect reads the host;
    // disappearance from the pending list alone never means approval.
    @Published private(set) var networkOutcomes: [String: NetworkApprovalResolution] = [:]
    @Published private(set) var unavailableNetworkOutcomes = Set<String>()
    @Published private(set) var agents: [AgentInfo] = []
    @Published private(set) var securityEvents: [SecurityObservation] = []
    @Published private(set) var busyAgentIDs = Set<String>()
    @Published private(set) var pendingTerminalIDs = Set<String>()
    @Published private(set) var instanceID = ""
    @Published private(set) var hostUser: String?
    @Published private(set) var hostExecutable: String?
    @Published private(set) var hostConfigPath: String?
    @Published private(set) var hostRoot: String?
    @Published private(set) var webmitmURL: URL?
    @Published private(set) var webMITMKeyCopied = false
    @Published private(set) var requestErrors: [String: String] = [:]
    @Published private(set) var eventFeedGap: String?
    @Published private(set) var adminConnected = false
    @Published private(set) var eventEndpoint: InstanceInfo.EventEndpoint?

    var connectionSummary: String {
        if adminConnected && connectionState == .reconnecting {
            return "Admin API connected; live events unavailable"
        }
        return connectionState.rawValue
    }

    var connectionGuidance: String? {
        guard adminConnected, connectionState != .connected, connectionState != .stopped else { return nil }
        let host = isLocalConnection ? "this Mac" : "the connected SafeYolo host"
        if eventEndpoint?.enabled == false {
            return """
            Admin API connected. Live events are disabled in the running SafeYolo host.
            On \(host), set enabled = true in the [command_centre] table of the connected instance's TOML configuration, then run its installed CLI:
            safeyolo stop
            safeyolo start

            If you already enabled live events, restart SafeYolo to apply the change.
            Restarting briefly interrupts agent networking and Coord. Agents stay running.
            """
        }
        if requestErrors["Live events"] != nil {
            return """
            Admin API connected, but the live-event connection failed.
            On \(host), run the connected instance's installed CLI: safeyolo doctor.
            Check [command_centre] in its TOML configuration, the event port, and any SSH tunnel or Tailnet forwarding.
            Copy Diagnostics includes the connection failure and retry history.
            """
        }
        return nil
    }

    var diagnosticReport: String {
        let endpointState = eventEndpoint.map { "enabled=\($0.enabled), port=\($0.port.map(String.init) ?? "none")" }
            ?? "Not reported by this host (older backend)"
        let report = """
        \(diagnostics.report())
        Admin endpoint origin: \(ConnectionDiagnostics.endpoint(adminURL))
        Event endpoint origin: \(ConnectionDiagnostics.endpoint(eventsURL))
        Mode: \(isLocalConnection ? "local" : "remote or explicit endpoint")
        State: \(connectionSummary)
        Admin API authenticated: \(adminConnected)
        Host event listener: \(endpointState)
        Agents in snapshot: \(agents.count)
        Pending approvals in snapshot: \(approvals.count)
        Current failed operations: \(requestErrors.keys.sorted().joined(separator: ", "))
        Feed gap: \(eventFeedGap ?? "None")
        Guidance: \(connectionGuidance ?? "None")
        Headers, credentials, URL paths/query/userinfo, and response bodies are excluded.
        """
        return token.isEmpty ? report : report.replacingOccurrences(of: token, with: "[redacted]")
    }

    var errorDetails: String? {
        guard !requestErrors.isEmpty else { return nil }
        return requestErrors.keys.sorted().map { "\($0):\n\(requestErrors[$0]!)" }.joined(separator: "\n\n")
    }

    var onNewApproval: ((ApprovalEvent) -> Void)?
    var onNewSecurityEvent: ((SecurityObservation) -> Void)?

    private let adminURL: URL
    private let eventsURL: URL
    private let token: String
    private let expectedInstanceID: String
    private let session: URLSession
    private let isLocalConnection: Bool
    private let makeEventSocket: (URLRequest) -> any EventSocket
    private let retryPause: @MainActor () async throws -> Void
    private var diagnostics = ConnectionDiagnostics()
    private var webSocket: (any EventSocket)?
    private var connectionTask: Task<Void, Never>?
    private var knownApprovalIDs = Set<String>()
    private var knownSecurityEventIDs = Set<String>()
    private var stopping = false
    private var pendingTerminals: [String: (Result<AgentInfo, Error>) -> Void] = [:]

    init(
        adminURL: String,
        eventsURL: String,
        token: String,
        expectedInstanceID: String,
        session: URLSession = .shared,
        isLocalConnection: Bool = false,
        makeEventSocket: ((URLRequest) -> any EventSocket)? = nil,
        retryPause: @escaping @MainActor () async throws -> Void = { try await Task.sleep(for: .seconds(1)) }
    ) throws {
        guard let parsedAdminURL = URL(string: adminURL) else {
            throw ClientError.invalidURL(adminURL)
        }
        guard let parsedEventsURL = URL(string: eventsURL) else {
            throw ClientError.invalidURL(eventsURL)
        }
        self.adminURL = parsedAdminURL
        self.eventsURL = parsedEventsURL
        self.token = token
        self.expectedInstanceID = expectedInstanceID
        self.session = session
        self.isLocalConnection = isLocalConnection
        self.makeEventSocket = makeEventSocket ?? { session.webSocketTask(with: $0) }
        self.retryPause = retryPause
    }

    func start() {
        stopping = false
        setConnectionState(.connecting)
        reconnectUntilAvailable()
    }

    func stop() {
        stopping = true
        let cancelled = pendingTerminals.values
        pendingTerminals.removeAll()
        pendingTerminalIDs.removeAll()
        for completion in cancelled { completion(.failure(CancellationError())) }
        setConnectionState(.stopped)
        connectionTask?.cancel()
        connectionTask = nil
        webSocket?.cancel(with: .goingAway, reason: nil)
        webSocket = nil
    }

    private func reconnectUntilAvailable() {
        connectionTask?.cancel()
        webSocket?.cancel(with: .goingAway, reason: nil)
        webSocket = nil
        connectionTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled, !stopping {
                diagnostics.attempts += 1
                if await refreshInstance() {
                    let approvalsReady = await refreshApprovals()
                    _ = await refreshAgents()
                    guard !Task.isCancelled, !stopping else { return }
                    if eventEndpoint?.enabled == false {
                        setRequestError("Live events", nil)
                        setConnectionState(.eventsDisabled)
                    } else if approvalsReady {
                        await connectEvents()
                    } else {
                        setConnectionState(.reconnecting)
                    }
                } else {
                    guard !Task.isCancelled, !stopping else { return }
                    setConnectionState(.reconnecting)
                }
                guard !Task.isCancelled, !stopping else { return }
                diagnostics.retries += 1
                // Every retry, including a successful HTTP snapshot followed by
                // a failed WebSocket, passes through this cancellable delay.
                do { try await retryPause() } catch { return }
            }
        }
    }

    private func setConnectionState(_ state: ConnectionState) {
        guard connectionState != state else { return }
        diagnostics.record("State: \(state.rawValue)")
        connectionState = state
    }

    private func setRequestError(_ operation: String, _ error: Error?) {
        if let error { diagnostics.failure(operation, error: error) }
        let description = error?.localizedDescription
        guard requestErrors[operation] != description else { return }
        requestErrors[operation] = description
    }

    func resolve(
        _ event: ApprovalEvent,
        allow: Bool,
        completion: @escaping (Result<ResolutionResult, Error>) -> Void
    ) {
        Task {
            var networkPath: String?
            do {
                let plan = try MutationPlan.forApproval(event, allow: allow)
                if plan.path.hasPrefix("/admin/approvals/") { networkPath = plan.path }
                let data = try await request(path: plan.path, method: "POST", json: plan.payload)
                let result: ResolutionResult
                if plan.expectsDesktop {
                    result = .desktop(try JSONDecoder().decode(DesktopPresentation.self, from: data))
                } else if plan.path.hasPrefix("/admin/approvals/") {
                    let resolution = try JSONDecoder().decode(NetworkApprovalResolution.self, from: data)
                    guard resolution.requestID == event.requestID, resolution.terminal else { throw ClientError.invalidResponse }
                    networkOutcomes[resolution.requestID] = resolution
                    unavailableNetworkOutcomes.remove(resolution.requestID)
                    result = .decided(resolution.display)
                } else {
                    result = .decided(allow ? "Allowed" : "Denied")
                }
                await refreshApprovals()
                setRequestError("Approval decision", nil)
                completion(.success(result))
            } catch {
                // The host may have committed before the connection failed.
                // Read once, and report its actual decision without replay.
                if let path = networkPath,
                   let outcome = try? await readNetworkOutcome(path),
                   outcome.requestID == event.requestID, outcome.terminal {
                    networkOutcomes[outcome.requestID] = outcome
                    unavailableNetworkOutcomes.remove(outcome.requestID)
                    _ = await refreshApprovals()
                    setRequestError("Approval decision", nil)
                    completion(.success(.decided(outcome.display)))
                    return
                }
                setRequestError("Approval decision", error)
                completion(.failure(error))
            }
        }
    }

    func setRunning(
        _ agent: AgentInfo,
        running: Bool,
        interactive: Bool = false,
        completion: @escaping (Result<AgentInfo, Error>) -> Void
    ) {
        guard !busyAgentIDs.contains(agent.agentID) else { return }
        if !running {
            let cancelled = pendingTerminals.removeValue(forKey: agent.agentID)
            pendingTerminalIDs.remove(agent.agentID)
            cancelled?(.failure(CancellationError()))
        }
        busyAgentIDs.insert(agent.agentID)
        Task {
            defer { busyAgentIDs.remove(agent.agentID) }
            do {
                guard let encodedID = encodePathComponent(agent.agentID) else {
                    throw ClientError.invalidURL(agent.agentID)
                }
                let action = running ? (interactive ? "start-interactive" : "start") : "stop"
                let data = try await request(
                    path: "/admin/agents/\(encodedID)/\(action)",
                    method: "POST"
                )
                let updated = try JSONDecoder().decode(AgentInfo.self, from: data)
                let refreshed = await refreshAgents()
                setRequestError("Run or stop agent", nil)
                completion(.success(refreshed ? agents.first(where: { $0.agentID == updated.agentID }) ?? updated : updated))
            } catch {
                setRequestError("Run or stop agent", error)
                completion(.failure(error))
            }
        }
    }

    func runAndWaitForTerminal(
        _ agent: AgentInfo,
        completion: @escaping (Result<AgentInfo, Error>) -> Void
    ) {
        guard !pendingTerminalIDs.contains(agent.agentID) else { return }
        setRunning(agent, running: true) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success(let updated):
                guard !self.stopping else { completion(.failure(CancellationError())); return }
                self.pendingTerminals[agent.agentID] = completion
                self.pendingTerminalIDs.insert(agent.agentID)
                self.finishPendingTerminals([updated])
            }
        }
    }

    private func finishPendingTerminals(_ inventory: [AgentInfo], completeInventory: Bool = false) {
        for (id, completion) in pendingTerminals {
            let agent = inventory.first { $0.agentID == id }
            if agent == nil && !completeInventory { continue }
            if let agent, !agent.attachable && ["starting", "launching", "restarting"].contains(agent.agentState) { continue }
            pendingTerminals.removeValue(forKey: id)
            pendingTerminalIDs.remove(id)
            if let agent, agent.attachable {
                completion(.success(agent))
            } else {
                let message = agent.map {
                    $0.error.flatMap { $0.isEmpty ? nil : $0 }
                        ?? "Agent \($0.name) is \($0.agentState), without an attachable terminal."
                } ?? "Agent \(id) is no longer listed by this SafeYolo host."
                completion(.failure(NSError(domain: "SafeYolo.Terminal", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: message])))
            }
        }
    }

    func presentDesktop(
        for agent: AgentInfo,
        completion: @escaping (Result<DesktopPresentation, Error>) -> Void
    ) {
        guard !busyAgentIDs.contains(agent.agentID) else { return }
        busyAgentIDs.insert(agent.agentID)
        Task {
            defer { busyAgentIDs.remove(agent.agentID) }
            do {
                guard let encodedID = encodePathComponent(agent.agentID) else {
                    throw ClientError.invalidURL(agent.agentID)
                }
                let data = try await request(
                    path: "/admin/agents/\(encodedID)/desktop/present",
                    method: "POST"
                )
                let presentation = try JSONDecoder().decode(DesktopPresentation.self, from: data)
                setRequestError("Present desktop", nil)
                completion(.success(presentation))
            } catch {
                setRequestError("Present desktop", error)
                completion(.failure(error))
            }
        }
    }

    func clearSecurityEvents() {
        securityEvents = []
        knownSecurityEventIDs = []
    }

    func openWebMITM(copyKey: (String) -> Bool, openBrowser: (URL) -> Bool) throws {
        webMITMKeyCopied = false
        guard let url = webmitmURL else { throw WebMITMOpenError.unavailable }
        guard copyKey(token) else { throw WebMITMOpenError.clipboard }
        webMITMKeyCopied = true
        guard openBrowser(url) else { throw WebMITMOpenError.browser }
    }

    func clearEventFeedGap() {
        eventFeedGap = nil
    }

    @discardableResult
    func refreshInstance() async -> Bool {
        do {
            let data = try await request(path: "/admin/instance")
            let instance = try JSONDecoder().decode(
                InstanceInfo.self,
                from: data
            )
            let validatedID = try validatePinnedInstanceID(
                actual: instance.safeyoloInstanceID,
                expected: expectedInstanceID
            )
            if instanceID != validatedID { instanceID = validatedID }
            if hostUser != instance.hostUser { hostUser = instance.hostUser }
            if hostExecutable != instance.hostExecutable { hostExecutable = instance.hostExecutable }
            if hostRoot != instance.hostRoot { hostRoot = instance.hostRoot }
            if hostConfigPath != instance.hostConfigPath { hostConfigPath = instance.hostConfigPath }
            let freshWebURL = instance.webmitmURL.flatMap { URL(string: $0) }
            if webmitmURL != freshWebURL { webmitmURL = freshWebURL }
            if eventEndpoint != instance.commandCentreEvents { eventEndpoint = instance.commandCentreEvents }
            if !adminConnected { adminConnected = true }
            diagnostics.lastAdminSuccess = Date()
            setRequestError("Instance identity", nil)
            return true
        } catch {
            guard !Task.isCancelled else { return false }
            if adminConnected { adminConnected = false }
            setRequestError("Instance identity", error)
            return false
        }
    }

    @discardableResult
    private func refreshApprovals() async -> Bool {
        do {
            let data = try await request(path: "/admin/approvals")
            let fresh = try JSONDecoder().decode(PendingApprovals.self, from: data).approvals
            var ids = Set(networkOutcomes.keys).union(unavailableNetworkOutcomes)
            for item in fresh where item.details?.networkAction?.kind == "network_allow" {
                if let id = item.requestID { ids.insert(id) }
            }
            for id in ids.sorted() {
                guard let encoded = encodePathComponent(id) else { continue }
                do {
                    let outcome = try await readNetworkOutcome("/admin/approvals/\(encoded)")
                    guard outcome.requestID == id else { throw ClientError.invalidResponse }
                    networkOutcomes[id] = outcome
                    unavailableNetworkOutcomes.remove(id)
                } catch {
                    unavailableNetworkOutcomes.insert(id)
                }
            }
            if approvals != fresh { approvals = fresh }
            let newApprovals = fresh.filter { !knownApprovalIDs.contains($0.id) }
            knownApprovalIDs = Set(fresh.map(\.id))
            for approval in newApprovals {
                onNewApproval?(approval)
            }
            setRequestError("Pending approvals", nil)
            return true
        } catch {
            guard !Task.isCancelled else { return false }
            setRequestError("Pending approvals", error)
            return false
        }
    }

    private func readNetworkOutcome(_ path: String) async throws -> NetworkApprovalResolution {
        let data = try await request(path: path)
        return try JSONDecoder().decode(NetworkApprovalResolution.self, from: data)
    }

    @discardableResult
    func refreshAgents() async -> Bool {
        do {
            let data = try await request(path: "/admin/agents")
            let fresh = try JSONDecoder().decode(AgentInventory.self, from: data).agents
            if agents != fresh { agents = fresh }
            finishPendingTerminals(agents, completeInventory: true)
            setRequestError("Agent status", nil)
            return true
        } catch {
            guard !Task.isCancelled else { return false }
            setRequestError("Agent status", error)
            return false
        }
    }

    private func connectEvents() async {
        guard !stopping, !Task.isCancelled else {
            return
        }
        var request = URLRequest(url: eventsURL)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let socket = makeEventSocket(request)
        diagnostics.socketAttempts += 1
        webSocket = socket
        socket.resume()
        defer {
            socket.cancel(with: .goingAway, reason: nil)
            if webSocket === socket { webSocket = nil }
        }
        do {
            try await ping(socket)
            guard !stopping, !Task.isCancelled, webSocket === socket else { return }
            diagnostics.lastEventSuccess = Date()
            // The listener starts at its handshake audit offset. Re-read the
            // pending list so an approval created after the earlier snapshot
            // but before this handshake cannot fall between both channels.
            guard await refreshApprovals() else { throw ClientError.invalidResponse }
            guard !stopping, !Task.isCancelled, webSocket === socket else { return }
            setConnectionState(.connected)
            if eventFeedGap != nil {
                eventFeedGap = "Live event feed reconnected after a gap; events during the gap may be missing."
            }
            setRequestError("Live events", nil)
            try await receiveEvents(from: socket)
        } catch {
            guard !stopping, !Task.isCancelled, webSocket === socket else { return }
            if let response = socket.response as? HTTPURLResponse {
                diagnostics.record("WebSocket HTTP status: \(response.statusCode)")
            }
            if socket.closeCode != .invalid {
                diagnostics.record("WebSocket close code: \(socket.closeCode.rawValue)")
            }
            setConnectionState(.reconnecting)
            if diagnostics.lastEventSuccess != nil {
                let gap = "Live event feed interrupted; events during this gap may be missing."
                if eventFeedGap != gap { eventFeedGap = gap }
            }
            setRequestError("Live events", error)
        }
    }

    private func receiveEvents(from socket: any EventSocket) async throws {
        while !stopping, !Task.isCancelled, webSocket === socket {
            let message = try await socket.receive()
            try Task.checkCancellation()
            let data: Data
            switch message {
            case .data(let value): data = value
            case .string(let value): data = Data(value.utf8)
            @unknown default: continue
            }
            try await ingestOperatorEventData(data)
            diagnostics.lastEventReceived = Date()
        }
    }

    func ingestOperatorEventData(_ data: Data) async throws {
        let event = try JSONDecoder().decode(OperatorEventEnvelope.self, from: data)
        if event.needsApproval || event.event.hasPrefix("admin.") {
            guard await refreshApprovals() else {
                throw ClientError.invalidResponse
            }
        }
        if event.event.hasPrefix("agent.") {
            _ = await refreshAgents()
        }
        if event.isSecurityObservation {
            recordSecurityEvent(event)
        }
    }

    private func recordSecurityEvent(_ event: OperatorEventEnvelope) {
        if let eventID = event.eventID {
            guard !knownSecurityEventIDs.contains(eventID) else { return }
            knownSecurityEventIDs.insert(eventID)
        }
        if let index = securityEvents.firstIndex(where: { $0.id == event.coalescingKey }) {
            securityEvents[index].observe(event)
            return
        }
        let observation = SecurityObservation(event)
        securityEvents.insert(observation, at: 0)
        onNewSecurityEvent?(observation)
    }

    private func ping(_ socket: any EventSocket) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            socket.sendPing { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private func request(
        path: String,
        method: String = "GET",
        json: [String: Any]? = nil
    ) async throws -> Data {
        guard let url = URL(string: path, relativeTo: adminURL)?.absoluteURL else {
            throw ClientError.invalidURL(path)
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        if method == "POST" && path.hasPrefix("/admin/agents/") {
            request.timeoutInterval = 130
        }
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        if let json {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: json)
        }
        let (data, response) = try await session.data(for: request)
        try Task.checkCancellation()
        guard let httpResponse = response as? HTTPURLResponse else {
            throw ClientError.invalidResponse
        }
        guard (200..<300).contains(httpResponse.statusCode) else {
            let message = (try? JSONSerialization.jsonObject(with: data) as? [String: String])?["error"]
                ?? String(data: data, encoding: .utf8)
                ?? "request failed"
            throw ClientError.requestFailed(httpResponse.statusCode, message)
        }
        return data
    }
}
