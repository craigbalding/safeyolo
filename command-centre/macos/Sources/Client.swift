import Combine
import Foundation

@MainActor
final class SafeYoloClient: ObservableObject {
    enum ConnectionState: String {
        case connecting = "Connecting…"
        case connected = "Connected"
        case reconnecting = "Reconnecting…"
        case stopped = "Stopped"
    }

    @Published private(set) var connectionState = ConnectionState.connecting
    @Published private(set) var approvals: [ApprovalEvent] = []
    @Published private(set) var agents: [AgentInfo] = []
    @Published private(set) var securityEvents: [SecurityObservation] = []
    @Published private(set) var busyAgentIDs = Set<String>()
    @Published private(set) var instanceID = ""
    @Published private(set) var hostUser: String?
    @Published private(set) var hostPython: String?
    @Published private(set) var requestErrors: [String: String] = [:]
    @Published private(set) var eventFeedGap: String?

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
    private var webSocket: URLSessionWebSocketTask?
    private var connectionTask: Task<Void, Never>?
    private var knownApprovalIDs = Set<String>()
    private var knownSecurityEventIDs = Set<String>()
    private var stopping = false

    init(
        adminURL: String,
        eventsURL: String,
        token: String,
        expectedInstanceID: String,
        session: URLSession = .shared
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
    }

    func start() {
        stopping = false
        connectionState = .connecting
        reconnectUntilAvailable()
    }

    func stop() {
        stopping = true
        connectionState = .stopped
        connectionTask?.cancel()
        connectionTask = nil
        webSocket?.cancel(with: .goingAway, reason: nil)
        webSocket = nil
    }

    private func reconnectUntilAvailable() {
        connectionTask?.cancel()
        connectionTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled, !stopping {
                if await refreshInstance() {
                    let approvalsReady = await refreshApprovals()
                    let agentsReady = await refreshAgents()
                    guard !Task.isCancelled, !stopping else { return }
                    if approvalsReady && agentsReady {
                        connectionTask = nil
                        connectEvents()
                        return
                    }
                }
                guard !Task.isCancelled, !stopping else { return }
                connectionState = .reconnecting
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func resolve(
        _ event: ApprovalEvent,
        allow: Bool,
        completion: @escaping (Result<ResolutionResult, Error>) -> Void
    ) {
        Task {
            do {
                let plan = try MutationPlan.forApproval(event, allow: allow)
                let data = try await request(path: plan.path, method: "POST", json: plan.body)
                let result: ResolutionResult
                if plan.expectsDesktop {
                    result = .desktop(try JSONDecoder().decode(DesktopPresentation.self, from: data))
                } else {
                    result = .decided(allow ? "Allowed" : "Denied")
                }
                await refreshApprovals()
                requestErrors["Approval decision"] = nil
                completion(.success(result))
            } catch {
                requestErrors["Approval decision"] = error.localizedDescription
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
                await refreshAgents()
                requestErrors["Run or stop agent"] = nil
                completion(.success(updated))
            } catch {
                requestErrors["Run or stop agent"] = error.localizedDescription
                completion(.failure(error))
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
                requestErrors["Present desktop"] = nil
                completion(.success(presentation))
            } catch {
                requestErrors["Present desktop"] = error.localizedDescription
                completion(.failure(error))
            }
        }
    }

    func clearSecurityEvents() {
        securityEvents = []
        knownSecurityEventIDs = []
    }

    func clearEventFeedGap() {
        eventFeedGap = nil
    }

    private func refreshInstance() async -> Bool {
        do {
            let data = try await request(path: "/admin/instance")
            let instance = try JSONDecoder().decode(
                InstanceInfo.self,
                from: data
            )
            instanceID = try validatePinnedInstanceID(
                actual: instance.safeyoloInstanceID,
                expected: expectedInstanceID
            )
            hostUser = instance.hostUser
            hostPython = instance.hostPython
            requestErrors["Instance identity"] = nil
            return true
        } catch {
            requestErrors["Instance identity"] = error.localizedDescription
            return false
        }
    }

    @discardableResult
    private func refreshApprovals() async -> Bool {
        do {
            let data = try await request(path: "/admin/approvals")
            let fresh = try JSONDecoder().decode(PendingApprovals.self, from: data).approvals
            approvals = fresh
            let newApprovals = fresh.filter { !knownApprovalIDs.contains($0.id) }
            knownApprovalIDs = Set(fresh.map(\.id))
            if let first = newApprovals.first {
                onNewApproval?(first)
            }
            requestErrors["Pending approvals"] = nil
            return true
        } catch {
            requestErrors["Pending approvals"] = error.localizedDescription
            return false
        }
    }

    @discardableResult
    func refreshAgents() async -> Bool {
        do {
            let data = try await request(path: "/admin/agents")
            agents = try JSONDecoder().decode(AgentInventory.self, from: data).agents
            requestErrors["Agent status"] = nil
            return true
        } catch {
            requestErrors["Agent status"] = error.localizedDescription
            return false
        }
    }

    private func connectEvents() {
        guard !stopping else {
            return
        }
        var request = URLRequest(url: eventsURL)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let socket = session.webSocketTask(with: request)
        webSocket = socket
        socket.resume()
        Task {
            do {
                try await ping(socket)
                guard !stopping, webSocket === socket else { return }
                connectionState = .connected
                if eventFeedGap != nil {
                    eventFeedGap = "Live event feed reconnected after a gap; events during the gap may be missing."
                }
                requestErrors["Live events"] = nil
                await receiveEvents(from: socket)
            } catch {
                handleEventDisconnect(socket, error: error)
            }
        }
    }

    private func receiveEvents(from socket: URLSessionWebSocketTask) async {
        do {
            while !stopping, webSocket === socket {
                let message = try await socket.receive()
                let data: Data
                switch message {
                case .data(let value): data = value
                case .string(let value): data = Data(value.utf8)
                @unknown default: continue
                }
                try await ingestOperatorEventData(data)
            }
        } catch {
            handleEventDisconnect(socket, error: error)
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
            guard await refreshAgents() else {
                throw ClientError.invalidResponse
            }
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

    private func handleEventDisconnect(_ socket: URLSessionWebSocketTask, error: Error) {
        guard !stopping, webSocket === socket else { return }
        connectionState = .reconnecting
        eventFeedGap = "Live event feed interrupted; events during this gap may be missing."
        requestErrors["Live events"] = error.localizedDescription
        webSocket = nil
        reconnectUntilAvailable()
    }

    private func ping(_ socket: URLSessionWebSocketTask) async throws {
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
        json: [String: String]? = nil
    ) async throws -> Data {
        guard let url = URL(string: path, relativeTo: adminURL)?.absoluteURL else {
            throw ClientError.invalidURL(path)
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        if let json {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: json)
        }
        let (data, response) = try await session.data(for: request)
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
