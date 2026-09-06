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
    @Published private(set) var instanceID = ""
    @Published private(set) var lastError: String?

    var onNewApproval: ((ApprovalEvent) -> Void)?

    private let adminURL: URL
    private let eventsURL: URL
    private let token: String
    private let expectedInstanceID: String
    private let session: URLSession
    private var webSocket: URLSessionWebSocketTask?
    private var connectionTask: Task<Void, Never>?
    private var knownApprovalIDs = Set<String>()
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
                    await refreshApprovals()
                    guard !Task.isCancelled, !stopping else { return }
                    connectionTask = nil
                    connectEvents()
                    return
                }
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
                completion(.success(result))
            } catch {
                lastError = error.localizedDescription
                completion(.failure(error))
            }
        }
    }

    private func refreshInstance() async -> Bool {
        do {
            let data = try await request(path: "/admin/instance")
            let actualInstanceID = try JSONDecoder().decode(
                InstanceInfo.self,
                from: data
            ).safeyoloInstanceID
            instanceID = try validatePinnedInstanceID(
                actual: actualInstanceID,
                expected: expectedInstanceID
            )
            connectionState = .connected
            lastError = nil
            return true
        } catch {
            connectionState = .reconnecting
            lastError = error.localizedDescription
            return false
        }
    }

    private func refreshApprovals() async {
        do {
            let data = try await request(path: "/admin/approvals")
            let fresh = try JSONDecoder().decode(PendingApprovals.self, from: data).approvals
            approvals = fresh
            let newApprovals = fresh.filter { !knownApprovalIDs.contains($0.id) }
            knownApprovalIDs = Set(fresh.map(\.id))
            if let first = newApprovals.first {
                onNewApproval?(first)
            }
            connectionState = .connected
            lastError = nil
        } catch {
            connectionState = .reconnecting
            lastError = error.localizedDescription
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
            await receiveEvents(from: socket)
        }
    }

    private func receiveEvents(from socket: URLSessionWebSocketTask) async {
        do {
            while !stopping, webSocket === socket {
                _ = try await socket.receive()
                await refreshApprovals()
            }
        } catch {
            guard !stopping, webSocket === socket else {
                return
            }
            connectionState = .reconnecting
            lastError = "Live events disconnected: \(error.localizedDescription)"
            if !stopping, webSocket === socket {
                webSocket = nil
                reconnectUntilAvailable()
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
