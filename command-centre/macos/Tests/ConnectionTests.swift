import Combine
import Foundation

private final class StubEventSocket: EventSocket {
    var response: URLResponse?
    var closeCode = URLSessionWebSocketTask.CloseCode.invalid
    var pingError: Error?
    var receiveError: Error?
    var cancelled = false
    var receiving = false

    func resume() {}
    func sendPing(pongReceiveHandler: @escaping @Sendable (Error?) -> Void) { pongReceiveHandler(pingError) }
    func cancel(with closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) { cancelled = true }
    func receive() async throws -> URLSessionWebSocketTask.Message {
        receiving = true
        while !cancelled {
            if let receiveError { throw receiveError }
            try await Task.sleep(for: .milliseconds(5))
        }
        throw CancellationError()
    }
}

@MainActor
private final class RetryGate {
    var waits = 0
    private var continuation: CheckedContinuation<Void, Error>?

    func pause() async throws {
        waits += 1
        try await withCheckedThrowingContinuation { continuation = $0 }
    }

    func release() {
        let next = continuation
        continuation = nil
        next?.resume()
    }
}

extension ModelTests {
    @MainActor
    static func testConnectionDiagnostics() async throws {
        try testDiagnosticRedaction()
        try await testDisabledEventsAndRecovery()
        try await testSocketFailurePacingAndRecovery()
        try await testRealSocketRefusalPacing()
        try await testRemoteDisabledGuidance()
        print("connection-tests: PASS disabled, legacy, retry pacing, stable snapshots, recovery, cancellation, redaction")
    }

    @MainActor
    private static func until(_ condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(4)
        while !condition(), Date() < deadline { try await Task.sleep(for: .milliseconds(5)) }
        precondition(condition(), "Connection test did not reach its required state")
    }

    private static func snapshot(events: String = "") {
        StubURLProtocol.failuresRemaining = 0
        StubURLProtocol.requestCount = 0
        StubURLProtocol.responsesByPath = [
            "/admin/instance": (200, Data("""
            {"schema_version":1,"safeyolo_instance_id":"sy-connection-test"\(events)}
            """.utf8)),
            "/admin/approvals": (200, Data(#"{"approvals":[]}"#.utf8)),
            "/admin/agents": (200, Data(#"{"agents":[{"agent_id":"ag-test","name":"test","sandbox_state":"ready","agent_state":"running","attachable":true}]}"#.utf8)),
        ]
    }

    private static func stubSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        return URLSession(configuration: config)
    }

    @MainActor
    private static func testDisabledEventsAndRecovery() async throws {
        snapshot(events: #", "command_centre_events":{"enabled":false,"port":null}"#)
        defer { StubURLProtocol.responsesByPath = [:] }
        let gate = RetryGate()
        let socket = StubEventSocket()
        var socketCount = 0
        let client = try SafeYoloClient(
            adminURL: "http://127.0.0.1:19090", eventsURL: "ws://127.0.0.1:19091/admin/events",
            token: "fixture-secret", expectedInstanceID: "sy-connection-test", session: stubSession(),
            isLocalConnection: true,
            makeEventSocket: { _ in socketCount += 1; return socket }, retryPause: { try await gate.pause() }
        )
        defer { client.stop(); gate.release() }
        client.start()
        try await until { gate.waits == 1 }
        precondition(client.connectionState == .eventsDisabled && client.adminConnected)
        precondition(client.agents.count == 1 && socketCount == 0)
        precondition(client.connectionGuidance!.contains("On this Mac"))
        precondition(client.connectionGuidance!.contains("safeyolo command-centre enable"))
        precondition(client.connectionGuidance!.contains("do not add --all"))
        precondition(client.eventFeedGap == nil, "A feed that never connected has no observed interruption")
        var updates = 0
        let subscription = client.objectWillChange.sink { updates += 1 }
        defer { subscription.cancel() }
        gate.release()
        try await until { gate.waits == 2 }
        precondition(updates == 0, "Unchanged snapshots must not rebuild open menus")
        snapshot(events: #", "command_centre_events":{"enabled":true,"port":19091}"#)
        gate.release()
        try await until { socket.receiving }
        precondition(client.connectionState == .connected && client.connectionGuidance == nil)
        precondition(socketCount == 1)
        precondition(client.diagnosticReport.contains("Live events disabled"), "Recovery erased history")
        client.stop()
        precondition(socket.cancelled && client.connectionState == .stopped)
    }

    @MainActor
    private static func testSocketFailurePacingAndRecovery() async throws {
        // An older backend omits the listener field. Do not diagnose it as disabled.
        snapshot()
        defer { StubURLProtocol.responsesByPath = [:] }
        let gate = RetryGate()
        let healthy = StubEventSocket()
        var sockets: [StubEventSocket] = []
        let client = try SafeYoloClient(
            adminURL: "http://127.0.0.1:19090", eventsURL: "ws://127.0.0.1:19091/admin/events",
            token: "fixture-secret", expectedInstanceID: "sy-connection-test", session: stubSession(),
            makeEventSocket: { request in
                precondition(request.value(forHTTPHeaderField: "Authorization") == "Bearer fixture-secret")
                let socket = sockets.count < 2 ? StubEventSocket() : healthy
                if sockets.count < 2 { socket.pingError = URLError(.cannotConnectToHost) }
                sockets.append(socket)
                return socket
            }, retryPause: { try await gate.pause() }
        )
        defer { client.stop(); gate.release() }
        client.start()
        try await until { gate.waits == 1 }
        precondition(sockets.count == 1 && sockets[0].cancelled)
        precondition(client.connectionState == .reconnecting && client.adminConnected)
        precondition(client.eventEndpoint == nil && client.eventFeedGap == nil)
        precondition(client.connectionGuidance!.contains("On the connected SafeYolo host"))
        precondition(client.connectionGuidance!.contains("If disabled"))
        precondition(client.diagnosticReport.contains("NSURLErrorDomain (-1004)"))
        var updates = 0
        let subscription = client.objectWillChange.sink { updates += 1 }
        defer { subscription.cancel() }
        gate.release()
        try await until { gate.waits == 2 }
        precondition(sockets.count == 2 && sockets[1].cancelled)
        precondition(updates == 0, "Repeated identical failures must not rebuild open menus")
        gate.release()
        try await until { healthy.receiving }
        precondition(client.requestErrors["Live events"] == nil && client.connectionState == .connected)
        precondition(client.diagnosticReport.contains("NSURLErrorDomain (-1004)"), "Recovery erased the failure")
        healthy.receiveError = URLError(.networkConnectionLost)
        healthy.response = HTTPURLResponse(url: URL(string: "http://fixture.invalid")!, statusCode: 101,
                                           httpVersion: "HTTP/1.1", headerFields: nil)
        healthy.closeCode = .goingAway
        try await until { gate.waits == 3 }
        precondition(client.eventFeedGap != nil && healthy.cancelled)
        precondition(client.diagnosticReport.contains("NSURLErrorDomain (-1005)"))
        precondition(client.diagnosticReport.contains("WebSocket HTTP status: 101"))
        precondition(client.diagnosticReport.contains("WebSocket close code: 1001"))
        client.stop()
        gate.release()
        await Task.yield()
        precondition(sockets.count == 3 && client.connectionState == .stopped)
    }

    @MainActor
    private static func testRemoteDisabledGuidance() async throws {
        snapshot(events: #", "command_centre_events":{"enabled":false,"port":null}"#)
        defer { StubURLProtocol.responsesByPath = [:] }
        let gate = RetryGate()
        let client = try SafeYoloClient(
            adminURL: "http://127.0.0.1:19090", eventsURL: "ws://127.0.0.1:19091/admin/events",
            token: "fixture-secret", expectedInstanceID: "sy-connection-test", session: stubSession(),
            makeEventSocket: { _ in preconditionFailure("Disabled host must not open a socket") },
            retryPause: { try await gate.pause() }
        )
        defer { client.stop(); gate.release() }
        client.start()
        try await until { gate.waits == 1 }
        precondition(client.connectionGuidance!.contains("On the connected SafeYolo host"))
        precondition(!client.connectionGuidance!.contains("On this Mac"), "An SSH tunnel is not a local host")
    }

    @MainActor
    private static func testRealSocketRefusalPacing() async throws {
        snapshot()
        defer { StubURLProtocol.responsesByPath = [:] }
        var attempts: [ContinuousClock.Instant] = []
        let realSession = URLSession(configuration: .ephemeral)
        defer { realSession.invalidateAndCancel() }
        let client = try SafeYoloClient(
            adminURL: "http://127.0.0.1:19090", eventsURL: "ws://127.0.0.1:1/admin/events",
            token: "fixture-secret", expectedInstanceID: "sy-connection-test", session: stubSession(),
            makeEventSocket: { request in
                attempts.append(ContinuousClock.now)
                return realSession.webSocketTask(with: request)
            }
        )
        defer { client.stop() }
        client.start()
        try await until { attempts.count >= 2 && client.requestErrors["Live events"] != nil }
        precondition(attempts[0].duration(to: attempts[1]) >= .seconds(1), "Real socket refusal bypassed backoff")
        precondition(client.agents.count == 1 && client.connectionState == .reconnecting)
        client.stop()
    }

    private static func testDiagnosticRedaction() throws {
        let url = URL(string: "wss://user:password@example.test:9444/secret-path?token=query-secret#fragment-secret")!
        precondition(ConnectionDiagnostics.endpoint(url) == "wss://example.test:9444")
        var diagnostics = ConnectionDiagnostics()
        diagnostics.failure("Live events", error: URLError(.cannotConnectToHost, userInfo: [
            NSLocalizedDescriptionKey: "Bearer payload-secret", NSURLErrorFailingURLErrorKey: url
        ]))
        diagnostics.failure("Admin API", error: ClientError.requestFailed(401, "Bearer body-secret"))
        diagnostics.failure("Live events", error: NSError(domain: NSPOSIXErrorDomain, code: 57,
                            userInfo: [NSLocalizedDescriptionKey: "posix-secret"]))
        diagnostics.record("State: Connected")
        let report = diagnostics.report()
        for secret in ["payload-secret", "body-secret", "posix-secret", "password", "query-secret", "secret-path"] {
            precondition(!report.contains(secret), "Diagnostic report contained sensitive input")
        }
        precondition(report.contains("HTTP 401") && report.contains("NSURLErrorDomain (-1004)"))
        precondition(report.contains("Cannot connect to the server") && report.contains("NSPOSIXErrorDomain (57)"))
        precondition(report.contains("State: Connected") && report.contains("Last failure"))
    }
}
