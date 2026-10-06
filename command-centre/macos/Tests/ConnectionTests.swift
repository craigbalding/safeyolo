import Combine
import Foundation

private final class StubEventSocket: EventSocket {
    var response: URLResponse?
    var closeCode = URLSessionWebSocketTask.CloseCode.invalid
    var pingError: Error?
    var receiveError: Error?
    var cancelled = false
    var receiving = false
    var onResume: (() -> Void)?
    var messages: [URLSessionWebSocketTask.Message] = []

    func resume() { onResume?() }
    func sendPing(pongReceiveHandler: @escaping @Sendable (Error?) -> Void) { pongReceiveHandler(pingError) }
    func cancel(with closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) { cancelled = true }
    func receive() async throws -> URLSessionWebSocketTask.Message {
        receiving = true
        while !cancelled {
            if let receiveError { throw receiveError }
            if !messages.isEmpty { return messages.removeFirst() }
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
        try await testMultiplePendingApprovals()
        try await testApprovalInSubscriptionGapAndReconnect()
        try await testFailedHandshakeSnapshotRetriesPendingApproval()
        try await testAgentInventoryFailureDoesNotBlockApprovals()
        try await testCanonicalNetworkResolution()
        try await testDisabledEventsAndRecovery()
        try await testSocketFailurePacingAndRecovery()
        try await testRealSocketRefusalPacing()
        try await testRemoteDisabledGuidance()
        print("connection-tests: PASS approvals, disabled, legacy, retry pacing, stable snapshots, recovery, cancellation, redaction")
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

    private static func pendingApprovals(_ keys: [String]) -> Data {
        let approvals: [[String: Any]] = keys.map { key in
            [
                "event": "security.credential_guard", "summary": "Credential needs approval",
                "agent": "forge", "host": "api.example.com",
                "approval": [
                    "required": true, "approval_type": "credential",
                    "key": key, "target": "api.example.com",
                ],
            ]
        }
        return try! JSONSerialization.data(withJSONObject: ["approvals": approvals])
    }

    private static var approvalEvent: URLSessionWebSocketTask.Message {
        .string(#"{"event":"security.credential_guard","kind":"security","severity":"high","summary":"Credential needs approval","approval":{"required":true}}"#)
    }

    private static var agentEvent: URLSessionWebSocketTask.Message {
        .string(#"{"event":"agent.started","kind":"admin","severity":"info","summary":"Agent started"}"#)
    }

    @MainActor
    private static func testCanonicalNetworkResolution() async throws {
        let event = try JSONDecoder().decode(ApprovalEvent.self, from: Data(#"{"event":"proxy.network_guard","request_id":"req-canonical","agent":"worker","summary":"Reusable network access","approval":{"required":true,"approval_type":"network_egress","key":"worker:origin:443","target":"origin:443"},"details":{"network_action":{"kind":"network_allow"}}}"#.utf8))
        for (status, message) in [("approved", "Approved"), ("rejected", "Rejected")] {
            snapshot()
            defer { StubURLProtocol.responsesByPath = [:] }
            StubURLProtocol.responsesByPath["/admin/approvals/req-canonical"] = (200, Data("{\"status\":\"\(status)\"}".utf8))
            let client = try SafeYoloClient(adminURL: "http://127.0.0.1:19090",
                eventsURL: "ws://127.0.0.1:19091/admin/events", token: "fixture-secret",
                expectedInstanceID: "sy-connection-test", session: stubSession())
            defer { client.stop() }
            var result: Result<ResolutionResult, Error>?
            client.resolve(event, allow: status == "rejected") { result = $0 }
            try await until { result != nil }
            let observed = try result!.get()
            precondition(observed == .decided(message), "Use the canonical outcome even when the other decision won")
        }
    }

    @MainActor
    private static func testMultiplePendingApprovals() async throws {
        snapshot()
        defer { StubURLProtocol.responsesByPath = [:] }
        StubURLProtocol.responsesByPath["/admin/approvals"] = (200, pendingApprovals(["one", "two"]))
        let socket = StubEventSocket()
        let client = try SafeYoloClient(
            adminURL: "http://127.0.0.1:19090", eventsURL: "ws://127.0.0.1:19091/admin/events",
            token: "fixture-secret", expectedInstanceID: "sy-connection-test", session: stubSession(),
            makeEventSocket: { _ in socket }
        )
        defer { client.stop() }
        var presented: [String] = []
        client.onNewApproval = { presented.append($0.id) }
        client.start()
        try await until { socket.receiving }
        precondition(presented == ["one:api.example.com", "two:api.example.com"])
        precondition(client.approvals.map(\.id) == presented, "Every presentation callback must have a pending menu item")

        socket.messages.append(approvalEvent)
        try await until { !client.diagnosticReport.contains("Last live event received: Never") }
        precondition(presented.count == 2, "An unchanged snapshot must not reopen windows")
        StubURLProtocol.responsesByPath["/admin/approvals"] = (200, pendingApprovals(["two"]))
        socket.messages.append(approvalEvent)
        try await until { client.approvals.count == 1 }
        precondition(client.approvals[0].id == "two:api.example.com" && presented.count == 2,
                     "A resolved approval must leave the menu without another window")
    }

    @MainActor
    private static func testApprovalInSubscriptionGapAndReconnect() async throws {
        snapshot()
        defer { StubURLProtocol.responsesByPath = [:] }
        let gate = RetryGate()
        let first = StubEventSocket()
        first.onResume = {
            // The server starts streaming at the handshake audit offset. This
            // approval is absent from the earlier HTTP snapshot and stream.
            StubURLProtocol.responsesByPath["/admin/approvals"] = (200, pendingApprovals(["gap"]))
        }
        let second = StubEventSocket()
        let third = StubEventSocket()
        var sockets = 0
        let client = try SafeYoloClient(
            adminURL: "http://127.0.0.1:19090", eventsURL: "ws://127.0.0.1:19091/admin/events",
            token: "fixture-secret", expectedInstanceID: "sy-connection-test", session: stubSession(),
            makeEventSocket: { _ in
                sockets += 1
                return sockets == 1 ? first : sockets == 2 ? second : third
            },
            retryPause: { try await gate.pause() }
        )
        defer { client.stop(); gate.release() }
        var presented: [String] = []
        client.onNewApproval = { presented.append($0.id) }
        client.start()
        try await until { first.receiving }
        precondition(presented == ["gap:api.example.com"] && client.approvals.map(\.id) == presented,
                     "A pending approval in the subscribe gap must be presented and appear in the menu")

        first.receiveError = URLError(.networkConnectionLost)
        try await until { gate.waits == 1 }
        StubURLProtocol.responsesByPath["/admin/approvals"] = (200, pendingApprovals([]))
        gate.release()
        try await until { second.receiving }
        precondition(client.approvals.isEmpty && presented.count == 1,
                     "Reconnect must remove resolved approvals without replaying their windows")
        second.receiveError = URLError(.networkConnectionLost)
        try await until { gate.waits == 2 }
        StubURLProtocol.responsesByPath["/admin/approvals"] = (200, pendingApprovals(["during-outage"]))
        gate.release()
        try await until { third.receiving }
        precondition(presented == ["gap:api.example.com", "during-outage:api.example.com"],
                     "Reconnect must present a still-pending approval missed during the outage")
    }

    @MainActor
    private static func testFailedHandshakeSnapshotRetriesPendingApproval() async throws {
        snapshot()
        defer { StubURLProtocol.responsesByPath = [:] }
        let gate = RetryGate()
        let first = StubEventSocket()
        first.onResume = {
            StubURLProtocol.responsesByPath["/admin/approvals"] = (503, Data(#"{"error":"temporarily unavailable"}"#.utf8))
        }
        let second = StubEventSocket()
        var sockets = 0
        let client = try SafeYoloClient(
            adminURL: "http://127.0.0.1:19090", eventsURL: "ws://127.0.0.1:19091/admin/events",
            token: "fixture-secret", expectedInstanceID: "sy-connection-test", session: stubSession(),
            makeEventSocket: { _ in sockets += 1; return sockets == 1 ? first : second },
            retryPause: { try await gate.pause() }
        )
        defer { client.stop(); gate.release() }
        var presented: [String] = []
        client.onNewApproval = { presented.append($0.id) }
        client.start()
        try await until { gate.waits == 1 }
        precondition(first.cancelled && client.connectionState == .reconnecting && presented.isEmpty)
        precondition(client.requestErrors["Pending approvals"] != nil)

        StubURLProtocol.responsesByPath["/admin/approvals"] = (200, pendingApprovals(["recovered"]))
        gate.release()
        try await until { second.receiving }
        precondition(client.connectionState == .connected)
        precondition(presented == ["recovered:api.example.com"] && client.approvals.map(\.id) == presented)
        precondition(client.requestErrors["Pending approvals"] == nil && client.requestErrors["Live events"] == nil)
    }

    @MainActor
    private static func testAgentInventoryFailureDoesNotBlockApprovals() async throws {
        snapshot()
        defer { StubURLProtocol.responsesByPath = [:] }
        // Native Rust's configured-listener inventory lacks the Mac client's
        // richer agent fields. Its decode error must not suppress approvals.
        StubURLProtocol.responsesByPath["/admin/agents"] = (200, Data(
            #"{"agents":[{"agent_id":"alice","socket_path":"/tmp/alice.sock","status":"configured"}]}"#.utf8
        ))
        StubURLProtocol.responsesByPath["/admin/approvals"] = (200, pendingApprovals(["first"]))
        let socket = StubEventSocket()
        let client = try SafeYoloClient(
            adminURL: "http://127.0.0.1:19090", eventsURL: "ws://127.0.0.1:19091/admin/events",
            token: "fixture-secret", expectedInstanceID: "sy-connection-test", session: stubSession(),
            makeEventSocket: { _ in socket }
        )
        defer { client.stop() }
        var presented: [String] = []
        client.onNewApproval = { presented.append($0.id) }
        client.start()
        try await until { socket.receiving }
        precondition(client.connectionState == .connected && presented == ["first:api.example.com"])
        precondition(client.requestErrors["Agent status"] != nil && client.requestErrors["Live events"] == nil)

        socket.messages.append(agentEvent)
        try await until { !client.diagnosticReport.contains("Last live event received: Never") }
        precondition(client.connectionState == .connected && client.requestErrors["Agent status"] != nil,
                     "An agent refresh failure must keep the approval event stream open")
        StubURLProtocol.responsesByPath["/admin/approvals"] = (200, pendingApprovals(["first", "second"]))
        socket.messages.append(approvalEvent)
        try await until { presented.count == 2 }
        precondition(presented == ["first:api.example.com", "second:api.example.com"])
        precondition(client.approvals.map(\.id) == presented)
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
        precondition(client.connectionGuidance!.contains("[command_centre]"))
        precondition(client.connectionGuidance!.contains("Agents stay running."))
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
        precondition(client.connectionGuidance!.contains("Check [command_centre]"))
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
