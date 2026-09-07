import Combine
import Foundation

private final class MemoryCredentialStore: CredentialStore {
    var values: [String: String] = [:]

    func load(account: String) throws -> String? {
        values[account]
    }

    func store(account: String, token: String) throws {
        values[account] = token
    }

    func delete(account: String) throws {
        values.removeValue(forKey: account)
    }
}

private final class StubURLProtocol: URLProtocol {
    static var responseData = Data()
    static var responseStatus = 200
    static var observedAuthorization: String?
    static var failuresRemaining = 0
    static var requestCount = 0
    static var responsesByPath: [String: (Int, Data)] = [:]

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        Self.requestCount += 1
        Self.observedAuthorization = request.value(forHTTPHeaderField: "Authorization")
        if Self.failuresRemaining > 0 {
            Self.failuresRemaining -= 1
            client?.urlProtocol(self, didFailWithError: URLError(.cannotConnectToHost))
            return
        }
        let (status, data) = Self.responsesByPath[request.url!.path] ?? (Self.responseStatus, Self.responseData)
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

@main
struct ModelTests {
    @MainActor
    static func main() async throws {
        try testMutationPlans()
        try testCredentialImportAndReload()
        try testRemoteProfileStorage()
        try testRemoteConnectionVerification()
        try testPinnedInstanceIdentity()
        try testAgentAndSecurityModels()
        try testTransportURLs()
        try testAutomaticTerminalTarget()
        try await testClientIngestsAndCoalescesSecurityEvents()
        try await testClientRetriesInitialConnection()
        try await testRequestErrorsRecoverIndependently()
        print("model-tests: PASS")
    }

    private static func testAutomaticTerminalTarget() throws {
        let adminURL = "https://server.example.ts.net:9443"
        let automatic = try agentAttachCommand(
            name: "probe", remote: true, terminalTarget: nil, adminURL: adminURL, hostUser: "operator"
        )
        let explicit = try agentAttachCommand(name: "probe", remote: true, terminalTarget: "operator@server.example.ts.net")
        precondition(automatic == explicit)
        precondition(!automatic.contains("9443"))
        let override = try agentAttachCommand(
            name: "probe", remote: true, terminalTarget: "custom-alias", adminURL: adminURL, hostUser: "operator"
        )
        precondition(override.hasPrefix("ssh -t -- 'custom-alias' "))
        let local = try agentAttachCommand(
            name: "probe", remote: false, terminalTarget: "ignored", adminURL: adminURL, hostUser: "operator"
        )
        precondition(local == "safeyolo agent attach -- 'probe'")
        do {
            _ = try agentAttachCommand(
                name: "probe", remote: true, terminalTarget: nil,
                adminURL: "http://localhost:19090", hostUser: "operator", transport: .sshTunnel
            )
            preconditionFailure("A forwarded API URL is not the SSH server")
        } catch ConnectionError.missingTerminalTarget {}
        let tunnel = try agentAttachCommand(
            name: "probe", remote: true, terminalTarget: "tunnel-alias",
            adminURL: "http://localhost:19090", hostUser: "operator", transport: .sshTunnel
        )
        precondition(tunnel.hasPrefix("ssh -t -- 'tunnel-alias' "))

        // Exercise both shell boundaries without making any SSH connection.
        func shellArguments(_ command: String, function: String) throws -> [String] {
            let process = Process()
            let output = Pipe()
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = ["-c", function + "() { printf '%s\\0' \"$@\"; }; " + command]
            process.standardOutput = output
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            precondition(process.terminationStatus == 0)
            return String(decoding: data, as: UTF8.self).split(separator: "\0").map(String.init)
        }
        let name = "probe'; echo SHOULD_NOT_EXECUTE; #"
        let target = "user'$(echo SHOULD_NOT_EXECUTE)@host"
        let command = try agentAttachCommand(name: name, remote: true, terminalTarget: target)
        let sshArgs = try shellArguments(command, function: "ssh")
        precondition(sshArgs.count == 4 && sshArgs[0] == "-t" && sshArgs[1] == "--" && sshArgs[2] == target)
        let attachArgs = try shellArguments(sshArgs[3], function: "safeyolo")
        precondition(attachArgs == ["agent", "attach", "--", name])
    }

    @MainActor
    private static func testRequestErrorsRecoverIndependently() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        StubURLProtocol.responsesByPath = [
            "/admin/instance": (200, Data(#"{"schema_version":1,"safeyolo_instance_id":"sy-remote-test","host_user":"operator"}"#.utf8)),
            "/admin/approvals": (200, Data(#"{"approvals":[]}"#.utf8)),
            "/admin/agents": (503, Data(#"{"error":"agent inventory unavailable"}"#.utf8)),
        ]
        defer { StubURLProtocol.responsesByPath = [:] }
        let client = try SafeYoloClient(
            adminURL: "https://dev.example.ts.net:9443", eventsURL: "wss://dev.example.ts.net:9444/admin/events",
            token: "fixture-token", expectedInstanceID: "sy-remote-test",
            session: URLSession(configuration: configuration)
        )
        defer { client.stop() }
        let failedRefresh = await client.refreshAgents()
        precondition(!failedRefresh && client.connectionState == .connecting,
                     "A manual inventory failure must not claim the event connection is reconnecting")
        var agentErrors: [String?] = []
        let subscription = client.$requestErrors.sink { agentErrors.append($0["Agent status"]) }
        defer { subscription.cancel() }
        client.start()
        let deadline = Date().addingTimeInterval(4)
        while agentErrors.compactMap({ $0 }).count < 3, Date() < deadline {
            try await Task.sleep(for: .milliseconds(20))
        }
        guard let firstFailure = agentErrors.firstIndex(where: { $0 != nil }) else {
            preconditionFailure("Expected agent inventory failure")
        }
        precondition(agentErrors.compactMap { $0 }.count >= 3)
        precondition(agentErrors[firstFailure...].allSatisfy { $0 != nil }, "Successful identity/approval retries cleared the agent error")
        precondition(client.hostUser == "operator")
        precondition(client.errorDetails?.contains("agent inventory unavailable") == true)
        client.stop()
        StubURLProtocol.responsesByPath["/admin/agents"] = (200, Data(#"{"agents":[]}"#.utf8))
        let recovered = await client.refreshAgents()
        precondition(recovered && client.errorDetails == nil)
    }

    private static func testTransportURLs() throws {
        let secure = try validatedRemoteURL("https://host.example.ts.net:9443", scheme: "https", transport: .tailnet)
        precondition(secure.host == "host.example.ts.net")
        let forwarded = try validatedRemoteURL("http://127.0.0.1:19090", scheme: "https", transport: .sshTunnel)
        precondition(forwarded.port == 19090)
        let events = try validatedRemoteURL("ws://localhost:19091/admin/events", scheme: "wss", transport: .sshTunnel)
        precondition(events.path == "/admin/events")
        do {
            _ = try validatedRemoteURL("http://public.example:9090", scheme: "https", transport: .sshTunnel)
            preconditionFailure("A tunnel option must not send an Admin credential over public plaintext HTTP")
        } catch ConnectionError.invalidRemoteURL {}
        let input = RemoteConnectionInput(friendlyName: "remote", adminURL: "", eventsURL: "", token: "")
        precondition(input.transport == .tailnet)
    }

    @MainActor
    private static func testClientIngestsAndCoalescesSecurityEvents() async throws {
        let client = try SafeYoloClient(
            adminURL: "https://dev.example.ts.net:9443",
            eventsURL: "wss://dev.example.ts.net:9444/admin/events",
            token: "fixture-token",
            expectedInstanceID: "sy-remote-test"
        )
        var notifications = 0
        client.onNewSecurityEvent = { _ in notifications += 1 }
        let first = Data("""
        {
          "event_id":"evt-security-1",
          "ts":"2026-09-06T23:00:00Z",
          "event":"security.pattern_detected",
          "kind":"security",
          "severity":"high",
          "summary":"Sensitive pattern blocked",
          "agent":"forge",
          "host":"api.example.com",
          "decision":"deny",
          "details":{"reason":"matched rule"}
        }
        """.utf8)
        let repeatEvent = Data(String(decoding: first, as: UTF8.self)
            .replacingOccurrences(of: "evt-security-1", with: "evt-security-2")
            .utf8)

        try await client.ingestOperatorEventData(first)
        try await client.ingestOperatorEventData(repeatEvent)

        precondition(client.securityEvents.count == 1)
        precondition(client.securityEvents[0].count == 2)
        precondition(notifications == 1)
        client.clearSecurityEvents()
        precondition(client.securityEvents.isEmpty)
    }

    private static func testAgentAndSecurityModels() throws {
        let inventory = try JSONDecoder().decode(
            AgentInventory.self,
            from: Data("""
            {"agents":[{"agent_id":"ag-probe","name":"probe","sandbox_state":"ready","agent_state":"exited","attachable":false}]}
            """.utf8)
        )
        precondition(
            inventory.agents == [
                AgentInfo(agentID: "ag-probe", name: "probe", sandboxState: "ready", agentState: "exited", launcher: nil, attachable: false, error: nil)
            ]
        )
        precondition(inventory.agents[0].sandboxReady)
        precondition(inventory.agents[0].canStart)
        precondition(!inventory.agents[0].attachable)
        let local = try agentAttachCommand(name: "probe", remote: false, terminalTarget: nil)
        precondition(local == "safeyolo agent attach -- 'probe'")
        let remote = try agentAttachCommand(name: "probe", remote: true, terminalTarget: "operator@host")
        precondition(remote.hasPrefix("ssh -t -- 'operator@host' "))
        precondition(!remote.contains("agent run"))
        do {
            _ = try agentAttachCommand(name: "probe", remote: true, terminalTarget: nil)
            preconditionFailure("Remote terminal needs a discovered or explicitly configured target")
        } catch ConnectionError.missingTerminalTarget {}

        let decoded = try JSONDecoder().decode(
            OperatorEventEnvelope.self,
            from: Data("""
            {
              "event_id":"evt-security",
              "ts":"2026-09-06T23:00:00Z",
              "event":"security.pattern_detected",
              "kind":"security",
              "severity":"high",
              "summary":"Sensitive pattern blocked",
              "agent":"forge",
              "host":"api.example.com",
              "decision":"deny",
              "details":{"reason":"matched rule","count":2}
            }
            """.utf8)
        )
        precondition(decoded.isSecurityObservation)
        var observation = SecurityObservation(decoded)
        observation.observe(decoded)
        precondition(observation.count == 2)
        precondition(observation.details["reason"]?.description == "matched rule")

        let approval = try JSONDecoder().decode(
            OperatorEventEnvelope.self,
            from: Data("""
            {
              "event_id":"evt-approval",
              "event":"security.credential_guard",
              "kind":"security",
              "severity":"high",
              "summary":"Approval needed",
              "approval":{"required":true},
              "details":{}
            }
            """.utf8)
        )
        precondition(approval.needsApproval)
        precondition(!approval.isSecurityObservation)
    }

    private static func testMutationPlans() throws {
        let credential = try JSONDecoder().decode(
            ApprovalEvent.self,
            from: Data("""
            {
              "event_id":"evt-one",
              "event":"security.credential_guard",
              "summary":"Credential needs approval",
              "agent":"forge",
              "host":"api.example.com",
              "approval":{
                "required":true,
                "approval_type":"credential",
                "key":"hmac:one",
                "target":"api.example.com"
              },
              "details":{}
            }
            """.utf8)
        )
        let allow = try MutationPlan.forApproval(credential, allow: true)
        precondition(
            allow == MutationPlan(
                path: "/admin/policy/baseline/approve",
                body: ["destination": "api.example.com", "cred_id": "hmac:one"],
                expectsDesktop: false
            )
        )
        let deny = try MutationPlan.forApproval(credential, allow: false)
        precondition(
            deny == MutationPlan(
                path: "/admin/policy/baseline/deny",
                body: [
                    "destination": "api.example.com",
                    "cred_id": "hmac:one",
                    "reason": "user_denied",
                ],
                expectsDesktop: false
            )
        )

        let desktop = try JSONDecoder().decode(
            ApprovalEvent.self,
            from: Data("""
            {
              "event_id":"evt-desktop",
              "request_id":"req-desktop",
              "event":"agent.desktop_present_requested",
              "summary":"Lens requests desktop presentation",
              "agent":"lens",
              "approval":{
                "required":true,
                "approval_type":"desktop_present",
                "key":"desktop.present",
                "target":"desktop:ag-lens",
                "scope_hint":{"agent_id":"ag-lens"}
              },
              "details":{}
            }
            """.utf8)
        )
        let desktopAllow = try MutationPlan.forApproval(desktop, allow: true)
        precondition(
            desktopAllow == MutationPlan(
                path: "/admin/agents/ag-lens/desktop/present",
                body: ["approval_request_id": "req-desktop"],
                expectsDesktop: true
            )
        )
        let desktopDeny = try MutationPlan.forApproval(desktop, allow: false)
        precondition(
            desktopDeny == MutationPlan(
                path: "/admin/policy/baseline/deny",
                body: [
                    "destination": "desktop:ag-lens",
                    "cred_id": "desktop.present",
                    "reason": "user_denied",
                    "approval_request_id": "req-desktop",
                ],
                expectsDesktop: false
            )
        )
    }

    private static func testCredentialImportAndReload() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("safeyolo-command-centre-model-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent("data/coord"),
            withIntermediateDirectories: true
        )
        try Data("sy-model-test\n".utf8).write(
            to: root.appendingPathComponent("data/coord/instance_id")
        )
        try Data("fixture-token\n".utf8).write(
            to: root.appendingPathComponent("data/admin_token")
        )

        let store = MemoryCredentialStore()
        let loader = LocalCredentialLoader(configDirectory: root, keychain: store)
        let imported = try loader.load()
        precondition(imported.source == .file)
        precondition(store.values["sy-model-test"] == imported.token)

        try FileManager.default.removeItem(at: root.appendingPathComponent("data/admin_token"))
        let reloaded = try loader.load()
        precondition(reloaded.source == .keychain)
        precondition(reloaded.token == imported.token)
    }

    private static func testRemoteProfileStorage() throws {
        let suiteName = "io.safeyolo.command-centre.tests.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            preconditionFailure("could not create isolated UserDefaults suite")
        }
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let store = UserDefaultsConnectionProfileStore(defaults: defaults)
        let profile = RemoteConnectionProfile(
            friendlyName: "Development server",
            adminURL: "https://dev.example.ts.net:9443",
            eventsURL: "wss://dev.example.ts.net:9444/admin/events",
            instanceID: "sy-remote-test"
        )

        let initiallyMissing = try store.load()
        precondition(initiallyMissing == nil)
        try store.save(profile)
        let loaded = try store.load()
        precondition(loaded == profile)
        let persisted = defaults.data(forKey: "remoteConnectionProfile")!
        precondition(!String(decoding: persisted, as: UTF8.self).contains("token"))
        try store.delete()
        let deleted = try store.load()
        precondition(deleted == nil)
    }

    private static func testRemoteConnectionVerification() throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let verifier = RemoteConnectionVerifier(
            session: URLSession(configuration: configuration)
        )
        StubURLProtocol.responseStatus = 200
        StubURLProtocol.failuresRemaining = 0
        StubURLProtocol.requestCount = 0
        StubURLProtocol.responseData = Data(
            """
            {"schema_version":1,"safeyolo_instance_id":"sy-remote-test"}
            """.utf8
        )
        var result: Result<RemoteConnectionProfile, Error>?
        verifier.verify(
            RemoteConnectionInput(
                friendlyName: "Development server",
                adminURL: "https://dev.example.ts.net:9443/",
                eventsURL: "wss://dev.example.ts.net:9444/admin/events",
                token: "fixture-token"
            )
        ) { result = $0 }
        let deadline = Date().addingTimeInterval(2)
        while result == nil && RunLoop.current.run(mode: .default, before: deadline) {}
        guard case .success(let profile) = result else {
            preconditionFailure("remote verification did not succeed: \(String(describing: result))")
        }
        precondition(profile.instanceID == "sy-remote-test")
        precondition(profile.adminURL == "https://dev.example.ts.net:9443")
        precondition(StubURLProtocol.observedAuthorization == "Bearer fixture-token")
    }

    @MainActor
    private static func testClientRetriesInitialConnection() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        StubURLProtocol.responseStatus = 200
        StubURLProtocol.responseData = Data(
            """
            {"schema_version":1,"safeyolo_instance_id":"sy-remote-test"}
            """.utf8
        )
        StubURLProtocol.failuresRemaining = 1
        StubURLProtocol.requestCount = 0
        let client = try SafeYoloClient(
            adminURL: "https://dev.example.ts.net:9443",
            eventsURL: "wss://dev.example.ts.net:9444/admin/events",
            token: "fixture-token",
            expectedInstanceID: "sy-remote-test",
            session: URLSession(configuration: configuration)
        )

        client.start()
        let deadline = Date().addingTimeInterval(3)
        while StubURLProtocol.requestCount < 2, Date() < deadline {
            try await Task.sleep(for: .milliseconds(20))
        }
        client.stop()

        precondition(StubURLProtocol.requestCount >= 2)
    }

    private static func testPinnedInstanceIdentity() throws {
        let accepted = try validatePinnedInstanceID(
            actual: "sy-remote-test",
            expected: "sy-remote-test"
        )
        precondition(accepted == "sy-remote-test")
        do {
            _ = try validatePinnedInstanceID(
                actual: "sy-replacement",
                expected: "sy-remote-test"
            )
            preconditionFailure("mismatched instance ID was accepted")
        } catch let error as ClientError {
            precondition(
                error.localizedDescription.contains("expected sy-remote-test")
            )
        }
    }
}
