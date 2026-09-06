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

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        Self.observedAuthorization = request.value(forHTTPHeaderField: "Authorization")
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: Self.responseStatus,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Self.responseData)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

@main
struct ModelTests {
    static func main() throws {
        try testMutationPlans()
        try testCredentialImportAndReload()
        try testRemoteProfileStorage()
        try testRemoteConnectionVerification()
        try testPinnedInstanceIdentity()
        print("model-tests: PASS")
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
                body: [:],
                expectsDesktop: true
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
