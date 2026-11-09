import AppKit
import Foundation
import SwiftUI

private final class SavedTestCredentials: CredentialStore, @unchecked Sendable {
    private let lock = NSLock()
    private var tokens: [String: String]
    init(_ tokens: [String: String]) { self.tokens = tokens }
    func load(account: String) throws -> String? { lock.withLock { tokens[account] } }
    func store(account: String, token: String) throws { lock.withLock { tokens[account] = token } }
    func delete(account: String) throws { _ = lock.withLock { tokens.removeValue(forKey: account) } }
}

private final class SupportEndpoints: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var failed: String?
    private var changed: String?
    private var failReceipts = false
    private var receiptReads = 0
    private var detailReads: [[String: Any]] = []
    private var writes = 0
    var failedOwner: String? { get { lock.withLock { failed } } set { lock.withLock { failed = newValue } } }
    var changedOwner: String? { get { lock.withLock { changed } } set { lock.withLock { changed = newValue } } }
    var receiptFailure: Bool { get { lock.withLock { failReceipts } } set { lock.withLock { failReceipts = newValue } } }
    var reads: Int { lock.withLock { receiptReads } }
    var details: [[String: Any]] { lock.withLock { detailReads } }
    var unexpectedWrites: Int { lock.withLock { writes } }

    func respond(_ request: URLRequest) throws -> (Int, Data) {
        lock.lock()
        defer { lock.unlock() }
        let owner = "sy-\(request.url!.port!)"
        guard request.value(forHTTPHeaderField: "Authorization") == "Bearer synthetic-\(owner)" else {
            return (403, Data())
        }
        if owner == failedOwner { throw URLError(.cannotConnectToHost) }
        let path = request.url!.path
        var value: [String: Any]
        if path == "/admin/instance" {
            value = ["schema_version": 1, "safeyolo_instance_id": owner == changedOwner ? "sy-recreated" : owner,
                     "host_root": "/owned/\(owner)", "host_executable": "/installed/bin/safeyolo",
                     "command_centre_events": ["enabled": false]]
        } else if path == "/admin/agents" { value = ["agents": []] }
        else if path == "/admin/approvals" { value = ["approvals": []] }
        else if path == "/admin/support-operations/list" {
            receiptReads += 1
            if receiptFailure { return (503, Data(#"{"error":"receipt owner unreadable"}"#.utf8)) }
            value = ["instance_id": owner, "receipts": [receipt(owner, "first"), receipt(owner, "second")], "total": 2, "omitted": 0]
        } else if path == "/admin/support-operations/read" {
            let body = try JSONSerialization.jsonObject(with: request.httpBody ?? request.httpBodyStream.map { stream in
                stream.open(); defer { stream.close() }
                var data = Data(); var bytes = [UInt8](repeating: 0, count: 1024)
                while stream.hasBytesAvailable { let count = stream.read(&bytes, maxLength: bytes.count); if count <= 0 { break }; data.append(contentsOf: bytes.prefix(count)) }
                return data
            } ?? Data()) as! [String: Any]
            detailReads.append(body)
            precondition(body["operation_id"] as? String == "original-lost-reply" && body["current"] as? Bool == true)
            let initiator = body["initiator"] as! String
            precondition(["first", "second"].contains(initiator))
            let output = body["include_output"] as! Bool
            value = ["receipt": receipt(owner, initiator), "output_included": output,
                     "current_target": ["availability": "observed", "state": ["model_health": "unverified"]],
                     "current_grant": ["active": false, "reason": "removed"],
                     "recovery": "Original operation was not submitted again."]
            if output { value["recorded_result"] = ["stdout": "private-untrusted-\(owner)"] }
        } else if path == "/admin/support-grants" { value = ["instance_id": owner, "grants": []] }
        else if path == "/admin/coord/signals" { value = ["items": [], "total": 0, "next_after": NSNull()] }
        else if path == "/admin/coord/diagnostics" {
            value = ["observations": [["agent_id": "ag-shared", "source": "host_runtime", "last_success_at": 1794200000000,
                                       "unavailable_reason": "probe_timeout", "last_observed_at": 1794200001000]],
                     "outbox": [["destination": "audit-jsonl", "pending": 1]], "local_connection": "Connected"]
        } else {
            if request.httpMethod == "POST" { writes += 1 }
            return (404, Data())
        }
        return (200, try JSONSerialization.data(withJSONObject: value))
    }

    private func receipt(_ owner: String, _ initiator: String) -> [String: Any] {
        ["operation_id": "original-lost-reply", "instance_id": owner, "initiator_principal": initiator,
         "initiator": ["run": ["agent_id": "ag-support-\(initiator)", "run_id": "original-run"]],
         "target_id": "ag-shared", "target_name": "worker", "target_run": "original-target-run",
         "action": "guest_command", "state": "outcome_unknown", "grant": "incident", "grant_expires_at": NSNull(),
         "completion_verified": false, "audit_event_id": NSNull()]
    }
}

extension ModelTests {
    @MainActor
    static func testSavedInstancesAndSupport() async throws {
        let suite = "io.safeyolo.saved-support.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite); StubURLProtocol.requestHandler = nil }
        let store = UserDefaultsConnectionProfileStore(defaults: defaults)
        let profiles = [19090, 29090, 39090].map { port in
            RemoteConnectionProfile(friendlyName: "Same display name", adminURL: "http://127.0.0.1:\(port)",
                eventsURL: "ws://127.0.0.1:\(port + 1)/admin/events", instanceID: "sy-\(port)", transport: .loopback)
        }
        for profile in profiles { try store.save(profile) }
        let tokens = Dictionary(uniqueKeysWithValues: profiles.map { ($0.instanceID, "synthetic-\($0.instanceID)") })
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let endpoints = SupportEndpoints()
        StubURLProtocol.requestHandler = { try endpoints.respond($0) }
        let controller = CommandCentreController(presenter: ApprovalWindowPresenter(), securityNotifier: SecurityNotificationPresenter(),
            keychain: SavedTestCredentials(tokens), profileStore: store, verifier: RemoteConnectionVerifier(session: session),
            localCredentialDirectory: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString), session: session)
        defer { controller.stop() }
        controller.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        let connections = controller.connections.filter { $0 !== controller.localConnection }
        try await supportUntil { connections.count == 3 && connections.allSatisfy { $0.client?.adminConnected == true } }
        precondition(controller.localConnection.startupError != nil && controller.hasConnectedInstance)
        for connection in connections { await connection.client!.refreshSupport() }
        for (index, connection) in connections.enumerated() {
            let client = connection.client!
            precondition(client.expectedInstanceID == profiles[index].instanceID && client.supportReceipts.count == 2)
            let first = try await client.readSupportReceipt(client.supportReceipts[0])
            precondition(first.receipt.instanceID == client.expectedInstanceID && !first.outputIncluded && first.recordedResult == nil)
            precondition(first.currentGrant?.fields?["active"] == .bool(false))
            precondition(!first.receipt.summary.contains("null") && first.receipt.summary.contains("standing"))
            let second = try await client.readSupportReceipt(client.supportReceipts[1], includeOutput: true)
            precondition(second.receipt.initiator == "second" && second.recordedResult?.fields?["stdout"]?.text == "private-untrusted-\(client.expectedInstanceID)")

        }
        let first = connections[0].client!
        let second = connections[1].client!
        let retained = first.supportReceipts
        do {
            _ = try await second.readSupportReceipt(retained[0])
            preconditionFailure("A receipt cannot be read through a different owner")
        } catch ClientError.connectionUnavailable {}
        endpoints.receiptFailure = true
        await first.refreshSupportReceipts()
        precondition(first.supportReceipts == retained && first.requestErrors["Support receipts"] != nil)
        endpoints.receiptFailure = false
        endpoints.failedOwner = first.expectedInstanceID
        await first.refreshSupport()
        precondition(!first.adminConnected && first.supportReceipts == retained)
        await second.refreshSupport()
        precondition(second.adminConnected && second.supportReceipts.count == 2)
        endpoints.failedOwner = nil
        await first.refreshSupport()
        precondition(first.adminConnected && first.requestErrors["Support receipts"] == nil)

        second.beginSupportObservation()
        let beforeInitial = endpoints.reads
        try await supportUntil { endpoints.reads > beforeInitial }
        try await Task.sleep(for: .milliseconds(100))
        let beforeBurst = endpoints.reads
        for index in 0..<40 {
            let event: [String: Any] = ["event_id": "evt-burst-\(index)", "event": "agent.operational", "kind": "agent",
                "severity": "low", "summary": "Selected operational transition", "agent": "worker",
                "details": ["reference": ["instance_id": second.expectedInstanceID, "kind": "observation_health",
                    "target": ["agent_id": "ag-shared", "name": "worker"], "source": "host_runtime"]]]
            try await second.ingestOperatorEventData(JSONSerialization.data(withJSONObject: event))
        }
        precondition(endpoints.reads == beforeBurst)
        try await supportUntil { endpoints.reads == beforeBurst + 1 }
        try await Task.sleep(for: .milliseconds(1100))
        precondition(endpoints.reads == beforeBurst + 1 && second.operationalEvents.count == 40,
                     "A burst coalesces into one owner refresh; an idle view performs no periodic reads")
        try await second.ingestOperatorEventData(Data(#"{"type":"operator_state","history_gap":"rotation"}"#.utf8))
        try await supportUntil { endpoints.reads == beforeBurst + 2 }
        precondition(second.eventFeedGap?.contains("rotation") == true && second.supportReceipts.count == 2)
        second.endSupportObservation()

        let support = NSHostingController(rootView: SupportView(client: second, instanceName: "Selected owner"))
        support.view.layoutSubtreeIfNeeded()
        precondition(support.view.fittingSize.width > 0)
        let detail = NSHostingController(rootView: SupportReceiptView(client: second, receipt: second.supportReceipts[0], close: {}))
        detail.view.layoutSubtreeIfNeeded()
        precondition(detail.view.fittingSize.width >= 700)

        endpoints.changedOwner = first.expectedInstanceID
        await first.refreshSupport()
        precondition(!first.adminConnected && first.supportReceipts == retained)
        // A failed edit cannot discard the pin and adopt a recreated same-name owner on the next attempt.
        for _ in 0..<2 {
            var result: Result<RemoteConnectionProfile, Error>?
            controller.configureRemote(RemoteConnectionInput(friendlyName: "Same display name", adminURL: profiles[0].adminURL,
                eventsURL: profiles[0].eventsURL, token: tokens[profiles[0].instanceID]!, transport: .loopback),
                replacing: connections[0]) { result = $0 }
            try await supportUntil { result != nil }
            guard case .failure = result! else { preconditionFailure("A profile edit cannot replace its durable owner binding") }
            precondition(connections[0].remoteProfile == profiles[0])
        }
        let preserved = try store.load()
        precondition(preserved == profiles && connections[1].client === second && second.adminConnected)
        try controller.remove(connections[0])
        precondition(controller.connections.filter { $0 !== controller.localConnection }.count == 2)
        controller.stop()
        controller.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        try await supportUntil { controller.connections.filter { $0.client?.adminConnected == true }.count == 2 }
        precondition(!controller.connections.contains { $0.remoteProfile?.instanceID == profiles[0].instanceID })
        defaults.set(Data("unreadable profile selection".utf8), forKey: "connectionProfiles")
        controller.start(commandLine: CommandLineConfiguration(adminURL: nil, eventsURL: nil))
        precondition(controller.profileError != nil, "Unavailable saved profiles cannot look like a healthy empty selection")
        precondition(endpoints.unexpectedWrites == 0 && endpoints.details.count >= 6)
        print("saved-support-tests: PASS three saved owner/root pins, restart/removal, credential routing, same-name replacement refusal, original ID+initiator detail, explicit output, removed authority, stale/unavailable retention, observation gaps, coalesced refresh and idle network")

    }

    @MainActor
    private static func supportUntil(_ condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(6)
        while !condition() && Date() < deadline { try await Task.sleep(for: .milliseconds(10)) }
        precondition(condition(), "Saved support consumer did not reach its expected state")
    }
}
