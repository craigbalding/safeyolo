import AppKit
import Foundation
import SwiftUI

extension ModelTests {
    @MainActor
    static func testOperatorContextEvidence() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        StubURLProtocol.requestHandler = nil
        StubURLProtocol.failuresRemaining = 0
        defer { StubURLProtocol.responsesByPath = [:] }
        let identity = Data(#"{"schema_version":1,"safeyolo_instance_id":"sy-context","host_user":"operator","host_executable":"/opt/selected/bin/safeyolo","host_root":"/opt/selected","host_config_path":"/opt/selected/custom.toml","command_centre_events":{"enabled":false,"port":null}}"#.utf8)
        StubURLProtocol.responsesByPath = [
            "/admin/instance": (200, identity),
            "/admin/agents": (200, Data(#"{"agents":[]}"#.utf8)),
            "/admin/approvals": (200, Data(#"{"approvals":[]}"#.utf8)),
        ]
        let client = try SafeYoloClient(
            adminURL: "http://127.0.0.1:19090", eventsURL: "ws://127.0.0.1:19091/admin/events",
            token: "context-test-token", expectedInstanceID: "sy-context",
            session: URLSession(configuration: configuration),
            terminalTarget: "selected-mac", transport: .sshTunnel, usesRemoteTerminal: true,
            makeEventSocket: { _ in preconditionFailure("Events disabled") },
            retryPause: { throw CancellationError() }
        )
        defer { client.stop() }
        precondition(client.agentObservation.observedAt == nil && client.approvalObservation.observedAt == nil)
        precondition(client.agentObservation.summary("Configured agents", count: 0).contains("not loaded"))
        // Authentication alone supplies no inventory observation.
        let authenticated = await client.refreshInstance()
        precondition(authenticated && client.agentObservation.observedAt == nil)
        StubURLProtocol.responsesByPath["/admin/agents"] = (503, Data(#"{"error":"unavailable"}"#.utf8))
        let firstFailure = await client.refreshAgents()
        precondition(!firstFailure && client.agentObservation.observedAt == nil)
        precondition(client.agentObservation.summary("Configured agents", count: 0).contains("No successful read"))
        StubURLProtocol.responsesByPath["/admin/agents"] = (200, Data(#"{"agents":[]}"#.utf8))
        client.start()
        let deadline = Date().addingTimeInterval(4)
        while client.connectionState != .eventsDisabled, Date() < deadline {
            try await Task.sleep(for: .milliseconds(10))
        }
        precondition(client.connectionState == .eventsDisabled)
        precondition(client.agentObservation.observedAt != nil && client.approvalObservation.observedAt != nil)
        precondition(client.agentObservation.summary("Configured agents", count: 0).contains("No configured agents"))
        let guidance = client.connectionGuidance!
        precondition(guidance.contains("ssh -t -- 'selected-mac'"))
        precondition(guidance.contains("/opt/selected/bin/safeyolo") && guidance.contains("/opt/selected/custom.toml"))
        precondition(guidance.contains("stop") && guidance.contains("start") && !guidance.contains("context-test-token"))
        let approvalRecovery = try client.recoveryCommand("approvals show apr-context --agent " + shellQuoted("context-agent"))
        precondition(approvalRecovery.contains("ssh -t -- 'selected-mac'") && approvalRecovery.contains("/opt/selected/custom.toml"))
        precondition(approvalRecovery.contains("approvals show apr-context") && approvalRecovery.contains("context-agent"))

        // Optional input is a captured canonical record from the native proxy.
        // The default record is only a focused decoding/rendering control.
        let pendingData: Data
        if let path = ProcessInfo.processInfo.environment["SAFEYOLO_APPROVAL_RENDER_INPUT"] {
            pendingData = try Data(contentsOf: URL(fileURLWithPath: path))
        } else {
            pendingData = Data(#"{"approval_id":"apr-context","request_id":"req-context","event":"gateway.route_escalated","summary":"Allow this literal route for this run","status":"pending","created_at":1794218300,"agent":"alice","approval":{"required":true,"approval_type":"gateway_route","key":"apr-context","target":"jobs"},"authority":{"expires_at":1794219900},"options":[{"id":"run","effect":"Reusable until the worker run or deadline ends; expiry does not undo persistent effects.","parameters":{"ttl_seconds":30}}],"assessment":{"model":{"persistent_effects":["executable_changed"],"consequence":"Stored executable can run later"},"unresolved_conditions":["Upstream state unverified"]},"guidance":{"alternatives":[{"id":"read_status","access":"available"}],"uncertainty":"Missing annotations do not establish safety"},"details":{"untrusted_reason_text":"The operator requested an edit"},"effect":"Allow this literal route for this run"}"#.utf8)
        }
        let pending = try JSONDecoder().decode(ApprovalEvent.self, from: pendingData)
        precondition(pending.assessment != nil && pending.guidance != nil && pending.options?.isEmpty == false)
        let duplicate = JSONValue.object(["assessment": pending.assessment!, "uncertainty": .string("Still unverified")])
        precondition(approvalGuidance(duplicate, assessment: pending.assessment)["assessment"] == nil)
        precondition(approvalGuidance(duplicate, assessment: pending.assessment)["uncertainty"] == .string("Still unverified"))
        let distinct = JSONValue.object(["assessment": .string("A different retained assessment")])
        precondition(approvalGuidance(distinct, assessment: pending.assessment) == distinct)
        let object = try JSONSerialization.jsonObject(with: pendingData)
        StubURLProtocol.responsesByPath["/admin/approvals"] = (200, try JSONSerialization.data(withJSONObject: ["approvals": [object]]))
        let id = pending.approvalID!
        StubURLProtocol.responsesByPath["/admin/approvals/\(id)"] = (200, pendingData)
        StubURLProtocol.responsesByPath["/admin/approvals/\(id)/attention"] = (200, Data(#"{"notify":false}"#.utf8))
        let loaded = await client.refreshApprovals()
        precondition(loaded && client.approvals.count == 1)
        precondition(client.approvals[0].options?.map(\.id) == pending.options?.map(\.id))
        let approvalDate = client.approvalObservation.observedAt
        let agentDate = client.agentObservation.observedAt
        StubURLProtocol.responsesByPath["/admin/approvals"] = (503, Data())
        let failed = await client.refreshApprovals()
        precondition(!failed && client.approvals.count == 1 && client.approvalObservation.observedAt == approvalDate)
        precondition(client.approvalObservation.summary("Pending approvals", count: 1).contains("stale"))
        let agentRead = await client.refreshAgents()
        precondition(agentRead && client.agentObservation.observedAt! >= agentDate!)
        precondition(client.approvalObservation.unavailable != nil, "An independent successful read must not clear failed approvals")
        try renderOperatorView(ApprovalView(event: pending, client: client, close: {}), name: "approval-stale")
        StubURLProtocol.responsesByPath["/admin/approvals"] = (200, Data(#"{"approvals":[]}"#.utf8))
        let empty = await client.refreshApprovals()
        precondition(empty && client.approvals.isEmpty && client.approvalObservation.unavailable == nil)
        precondition(client.approvalObservation.summary("Pending approvals", count: 0).contains("No pending approvals"))

        // Use the production recovery and handoff views in a native macOS window.
        try renderOperatorView(ErrorDetailsView(details: guidance, dismissFeedGap: nil, diagnostics: nil, heading: "Connection help", close: {}), name: "qualified-recovery")
        StubURLProtocol.responsesByPath["/admin/instance"] = (200, Data(#"{"schema_version":1,"safeyolo_instance_id":"sy-context","command_centre_events":{"enabled":false,"port":null}}"#.utf8))
        let missing = await client.refreshInstance()
        precondition(missing && client.connectionGuidance!.contains("recovery command unavailable"))
        precondition(!client.connectionGuidance!.contains("safeyolo stop"))

        let url = ProcessInfo.processInfo.environment["SAFEYOLO_DESKTOP_HANDOFF_URL"] ?? "http://127.0.0.1:19092/"
        let desktop = try JSONDecoder().decode(DesktopPresentation.self, from: JSONSerialization.data(withJSONObject: [
            "agent_id": "ag-context", "agent": "context-agent", "url": url, "unlock_code": "4321-8765", "reused": true,
        ]))
        var opened = false
        do {
            try desktop.open(copyCode: { _ in false }, openBrowser: { _ in opened = true; return true })
            preconditionFailure("Clipboard failure became success")
        } catch { precondition(!opened && error.localizedDescription.contains("could not be copied")) }
        do {
            try desktop.open(copyCode: { _ in true }, openBrowser: { _ in false })
            preconditionFailure("Browser failure became success")
        } catch { precondition(error.localizedDescription.contains("was copied")) }
        // A real browser handoff is opt-in because it opens a native application.
        if ProcessInfo.processInfo.environment["SAFEYOLO_DESKTOP_HANDOFF_URL"] != nil {
            let pasteboard = NSPasteboard.withUniqueName()
            defer { pasteboard.releaseGlobally() }
            try desktop.open(copyCode: { pasteboard.setString($0, forType: .string) }, openBrowser: { NSWorkspace.shared.open($0) })
            precondition(pasteboard.string(forType: .string) == desktop.unlockCode)
        }
        let presenter = ErrorWindowPresenter()
        presenter.show("sy-context — " + desktop.handoffNotice, heading: "Desktop ready")
        precondition(NSApp.windows.contains { $0.title == "SafeYolo — Desktop ready" })
        try renderOperatorView(ErrorDetailsView(details: "sy-context — " + desktop.handoffNotice, dismissFeedGap: nil, diagnostics: nil, heading: "Desktop ready", close: {}), name: "desktop-feedback")
        let lastApprovalRead = client.approvalObservation.observedAt
        let lastAgentRead = client.agentObservation.observedAt
        StubURLProtocol.responsesByPath["/admin/instance"] = (200, Data(#"{"schema_version":1,"safeyolo_instance_id":"sy-replaced"}"#.utf8))
        let wrongApprovals = await client.refreshApprovals(verifyInstance: true)
        let wrongAgents = await client.refreshAgents(verifyInstance: true)
        precondition(!wrongApprovals && !wrongAgents && client.approvalObservation.observedAt == lastApprovalRead && client.agentObservation.observedAt == lastAgentRead)
        precondition(client.approvalObservation.unavailable != nil && client.agentObservation.unavailable != nil)
        print("operator-context: per-read empty/unavailable/stale, qualified SSH/config recovery, canonical evidence, clipboard/browser failure and native feedback controls passed")
    }

    @MainActor
    private static func renderOperatorView<Content: View>(_ content: Content, name: String) throws {
        guard let directory = ProcessInfo.processInfo.environment["SAFEYOLO_APPROVAL_RENDER_DIR"] else { return }
        let view = NSHostingView(rootView: content.environment(\.colorScheme, .light).background(Color.white))
        view.frame = NSRect(x: 0, y: 0, width: 780, height: 1100)
        let window = NSWindow(contentRect: view.bounds, styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = view
        window.title = "SafeYolo operator context — " + name
        window.makeKeyAndOrderFront(nil)
        view.layoutSubtreeIfNeeded()
        let image = view.bitmapImageRepForCachingDisplay(in: view.bounds)!
        view.cacheDisplay(in: view.bounds, to: image)
        try image.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: directory).appendingPathComponent(name + ".png"))
        window.orderOut(nil)
    }
}
