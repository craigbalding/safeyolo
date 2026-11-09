import AppKit
import SwiftUI

private func securityMenuTitle(_ event: SecurityObservation) -> String {
    // Native menus size themselves to the label. Bound only this preview;
    // retain the complete summary in the event and its details window.
    let suffix = event.count > 1 ? " (×\(event.count))" : ""
    let font = NSFont.menuFont(ofSize: 0)
    func width(_ text: String) -> CGFloat {
        (text as NSString).size(withAttributes: [.font: font]).width
    }
    let full = event.summary + suffix
    guard width(full) > 320 else { return full }
    var preview = ""
    for character in event.summary {
        let next = preview + String(character)
        if width(next + "…" + suffix) > 320 { break }
        preview = next
    }
    return preview + "…" + suffix
}

private struct InstanceEventID: Hashable {
    let instanceID: String
    let eventID: String
}

@MainActor
final class ApprovalWindowPresenter {
    private var windows: [InstanceEventID: NSWindow] = [:]

    func show(_ event: ApprovalEvent, client: SafeYoloClient, instanceName: String? = nil) {
        let key = InstanceEventID(instanceID: client.expectedInstanceID, eventID: event.id)
        if let existing = windows[key] {
            NSApp.activate(ignoringOtherApps: true)
            existing.makeKeyAndOrderFront(nil)
            return
        }

        let view = ApprovalView(
            event: event,
            client: client,
            close: { [weak self] in self?.close(event.id, instanceID: key.instanceID) }
        )
        let controller = NSHostingController(rootView: view)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 420),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "SafeYolo Approval — \(instanceName ?? client.expectedInstanceID)"
        window.identifier = NSUserInterfaceItemIdentifier(event.id)
        window.contentViewController = controller
        window.setContentSize(NSSize(width: 520, height: 420))
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        windows[key] = window
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        DispatchQueue.main.async {
            window.center()
            window.orderFrontRegardless()
            NSApp.activate(ignoringOtherApps: true)
            window.makeKey()
        }
    }

    func close(_ id: String, instanceID: String) {
        windows.removeValue(forKey: InstanceEventID(instanceID: instanceID, eventID: id))?.close()
    }

    func close(instanceID: String) {
        for key in windows.keys.filter({ $0.instanceID == instanceID }) {
            windows.removeValue(forKey: key)?.close()
        }
    }
}

@MainActor
final class ConnectionSettingsWindowPresenter {
    private var window: NSWindow?

    func show(controller: CommandCentreController) {
        if let window {
            NSApp.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            return
        }
        let view = ConnectionSettingsView(
            controller: controller,
            close: { [weak self] in self?.close() }
        )
        let hostingController = NSHostingController(rootView: view)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 330),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "SafeYolo Connection"
        window.contentViewController = hostingController
        window.setContentSize(hostingController.view.fittingSize)
        window.isReleasedWhenClosed = false
        window.level = .floating
        self.window = window
        NSApp.activate(ignoringOtherApps: true)
        window.center()
        window.makeKeyAndOrderFront(nil)
    }

    private func close() {
        window?.close()
        window = nil
    }
}

@MainActor
final class SecurityEventWindowPresenter {
    private var windows: [InstanceEventID: NSWindow] = [:]

    func show(_ event: SecurityObservation, instanceName: String, instanceID: String) {
        let key = InstanceEventID(instanceID: instanceID, eventID: event.id)
        if let existing = windows[key] {
            NSApp.activate(ignoringOtherApps: true)
            existing.makeKeyAndOrderFront(nil)
            return
        }
        let view = SecurityEventView(event: event, close: { [weak self] in
            self?.close(key)
        })
        let controller = NSHostingController(rootView: view)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 500, height: 360),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "SafeYolo Security Event — \(instanceName)"
        window.contentViewController = controller
        window.isReleasedWhenClosed = false
        windows[key] = window
        NSApp.activate(ignoringOtherApps: true)
        window.center()
        window.makeKeyAndOrderFront(nil)
    }

    private func close(_ id: InstanceEventID) {
        windows.removeValue(forKey: id)?.close()
    }
}

@MainActor
final class ErrorWindowPresenter {
    private var window: NSWindow?

    func show(_ details: String, dismissFeedGap: (() -> Void)? = nil, diagnostics: (() -> String)? = nil) {
        let window = self.window ?? NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 580, height: 340),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered, defer: false
        )
        window.title = "SafeYolo Error Details"
        window.isReleasedWhenClosed = false
        window.contentViewController = NSHostingController(rootView: ErrorDetailsView(
            details: details, dismissFeedGap: dismissFeedGap, diagnostics: diagnostics,
            close: { [weak window] in window?.close() }
        ))
        if self.window == nil { window.center() }
        self.window = window
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }
}

struct ErrorDetailsView: View {
    let details: String
    let dismissFeedGap: (() -> Void)?
    let diagnostics: (() -> String)?
    let close: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Error details").font(.headline)
            ScrollView {
                Text(details)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack {
                Button("Copy Details") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(details, forType: .string)
                }
                if let diagnostics {
                    Button("Copy Diagnostics") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(diagnostics(), forType: .string)
                    }
                }
                if let dismissFeedGap {
                    Button("Dismiss Feed Gap") { dismissFeedGap(); close() }
                }
                Spacer()
                Button("Close") { close() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(minWidth: 460, minHeight: 240)
    }
}

struct SecurityEventView: View {
    let event: SecurityObservation
    let close: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "exclamationmark.shield.fill")
                    .font(.system(size: 26))
                    .foregroundStyle(.red)
                VStack(alignment: .leading, spacing: 2) {
                    Text(event.summary).font(.headline)
                    Text("\(event.severity.capitalized) · observed this app session")
                        .foregroundStyle(.secondary)
                }
            }
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 5) {
                detailRow("Event", event.event)
                if let agent = event.agent { detailRow("Agent", agent) }
                if let host = event.host { detailRow("Host", host) }
                if let decision = event.decision { detailRow("Decision", decision) }
                if event.count > 1 { detailRow("Occurrences", String(event.count)) }
                if let first = event.firstSeen { detailRow("First seen", first) }
                if let last = event.lastSeen, last != event.firstSeen { detailRow("Last seen", last) }
            }
            if !event.details.isEmpty {
                Divider()
                ScrollView {
                    VStack(alignment: .leading, spacing: 5) {
                        ForEach(event.details.keys.sorted(), id: \.self) { key in
                            detailRow(key, event.details[key]?.description ?? "")
                        }
                    }
                }
            }
            Spacer(minLength: 0)
            HStack {
                Spacer()
                Button("Close") { close() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(minWidth: 500, minHeight: 320)
    }

    @ViewBuilder
    private func detailRow(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
    }
}

struct ConnectionSettingsView: View {
    @ObservedObject var controller: CommandCentreController
    let close: () -> Void

    @State private var selectedConnectionID = ""
    @State private var handoffInstanceID: String?
    @State private var handoffOwnerRoot: String?
    @State private var friendlyName: String
    @State private var adminURL: String
    @State private var eventsURL: String
    @State private var terminalTarget: String
    @State private var transport: RemoteTransport
    @State private var token = ""
    @State private var busy = false
    @State private var error: String?

    init(controller: CommandCentreController, close: @escaping () -> Void) {
        self.controller = controller
        self.close = close
        _friendlyName = State(initialValue: "")
        _adminURL = State(initialValue: "https://")
        _eventsURL = State(initialValue: "wss://")
        _terminalTarget = State(initialValue: "")
        _transport = State(initialValue: .tailnet)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Saved SafeYolo instances")
                .font(.title2.weight(.semibold))
            Picker("Instance", selection: Binding(get: { selectedConnectionID }, set: { value in
                selectedConnectionID = value
                selectProfile()
            })) {
                Text("Add an instance…").tag("")
                ForEach(controller.connections.filter { $0 !== controller.localConnection }) { connection in
                    Text("\(connection.connectionName) (\(connection.remoteProfile?.instanceID ?? "unsaved"))").tag(connection.id)
                }
            }
            .disabled(busy)
            Text(connectionInstructions)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let profile = selectedConnection?.remoteProfile {
                Text("Pinned owner: \(profile.instanceID). Reconnecting must verify this identity. A recreated instance needs a new profile.")
                    .font(.caption).textSelection(.enabled)
            }
            if let handoffInstanceID {
                Text("Imported owner: \(handoffInstanceID) at \(handoffOwnerRoot ?? "Root unavailable")")
                    .font(.caption).textSelection(.enabled)
            }
            if let failure = controller.profileError { Text(failure).foregroundStyle(.red) }

            ForEach(controller.connections) { connection in
                if let status = connection.credentialStatus {
                    Text("\(connection.connectionName): \(status)")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let instanceID = connection.credentialFileInstanceID {
                    Button("Use Credential File for \(instanceID)") {
                        error = nil
                        connection.useCredentialFile()
                    }
                }
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("On the owning host, configure command-centre FILE exports a private connection handoff with full operator Admin access. Transfer it through your existing authenticated administrative channel. Import fills this form for review; Connect verifies its pinned owner. No listener, sharing or support authority is changed.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Import Connection File…") { importConnectionFile() }.disabled(busy)
                    Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 10) {
                        settingsRow("Transport") {
                            Picker("Transport", selection: $transport) {
                                ForEach(RemoteTransport.allCases, id: \.self) { transport in
                                    Text(transport.label).tag(transport)
                                }
                            }.labelsHidden()
                        }
                        settingsRow("Name") {
                            TextField("Remote SafeYolo", text: $friendlyName)
                        }
                        settingsRow("Admin URL") {
                            TextField("https://host.example.ts.net:9443", text: $adminURL)
                        }
                        settingsRow("Events URL") {
                            TextField("wss://host.example.ts.net:9444/admin/events", text: $eventsURL)
                        }
                        settingsRow("Admin credential") {
                            SecureField("Stored in Keychain", text: $token)
                        }
                        settingsRow("SSH target (optional)") {
                            TextField("Override: user@host or SSH alias", text: $terminalTarget)
                        }
                    }
                    .textFieldStyle(.roundedBorder)
                    Text("Tailscale terminals use the connected host and its SafeYolo username automatically. Set an SSH target for a different login or an SSH tunnel. Run Agent uses the Admin API and survives disconnects.")
                        .font(.caption).foregroundStyle(.secondary)

                    if let error {
                        Text(error)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    ForEach(controller.connections) { connection in
                        if let failure = connection.startupError {
                            Text("\(connection.connectionName): \(failure)")
                                .foregroundStyle(.red)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
            }
            if let selected = selectedConnection {
                Button("Remove Selected Profile") {
                    do {
                        try controller.remove(selected)
                        selectedConnectionID = ""
                        selectProfile()
                    } catch { self.error = error.localizedDescription }
                }.disabled(busy)
            }
            HStack {
                Button("Connect Local SafeYolo") { controller.useLocal(); close() }
                    .disabled(busy)
                Spacer()
                Button("Cancel") { close() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(busy)
                Button("Connect") { connect() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy)
            }
        }
        .padding(20)
        .frame(minWidth: 520, maxWidth: 520, minHeight: 310)
    }

    @ViewBuilder
    private func settingsRow<Content: View>(
        _ label: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            content()
        }
    }

    private var selectedConnection: CommandCentreConnection? {
        controller.connections.first { $0.id == selectedConnectionID }
    }

    private var connectionInstructions: String {
        switch transport {
        case .tailnet:
            return "Use the two Tailnet URLs shown by safeyolo configure command-centre on the owner, or import its private connection file."
        case .sshTunnel:
            return "Start your existing SSH port forwards, then enter their loopback Admin and Events URLs. The forwarded instance remains remote."
        case .loopback:
            return "Enter this Mac's selected instance Admin and Events loopback URLs. Separate roots keep separate identities and credentials."
        }
    }

    private func selectProfile() {
        let profile = selectedConnection?.remoteProfile
        friendlyName = profile?.friendlyName ?? ""
        adminURL = profile?.adminURL ?? "https://"
        eventsURL = profile?.eventsURL ?? "wss://"
        terminalTarget = profile?.terminalTarget ?? ""
        transport = profile?.transport ?? .tailnet
        token = ""
        handoffInstanceID = nil
        handoffOwnerRoot = nil
        error = nil
    }

    private func importConnectionFile() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let file = try JSONDecoder().decode(CommandCentreConnectionFile.self, from: Data(contentsOf: url))
            guard file.schema == "safeyolo.command-centre-connection/v1", !file.instanceID.isEmpty else {
                throw ClientError.invalidResponse
            }
            selectedConnectionID = ""
            friendlyName = file.friendlyName
            adminURL = file.adminURL
            eventsURL = file.eventsURL
            terminalTarget = ""
            transport = file.transport
            token = file.token
            handoffInstanceID = file.instanceID
            handoffOwnerRoot = file.ownerRoot
            error = nil
        } catch { self.error = "Connection file unavailable: \(error.localizedDescription)" }
    }

    private func connect() {
        busy = true
        error = nil
        controller.configureRemote(
            RemoteConnectionInput(
                friendlyName: friendlyName.trimmingCharacters(in: .whitespacesAndNewlines),
                adminURL: adminURL.trimmingCharacters(in: .whitespacesAndNewlines),
                eventsURL: eventsURL.trimmingCharacters(in: .whitespacesAndNewlines),
                token: token,
                terminalTarget: terminalTarget.trimmingCharacters(in: .whitespacesAndNewlines),
                transport: transport,
                expectedInstanceID: handoffInstanceID
            ), replacing: selectedConnection
        ) { result in
            busy = false
            switch result {
            case .success:
                token = ""
                close()
            case .failure(let failure):
                error = failure.localizedDescription
            }
        }
    }

}

struct ApprovalView: View {
    let event: ApprovalEvent
    @ObservedObject var client: SafeYoloClient
    let close: () -> Void

    @State private var busy = false
    @State private var error: String?
    @State private var selectedOption: String?

    var currentEvent: ApprovalEvent {
        client.approvals.first { $0.id == event.id } ?? event
    }

    var approvalOutcome: ApprovalResolution? {
        guard let id = event.outcomeID else { return nil }
        return client.approvalOutcomes[id]
    }

    var displayedEffect: String {
        if let outcome = approvalOutcome, outcome.terminal { return outcome.effect }
        if let option = currentEvent.options?.first(where: { $0.id == selectedOption && $0.available }) {
            return option.effect
        }
        return approvalOutcome?.effect ?? currentEvent.summary
    }
    var quotedUntrustedReason: String? { approvalOutcome?.quotedUntrustedReason ?? currentEvent.quotedUntrustedReason }

    private var evidenceUnavailable: Bool {
        event.outcomeID.map { client.unavailableApprovalOutcomes.contains($0) } ?? false
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            ScrollView {
                approvalDetails
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            if let options = currentEvent.options, options.count > 1 {
                Picker("Approval option", selection: $selectedOption) {
                    Text("Choose an option").tag(nil as String?)
                    ForEach(options) { option in
                        Text(verbatim: option.id + (option.available ? "" : " (\(option.status ?? "unavailable"))"))
                            .tag(Optional(option.id))
                            .disabled(!option.available)
                    }
                }
            }
            Divider()
            HStack {
                Button("Deny") { decide(allow: false) }
                    .disabled(busy || approvalOutcome?.terminal == true)
                    .accessibilityLabel("Deny")
                    .accessibilityIdentifier("deny-button")
                Spacer()
                Button("Cancel") { close() }
                    .disabled(busy)
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("cancel-button")
                Button("Allow") { decide(allow: true) }
                    .buttonStyle(.borderedProminent)
                    .disabled(busy || approvalOutcome?.terminal == true)
                    .keyboardShortcut(.defaultAction)
                    .accessibilityLabel("Allow")
                    .accessibilityIdentifier("allow-button")
            }
        }
        .onAppear {
            if selectedOption == nil, currentEvent.options?.contains(where: { $0.id == "once" && $0.available }) == true {
                selectedOption = "once"
            }
        }
        .padding(20)
        .frame(minWidth: 460, minHeight: 320)
    }

    private var approvalDetails: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "exclamationmark.shield.fill")
                    .font(.system(size: 26))
                    .foregroundStyle(.pink)
                Text(verbatim: approvalDisplayText(displayedEffect))
                    .font(.headline)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 5) {
                row("Agent", currentEvent.agent ?? "Unknown agent")
                row("Action", currentEvent.approval.approvalType.replacingOccurrences(of: "_", with: " "))
                row("Target", currentEvent.target)
                if let id = currentEvent.approvalID { row("Approval", id) }
                if let id = currentEvent.requestID { row("Request", id) }
                if let method = currentEvent.details?.method { row("Method", method) }
                if let path = currentEvent.details?.path { row("Path (request data)", quotedRequesterText(path)) }
                if let presentation = currentEvent.details?.presentation { row("Presentation", presentation) }
                if let ttl = currentEvent.details?.ttlSeconds { row("Preview lifetime", "\(ttl) seconds") }
                if let url = currentEvent.details?.browserURL { row("Guest browser URL (agent-selected data)", quotedRequesterText(url)) }
            }

            if let history = approvalOutcome?.requestHistory ?? currentEvent.requestHistory {
                Text(verbatim: history.display).textSelection(.enabled)
            }
            if let delivery = (approvalOutcome?.attention ?? currentEvent.attention)?["operator"] {
                Text(verbatim: "Operator attention: \(delivery.status)").foregroundStyle(.secondary)
            }

            if let options = currentEvent.options, options.count > 1 {
                ForEach(options) { option in
                    Text(verbatim: approvalDisplayText("\(option.id): \(option.effect)"))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if let reason = quotedUntrustedReason {
                Text("Agent-provided reason (untrusted)").foregroundStyle(.secondary)
                Text(verbatim: reason)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if evidenceUnavailable {
                Text("Approval evidence unavailable. Direct policy controls remain available.")
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let outcome = approvalOutcome, outcome.terminal {
                Text(verbatim: approvalDisplayText(outcome.display))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let error {
                Text(error)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            } else if busy {
                HStack(spacing: 7) {
                    ProgressView()
                        .controlSize(.small)
                    Text("Sending decision…")
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    @ViewBuilder
    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(verbatim: approvalDisplayText(value))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func decide(allow: Bool) {
        busy = true
        error = nil
        client.resolve(currentEvent, allow: allow, option: allow ? selectedOption : nil) { result in
            switch result {
            case .success(.desktop(let presentation)):
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(presentation.unlockCode, forType: .string)
                if let url = URL(string: presentation.url) {
                    NSWorkspace.shared.open(url)
                }
                close()
            case .success(.decided):
                if let outcome = approvalOutcome, let status = outcome.result?.status, status != "started", status != "denied" {
                    busy = false
                    error = outcome.display
                } else {
                    close()
                }
            case .failure(let failure):
                busy = false
                error = failure.localizedDescription
            }
        }
    }
}

struct CommandCentreMenu: View {
    @ObservedObject var controller: CommandCentreController
    let presenter: ApprovalWindowPresenter
    let settingsPresenter: ConnectionSettingsWindowPresenter
    let securityPresenter: SecurityEventWindowPresenter
    let errorPresenter: ErrorWindowPresenter

    var body: some View {
        ForEach(controller.connections) { connection in
            Menu("\(connection.connectionName) — \(connection.client?.connectionSummary ?? "Not connected")") {
                InstanceMenu(connection: connection, presenter: presenter,
                             securityPresenter: securityPresenter, errorPresenter: errorPresenter)
            }
        }
        if let failure = controller.profileError { Text(failure) }
        Divider()
        Button("Connection Settings…") { settingsPresenter.show(controller: controller) }
        Button("Quit Command Centre") {
            controller.stop()
            NSApplication.shared.terminate(nil)
        }
    }
}

struct InstanceMenu: View {
    @ObservedObject var connection: CommandCentreConnection
    let presenter: ApprovalWindowPresenter
    let securityPresenter: SecurityEventWindowPresenter
    let errorPresenter: ErrorWindowPresenter

    @State private var actionError: String?
    @State private var supportWindow: NSWindow?

    var body: some View {
        Text(connection.connectionName)
        if let client = connection.client {
            Text(client.connectionSummary)
            if client.connectionGuidance != nil {
                Button(client.eventEndpoint?.enabled == false ? "Set Up Live Events…" : "Connection Help…") {
                    errorPresenter.show(client.connectionGuidance ?? "", diagnostics: { client.diagnosticReport })
                }
            }
            if !client.instanceID.isEmpty {
                Text(client.instanceID).font(.caption)
            }
            if let root = client.hostRoot { Text("Owning root: \(root)").font(.caption) }
            if client.webmitmURL != nil {
                Button("Open WebMITM") { openWebMITM(client) }
                if client.webMITMKeyCopied {
                    Text("Key copied—paste to sign in")
                }
            }
            Button("Reconnect to This Owner") { client.start() }
            Button("Support, Notices and Receipts…") { showSupport(client) }
            Divider()
            if client.requestErrors["Pending approvals"] != nil || !client.adminConnected || !client.hasApprovalSnapshot {
                Text("Pending approvals unavailable; retained entries may be stale")
            }
            if client.approvals.isEmpty {
                Text(client.hasApprovalSnapshot && client.requestErrors["Pending approvals"] == nil && client.adminConnected ? "No pending approvals in last read" : "No current approval snapshot")
            } else {
                Text("Approvals (\(client.approvals.count))")
                ForEach(client.approvals) { approval in
                    Button(approval.title) {
                        presenter.show(approval, client: client, instanceName: instanceLabel)
                    }
                }
            }
            ForEach(client.approvalOutcomes.keys.sorted(), id: \.self) { id in
                if let outcome = client.approvalOutcomes[id] {
                    if client.unavailableApprovalOutcomes.contains(id) {
                        Text("Approval outcome unavailable: \(id)")
                    } else if outcome.terminal {
                        Text(outcome.display).textSelection(.enabled)
                    }
                }
            }
            ForEach(client.unavailableApprovalOutcomes.subtracting(client.approvalOutcomes.keys).sorted(), id: \.self) { id in
                Text("Approval evidence unavailable: \(id). Direct policy controls remain available.")
            }
            Divider()
            if client.requestErrors["Agent status"] != nil || !client.adminConnected || !client.hasAgentSnapshot {
                Text("Agent inventory unavailable; retained entries may be stale")
            }
            if client.agents.isEmpty {
                Text(client.hasAgentSnapshot && client.requestErrors["Agent status"] == nil && client.adminConnected ? "No configured agents in last read" : "No current agent inventory")
            } else {
                Text("Agents")
                Button("Refresh Agent Status") {
                    Task { _ = await client.refreshAgents() }
                }
                ForEach(client.agents) { agent in
                    Menu {
                        Text("Agent: \(agent.agentState)")
                        Text("Sandbox: \(agent.sandboxState)")
                        Text("Control: \(agent.controlState ?? "unknown")")
                        Text("Terminal: \(agent.terminalState ?? "unknown")")
                        Text("Configured harness: \(agent.harnessLabel)")
                        if client.pendingTerminalIDs.contains(agent.agentID) {
                            Text("Waiting for agent terminal…")
                        }
                        if let launcher = agent.launcher {
                            Text("Launcher: \(launcher.script ?? launcher.kind) (\(launcher.source))")
                        }
                        let failures = ([agent.error, agent.runtimeError, agent.nextAction].compactMap { $0 }.filter { !$0.isEmpty }
                            + (agent.hookErrors ?? []).map { "\($0.hook) failed (\($0.exitCode)): \($0.detail)" })
                            .joined(separator: "\n\n")
                        Button("Error details…") { errorPresenter.show(failures) }
                            .disabled(failures.isEmpty)
                        if let code = agent.exitCode { Text("Last command exit: \(code)") }
                        if agent.sandboxReady {
                            Button("Present Desktop") { present(agent, client: client) }
                            Button("Open Sandbox Shell") { openTerminal(agent, client: client, shell: true) }
                        }
                        if agent.canStart {
                            Button("Run Agent") { setRunning(agent, running: true, client: client) }
                            if agent.launcher?.kind != "supervisor" {
                                Button("Run Agent and Open Terminal") { runAndOpen(agent, client: client) }
                            }
                            if agent.managed {
                                Button("Run Interactively") { setRunning(agent, running: true, interactive: true, client: client) }
                            }
                        }
                        if agent.attachable {
                            Button("Open Agent Terminal") { openTerminal(agent, client: client) }
                        } else if agent.managed && !agent.canStart {
                            Text("Headless agent: use Coord output or agent diagnostics")
                        }
                        if agent.sandboxReady || !agent.canStart {
                            Button("Stop Agent and Sandbox") { setRunning(agent, running: false, client: client) }
                        }
                    } label: {
                        Label {
                            Text("\(agent.name)  \(agent.harnessMark)")
                        } icon: {
                            Image(systemName: agent.statusSymbol)
                        }
                    }
                    .accessibilityLabel("\(agent.name), \(agent.harnessLabel), agent \(agent.agentState)")
                    .disabled(!client.adminConnected || client.busyAgentIDs.contains(agent.agentID))
                }
            }
            if !client.securityEvents.isEmpty {
                Divider()
                Text("Security events observed this session (\(client.securityEvents.count))")
                ForEach(client.securityEvents) { event in
                    Button(securityMenuTitle(event)) {
                        securityPresenter.show(event, instanceName: instanceLabel, instanceID: client.expectedInstanceID)
                    }
                }
                Button("Clear Security Events") { client.clearSecurityEvents() }
            }
        } else {
            Text("Not connected")
        }
        if let status = connection.credentialStatus { Text(status) }
        Divider()
        Button("Error details…") {
            let client = connection.client
            errorPresenter.show(errorDetails, dismissFeedGap: client?.eventFeedGap == nil ? nil : {
                client?.clearEventFeedGap()
            }, diagnostics: client.map { client in { client.diagnosticReport } })
        }
        .foregroundStyle(errorDetails.isEmpty ? Color.secondary : Color.red)
        .disabled(errorDetails.isEmpty)
        if let client = connection.client {
            Button("Copy Diagnostics") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(client.diagnosticReport, forType: .string)
            }
        }
    }

    private func showSupport(_ client: SafeYoloClient) {
        if let supportWindow {
            supportWindow.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 760, height: 640),
                              styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Support — \(instanceLabel)"
        window.contentViewController = NSHostingController(rootView: SupportView(client: client, instanceName: instanceLabel))
        window.isReleasedWhenClosed = false
        supportWindow = window
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private var instanceLabel: String {
        "\(connection.connectionName) (\(connection.client?.expectedInstanceID ?? connection.credentialFileInstanceID ?? connection.id))"
    }

    private var errorDetails: String {
        [connection.client?.connectionGuidance, connection.startupError, connection.client?.errorDetails,
         connection.notificationError, actionError, connection.client?.eventFeedGap]
            .compactMap { $0 }.joined(separator: "\n\n")
    }

    private func openWebMITM(_ client: SafeYoloClient) {
        do {
            try client.openWebMITM(copyKey: { key in
                NSPasteboard.general.clearContents()
                return NSPasteboard.general.setString(key, forType: .string)
            }, openBrowser: { NSWorkspace.shared.open($0) })
            actionError = nil
            connection.showWebMITMSignInNotice()
        } catch {
            actionError = error.localizedDescription
            errorPresenter.show("\(instanceLabel) — Open WebMITM:\n\(error.localizedDescription)")
        }
    }

    private func setRunning(_ agent: AgentInfo, running: Bool, interactive: Bool = false, client: SafeYoloClient) {
        client.setRunning(agent, running: running, interactive: interactive) { result in
            if case .failure(let error) = result {
                errorPresenter.show("\(instanceLabel) — \(running ? "Run" : "Stop") \(agent.name):\n\(error.localizedDescription)")
            }
        }
    }

    private func openTerminal(_ agent: AgentInfo, client: SafeYoloClient, shell: Bool = false) {
        do {
            if shell { try connection.openSandboxShell(agent, client: client) }
            else { try connection.openAgentTerminal(agent, client: client) }
            actionError = nil
        } catch {
            actionError = error.localizedDescription
            errorPresenter.show("\(instanceLabel) — Open \(shell ? "sandbox shell" : "agent terminal") for \(agent.name):\n\(error.localizedDescription)")
        }
    }

    private func runAndOpen(_ agent: AgentInfo, client: SafeYoloClient) {
        client.runAndWaitForTerminal(agent) { result in
            switch result {
            case .success(let ready): openTerminal(ready, client: client)
            case .failure(let error):
                if error is CancellationError { return }
                actionError = error.localizedDescription
                errorPresenter.show("\(instanceLabel) — Run and open terminal for \(agent.name):\n\(error.localizedDescription)")
            }
        }
    }

    private func present(_ agent: AgentInfo, client: SafeYoloClient) {
        client.presentDesktop(for: agent) { result in
            switch result {
            case .success(let presentation):
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(presentation.unlockCode, forType: .string)
                if let url = URL(string: presentation.url) {
                    NSWorkspace.shared.open(url)
                }
            case .failure(let error):
                errorPresenter.show("\(instanceLabel) — Present desktop for \(agent.name):\n\(error.localizedDescription)")
            }
        }
    }
}

struct SupportView: View {
    @ObservedObject var client: SafeYoloClient
    let instanceName: String
    @State private var selectedReceipt: SupportReceipt?
    @State private var evidence: String?
    @State private var reading = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(instanceName).font(.title2)
            if let root = client.hostRoot { Text("Owning root: \(root)").textSelection(.enabled) }
            Text(client.connectionSummary)
            if let gap = client.eventFeedGap { Text(gap).foregroundStyle(.orange) }
            Text("Owner observations and recorded actions do not establish model health. Reads below never repeat a support operation.")
                .foregroundStyle(.secondary)
            HStack {
                Button("Refresh Owner Evidence") { Task { await client.refreshSupport() } }
                Spacer()
                if reading { ProgressView().controlSize(.small) }
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    GroupBox("Pending human work") {
                        VStack(alignment: .leading) {
                            snapshotStatus("Pending human signals")
                            Text("\(client.pendingSignals.count) shown of \(client.pendingSignalTotal) material signals requesting an operator. Approval decisions remain in this instance's menu.")
                            ForEach(client.pendingSignals) { signal in
                                Button("Read \(signal.kind) — \(signal.signalID), revision \(signal.revision)") {
                                    readEvidence { supportEvidence(try await client.readOperatorSignal(signal)) }
                                }
                            }
                            if let next = client.pendingSignalNext {
                                Button("Read More Pending Signals") { Task { await client.refreshPendingSignals(after: next) } }
                            }
                            Text("Signal content is an agent-authored claim. Reading it grants no permission and resolves no work.")
                                .font(.caption).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                    GroupBox("Support activity and original receipts") {
                        VStack(alignment: .leading) {
                            snapshotStatus("Support receipts")
                            Text("Retained receipt entries: \(client.supportReceipts.count) of \(client.supportReceiptTotal) from the last read. Guest output is excluded.")
                            ForEach(client.supportReceipts) { receipt in
                                Button("\(receipt.title) — \(receipt.operationID)") { selectedReceipt = receipt }
                                    .accessibilityIdentifier("receipt-\(receipt.id)")
                            }
                            if client.supportReceiptOmitted > 0 {
                                Text("\(client.supportReceiptOmitted) older receipts omitted. On this owner, support receipts --lines NUMBER lists a larger selection.")
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                    GroupBox("Current support grants") {
                        VStack(alignment: .leading) {
                            snapshotStatus("Support grants")
                            if client.supportGrants.isEmpty, client.supportReadTimes["Support grants"] != nil,
                               client.requestErrors["Support grants"] == nil, client.adminConnected {
                                Text("This owner returned no support grants. Other authority can remain.")
                            }
                            ForEach(Array(client.supportGrants.enumerated()), id: \.offset) { _, grant in
                                if let name = grant.fields?["name"]?.text {
                                    DisclosureGroup(name) {
                                        Text(supportEvidence(grant)).textSelection(.enabled)
                                        Button("Read Authority Composition for \(name)") {
                                            readEvidence { supportEvidence(try await client.readSupportAuthority(grant: name)) }
                                        }
                                    }
                                }
                            }
                            Text("Composition uses the owner's existing report and selected coverage. Unknown reach is not no reach. On the owner, configure support NAME edits a grant; configure revoke-support NAME reviews removal and remaining paths. Approval and factory-direction selections stay separate.")
                                .font(.caption).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                    GroupBox("Observation sources and transport") {
                        VStack(alignment: .leading) {
                            snapshotStatus("Observation sources")
                            if let diagnostic = client.observationDiagnostics?.fields {
                                Text("Local Core connection: \(diagnostic["local_connection"].map(supportEvidence) ?? "Unavailable")")
                                Text("Federation connection: \(diagnostic["owner_federation_connection"].map(supportEvidence) ?? "Unavailable")")
                                DisclosureGroup("Source observations (Unix milliseconds)") {
                                    Text(diagnostic["observations"].map(supportEvidence) ?? "Unavailable").textSelection(.enabled)
                                }
                                DisclosureGroup("Notification and audit delivery") {
                                    Text(diagnostic["outbox"].map(supportEvidence) ?? "Unavailable").textSelection(.enabled)
                                }
                            }
                            Text("Times are the source's last observations. Empty, quiet or old records do not prove coverage or health. If a source is unavailable, inspect this owner's coord status and the named source. For target recovery, use this owner's agent diagnostics and the original receipt; preserve the current run before choosing a new action.")
                                .font(.caption).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                    GroupBox("Operational notices observed this session") {
                        VStack(alignment: .leading) {
                            Text("\(client.operationalEvents.count) latest observations retained in this session. A feed gap can hide transitions; reconnect reconciles current owner state and receipts without replaying history.")
                            ForEach(Array(client.operationalEvents.enumerated()), id: \.offset) { _, event in
                                DisclosureGroup("\(event.timestamp ?? "Time unavailable") — \(event.agent ?? "Target") — \(operationalMeaning(event))") {
                                    Text(event.details.map { supportEvidence(.object($0)) } ?? "Evidence unavailable").textSelection(.enabled)
                                }
                            }
                            Text("A recovery notice verifies only its recorded runtime/control observation. It does not establish a guest repair or model progress.")
                                .font(.caption).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                    if let evidence { GroupBox("Owner evidence") { Text(evidence).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) } }
                }.padding(.trailing, 8)
            }
        }
        .padding(20).frame(minWidth: 650, minHeight: 500)
        .onAppear { client.beginSupportObservation() }
        .onDisappear { client.endSupportObservation() }
        .sheet(item: $selectedReceipt) { receipt in
            SupportReceiptView(client: client, receipt: receipt, close: { selectedReceipt = nil })
        }
    }

    @ViewBuilder
    private func snapshotStatus(_ name: String) -> some View {
        if !client.adminConnected || client.requestErrors[name] != nil {
            Text("Unavailable — retained evidence may be stale. \(client.requestErrors[name] ?? "Verify this owner's identity and Admin connection, then refresh.")")
                .foregroundStyle(.red)
        }
        if let time = client.supportReadTimes[name] {
            Text("Last successful owner read: \(time.formatted()). Current state may have changed.")
                .font(.caption).foregroundStyle(.secondary)
        } else { Text("No successful owner read yet").foregroundStyle(.secondary) }
    }

    private func readEvidence(_ read: @escaping @MainActor () async throws -> String) {
        guard !reading else { return }
        reading = true
        Task {
            defer { reading = false }
            do { evidence = try await read() }
            catch { evidence = "Owner evidence unavailable: \(error.localizedDescription). Restore this owner's connection and read again. No mutation was submitted." }
        }
    }
}

private func operationalMeaning(_ event: OperatorEventEnvelope) -> String {
    let kind = event.details?["reference"]?.fields?["kind"]?.text
    switch kind {
    case "observation_health": return "Observation source unavailable or recovered"
    case "sandbox_recovered": return "Sandbox/control recovery observation; model health unverified"
    case "sandbox_availability": return "Sandbox availability changed"
    case "control_availability": return "Control availability changed"
    case "launch_failed": return "Start request failed; inspect current target"
    case "command_exit": return "Guest command exited"
    case "command_restart": return "Guest command replacement started"
    case "command_failed": return "Guest command reached terminal failure"
    case "supervisor_exit": return "Command supervisor exited; child state unknown"
    case "supervisor_restart": return "Replacement supervisor resumed its launch"
    case "needs_operator": return "Selected material signal needs an operator"
    default: return event.summary
    }
}

struct SupportReceiptView: View {
    @ObservedObject var client: SafeYoloClient
    let receipt: SupportReceipt
    let close: () -> Void
    @State private var detail: SupportReceiptDetail?
    @State private var failure: String?
    @State private var reading = false
    @State private var readAt: Date?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Original operation: \(receipt.operationID)").font(.headline)
            Text("Owner: \(receipt.instanceID) · Durable target: \(receipt.targetID)").textSelection(.enabled)
            if !client.adminConnected { Text("Owner connection unavailable. Retained detail may be stale.").foregroundStyle(.red) }
            if let failure { Text(failure).foregroundStyle(.red) }
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text((detail?.receipt ?? receipt).summary).textSelection(.enabled)
                    if let detail {
                        Text("Current target (separate observation)").font(.headline)
                        Text(detail.currentTarget.map(supportEvidence) ?? "Unavailable").textSelection(.enabled)
                        Text("Current authority (separate from original admission)").font(.headline)
                        Text(detail.currentGrant.map(supportEvidence) ?? "Unavailable").textSelection(.enabled)
                        Text("Other grants and operator permissions can remain. Inspect this owner's authority composition before narrowing or revoking.")
                        Text(detail.recovery)
                        if detail.outputIncluded {
                            Text("Private, untrusted recorded guest result").font(.headline)
                            Text(detail.recordedResult.map(supportEvidence) ?? "No result recorded").textSelection(.enabled)
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            if let readAt { Text("Read at \(readAt.formatted()). Current state may have changed.").font(.caption) }
            Text("These reads reconcile the original ID. No support effect is submitted or retried.").foregroundStyle(.secondary)
            HStack {
                Button("Read Original Receipt and Current State") { read(output: false) }
                Button("Read Guest Output") { read(output: true) }
                Spacer()
                Button("Close", action: close).keyboardShortcut(.cancelAction)
            }.disabled(reading)
        }
        .padding(20).frame(width: 740, height: 580)
        .task { read(output: false) }
    }

    private func read(output: Bool) {
        reading = true
        failure = nil
        Task {
            defer { reading = false }
            do {
                detail = try await client.readSupportReceipt(receipt, includeOutput: output)
                readAt = Date()
            } catch {
                failure = "Original receipt/current evidence unavailable: \(error.localizedDescription). Any retained detail is stale. On this owner, use support recover with this original ID and initiator."
            }
        }
    }
}
