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

@MainActor
final class ApprovalWindowPresenter {
    private var windows: [String: NSWindow] = [:]

    func show(_ event: ApprovalEvent, client: SafeYoloClient) {
        if let existing = windows[event.id] {
            NSApp.activate(ignoringOtherApps: true)
            existing.makeKeyAndOrderFront(nil)
            return
        }

        let view = ApprovalView(
            event: event,
            client: client,
            close: { [weak self] in self?.close(event.id) }
        )
        let controller = NSHostingController(rootView: view)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 460, height: 230),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "SafeYolo Approval"
        window.contentViewController = controller
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        windows[event.id] = window
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        DispatchQueue.main.async {
            window.center()
            window.orderFrontRegardless()
            NSApp.activate(ignoringOtherApps: true)
            window.makeKey()
        }
    }

    func close(_ id: String) {
        windows.removeValue(forKey: id)?.close()
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
    private var windows: [String: NSWindow] = [:]

    func show(_ event: SecurityObservation) {
        if let existing = windows[event.id] {
            NSApp.activate(ignoringOtherApps: true)
            existing.makeKeyAndOrderFront(nil)
            return
        }
        let view = SecurityEventView(event: event, close: { [weak self] in
            self?.close(event.id)
        })
        let controller = NSHostingController(rootView: view)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 500, height: 360),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "SafeYolo Security Event"
        window.contentViewController = controller
        window.isReleasedWhenClosed = false
        windows[event.id] = window
        NSApp.activate(ignoringOtherApps: true)
        window.center()
        window.makeKeyAndOrderFront(nil)
    }

    private func close(_ id: String) {
        windows.removeValue(forKey: id)?.close()
    }
}

@MainActor
final class ErrorWindowPresenter {
    private var window: NSWindow?

    func show(_ details: String, dismissFeedGap: (() -> Void)? = nil) {
        let window = self.window ?? NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 580, height: 340),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered, defer: false
        )
        window.title = "SafeYolo Error Details"
        window.isReleasedWhenClosed = false
        window.contentViewController = NSHostingController(rootView: ErrorDetailsView(
            details: details, dismissFeedGap: dismissFeedGap,
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
        let profile = controller.savedRemoteProfile
        _friendlyName = State(initialValue: profile?.friendlyName ?? "Remote SafeYolo")
        _adminURL = State(initialValue: profile?.adminURL ?? "https://")
        _eventsURL = State(initialValue: profile?.eventsURL ?? "wss://")
        _terminalTarget = State(initialValue: profile?.terminalTarget ?? "")
        _transport = State(initialValue: profile?.transport ?? .tailnet)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Connect to a remote SafeYolo")
                .font(.title2.weight(.semibold))
            Text(transport == .tailnet
                 ? "Use the two Tailnet URLs shown by `safeyolo command-centre status` on the remote host."
                 : "Start your SSH port forwards, then enter their local Admin and Events URLs. The forwarded instance is still remote.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

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

            Spacer(minLength: 0)
            HStack {
                Button("Use Local SafeYolo") { useLocal() }
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
                transport: transport
            )
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

    private func useLocal() {
        do {
            try controller.useLocal()
            close()
        } catch {
            self.error = error.localizedDescription
        }
    }
}

struct ApprovalView: View {
    let event: ApprovalEvent
    let client: SafeYoloClient
    let close: () -> Void

    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "exclamationmark.shield.fill")
                    .font(.system(size: 26))
                    .foregroundStyle(.pink)
                Text(event.summary)
                    .font(.headline)
                    .textSelection(.enabled)
            }

            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 5) {
                row("Agent", event.agent ?? "Unknown agent")
                row("Action", event.approval.approvalType.replacingOccurrences(of: "_", with: " "))
                row("Target", event.target)
                if let method = event.details?.method { row("Method", method) }
                if let path = event.details?.path { row("Path", path) }
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

            Spacer(minLength: 2)
            HStack {
                Button("Deny") { decide(allow: false) }
                    .disabled(busy)
                    .accessibilityLabel("Deny")
                    .accessibilityIdentifier("deny-button")
                Spacer()
                Button("Cancel") { close() }
                    .disabled(busy)
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("cancel-button")
                Button("Allow") { decide(allow: true) }
                    .buttonStyle(.borderedProminent)
                    .disabled(busy)
                    .keyboardShortcut(.defaultAction)
                    .accessibilityLabel("Allow")
                    .accessibilityIdentifier("allow-button")
            }
        }
        .padding(20)
        .frame(minWidth: 460, maxWidth: 460, minHeight: 205)
    }

    @ViewBuilder
    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func decide(allow: Bool) {
        busy = true
        error = nil
        client.resolve(event, allow: allow) { result in
            switch result {
            case .success(.desktop(let presentation)):
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(presentation.unlockCode, forType: .string)
                if let url = URL(string: presentation.url) {
                    NSWorkspace.shared.open(url)
                }
                close()
            case .success(.decided):
                close()
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

    @State private var actionError: String?

    var body: some View {
        Text(controller.connectionName)
        if let client = controller.client {
            Text(client.connectionState.rawValue)
            if !client.instanceID.isEmpty {
                Text(client.instanceID).font(.caption)
            }
            if client.webmitmURL != nil {
                Button("Open WebMITM") { openWebMITM(client) }
                if client.webMITMKeyCopied {
                    Text("Key copied—paste to sign in")
                }
            }
            Divider()
            if client.approvals.isEmpty {
                Text("No pending approvals")
            } else {
                Text("Approvals (\(client.approvals.count))")
                ForEach(client.approvals) { approval in
                    Button(approval.title) {
                        presenter.show(approval, client: client)
                    }
                }
            }
            Divider()
            if client.agents.isEmpty {
                Text("No configured agents")
            } else {
                Text("Agents")
                Button("Refresh Agent Status") {
                    Task { _ = await client.refreshAgents() }
                }
                ForEach(client.agents) { agent in
                    Menu {
                        Text("Agent: \(agent.agentState)")
                        Text("Sandbox: \(agent.sandboxState)")
                        if client.pendingTerminalIDs.contains(agent.agentID) {
                            Text("Waiting for agent terminal…")
                        }
                        if let launcher = agent.launcher {
                            Text("Launcher: \(launcher.script ?? launcher.kind) (\(launcher.source))")
                        }
                        let failures = ([agent.error].compactMap { $0 }.filter { !$0.isEmpty }
                            + (agent.hookErrors ?? []).map { "\($0.hook) failed (\($0.exitCode)): \($0.detail)" })
                            .joined(separator: "\n\n")
                        Button("Error details…") { errorPresenter.show(failures) }
                            .disabled(failures.isEmpty)
                        if let code = agent.exitCode { Text("Last command exit: \(code)") }
                        if agent.sandboxReady {
                            Button("Present Desktop") { present(agent, client: client) }
                            Button("Open Sandbox Shell") { openTerminal(agent, shell: true) }
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
                            Button("Open Agent Terminal") { openTerminal(agent) }
                        } else if agent.managed && !agent.canStart {
                            Text("Headless agent: use Coord output or agent diag")
                        }
                        if agent.sandboxReady || !agent.canStart {
                            Button("Stop Agent and Sandbox") { setRunning(agent, running: false, client: client) }
                        }
                    } label: {
                        Label(agent.name, systemImage: agent.statusSymbol)
                    }
                    .accessibilityLabel("\(agent.name), agent \(agent.agentState)")
                    .disabled(client.busyAgentIDs.contains(agent.agentID))
                }
            }
            if !client.securityEvents.isEmpty {
                Divider()
                Text("Security events observed this session (\(client.securityEvents.count))")
                ForEach(client.securityEvents) { event in
                    Button(securityMenuTitle(event)) {
                        securityPresenter.show(event)
                    }
                }
                Button("Clear Security Events") { client.clearSecurityEvents() }
            }
        } else {
            Text("Not connected")
        }
        Divider()
        Button("Error details…") {
            let client = controller.client
            errorPresenter.show(errorDetails, dismissFeedGap: client?.eventFeedGap == nil ? nil : {
                client?.clearEventFeedGap()
            })
        }
        .foregroundStyle(errorDetails.isEmpty ? Color.secondary : Color.red)
        .disabled(errorDetails.isEmpty)
        Button("Connection Settings…") {
            settingsPresenter.show(controller: controller)
        }
        Button("Quit Command Centre") {
            controller.stop()
            NSApplication.shared.terminate(nil)
        }
    }

    private var errorDetails: String {
        [controller.startupError, controller.client?.errorDetails, controller.notificationError, actionError, controller.client?.eventFeedGap]
            .compactMap { $0 }.joined(separator: "\n\n")
    }

    private func openWebMITM(_ client: SafeYoloClient) {
        do {
            try client.openWebMITM(copyKey: { key in
                NSPasteboard.general.clearContents()
                return NSPasteboard.general.setString(key, forType: .string)
            }, openBrowser: { NSWorkspace.shared.open($0) })
            actionError = nil
            controller.showWebMITMSignInNotice()
        } catch {
            actionError = error.localizedDescription
            errorPresenter.show("Open WebMITM:\n\(error.localizedDescription)")
        }
    }

    private func setRunning(_ agent: AgentInfo, running: Bool, interactive: Bool = false, client: SafeYoloClient) {
        client.setRunning(agent, running: running, interactive: interactive) { result in
            if case .failure(let error) = result {
                errorPresenter.show("\(running ? "Run" : "Stop") \(agent.name):\n\(error.localizedDescription)")
            }
        }
    }

    private func openTerminal(_ agent: AgentInfo, shell: Bool = false) {
        do {
            if shell { try controller.openSandboxShell(agent) }
            else { try controller.openAgentTerminal(agent) }
            actionError = nil
        } catch {
            actionError = error.localizedDescription
            errorPresenter.show("Open \(shell ? "sandbox shell" : "agent terminal") for \(agent.name):\n\(error.localizedDescription)")
        }
    }

    private func runAndOpen(_ agent: AgentInfo, client: SafeYoloClient) {
        client.runAndWaitForTerminal(agent) { result in
            switch result {
            case .success(let ready): openTerminal(ready)
            case .failure(let error):
                if error is CancellationError { return }
                actionError = error.localizedDescription
                errorPresenter.show("Run and open terminal for \(agent.name):\n\(error.localizedDescription)")
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
                errorPresenter.show("Present desktop for \(agent.name):\n\(error.localizedDescription)")
            }
        }
    }
}
