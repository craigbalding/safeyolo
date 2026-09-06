import AppKit
import SwiftUI

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

struct ConnectionSettingsView: View {
    @ObservedObject var controller: CommandCentreController
    let close: () -> Void

    @State private var friendlyName: String
    @State private var adminURL: String
    @State private var eventsURL: String
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
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Connect to a remote SafeYolo")
                .font(.title2.weight(.semibold))
            Text("Use the two Tailnet URLs shown by `safeyolo command-centre status` on the remote host.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 10) {
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
            }
            .textFieldStyle(.roundedBorder)

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
                token: token
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

    var body: some View {
        Text(controller.connectionName)
        if let client = controller.client {
            Text(client.connectionState.rawValue)
            if !client.instanceID.isEmpty {
                Text(client.instanceID).font(.caption)
            }
            if let error = client.lastError {
                Text(error).foregroundStyle(.red)
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
        } else {
            Text("Not connected")
            if let error = controller.startupError {
                Text(error).foregroundStyle(.red)
            }
        }
        Divider()
        Button("Connection Settings…") {
            settingsPresenter.show(controller: controller)
        }
        Button("Quit Command Centre") {
            controller.stop()
            NSApplication.shared.terminate(nil)
        }
    }
}
