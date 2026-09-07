import AppKit
import SwiftUI

@main
struct SafeYoloCommandCentreApp: App {
    @StateObject private var controller: CommandCentreController
    private let presenter: ApprovalWindowPresenter
    private let settingsPresenter: ConnectionSettingsWindowPresenter
    private let securityPresenter: SecurityEventWindowPresenter

    init() {
        NSApplication.shared.setActivationPolicy(.accessory)
        let presenter = ApprovalWindowPresenter()
        let settingsPresenter = ConnectionSettingsWindowPresenter()
        let securityPresenter = SecurityEventWindowPresenter()
        let securityNotifier = SecurityNotificationPresenter()
        let controller = CommandCentreController(
            presenter: presenter,
            securityNotifier: securityNotifier
        )
        self.presenter = presenter
        self.settingsPresenter = settingsPresenter
        self.securityPresenter = securityPresenter
        _controller = StateObject(wrappedValue: controller)
        DispatchQueue.main.async {
            controller.start()
            if controller.client == nil {
                settingsPresenter.show(controller: controller)
            }
        }
    }

    var body: some Scene {
        MenuBarExtra {
            CommandCentreMenu(
                controller: controller,
                presenter: presenter,
                settingsPresenter: settingsPresenter,
                securityPresenter: securityPresenter
            )
            .onAppear {
                Task { _ = await controller.client?.refreshAgents() }
            }
        } label: {
            Image(
                systemName: controller.hasSecurityEvents
                    ? "exclamationmark.shield.fill"
                    : controller.hasPendingApprovals
                        ? "exclamationmark.shield.fill"
                        : controller.client == nil
                        ? "shield.slash"
                        : "shield.lefthalf.filled"
            )
            .symbolRenderingMode(.palette)
            .foregroundStyle(controller.hasSecurityEvents ? Color.red : Color.primary)
            .accessibilityLabel("SafeYolo")
        }
        .menuBarExtraStyle(.menu)
    }
}
