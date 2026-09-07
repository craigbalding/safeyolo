import AppKit
import SwiftUI

@main
struct SafeYoloCommandCentreApp: App {
    @StateObject private var controller: CommandCentreController
    private let presenter: ApprovalWindowPresenter
    private let settingsPresenter: ConnectionSettingsWindowPresenter
    private let securityPresenter: SecurityEventWindowPresenter
    private let errorPresenter = ErrorWindowPresenter()

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
                securityPresenter: securityPresenter,
                errorPresenter: errorPresenter
            )
            .onAppear {
                Task {
                    guard let client = controller.client else { return }
                    await client.refreshInstance()
                    await client.refreshAgents()
                }
            }
        } label: {
            HStack(spacing: 1) {
                Image("MenuBarTemplate")
                    .renderingMode(.template)
                    .resizable()
                    .frame(width: 18, height: 18)
                // Preserve the old shield's attention and unconfigured states.
                Text(controller.hasSecurityEvents || controller.hasPendingApprovals
                     ? "!" : controller.client == nil ? "×" : "")
                    .font(.system(size: 11, weight: .bold))
                    .frame(width: 6)
            }
            .foregroundStyle(controller.hasSecurityEvents ? Color.red : Color.primary)
            .accessibilityLabel(controller.hasSecurityEvents ? "SafeYolo, security events"
                                : controller.hasPendingApprovals ? "SafeYolo, approvals waiting"
                                : controller.client == nil ? "SafeYolo, not configured" : "SafeYolo")
        }
        .menuBarExtraStyle(.menu)
    }
}
