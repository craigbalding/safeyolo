import AppKit
import SwiftUI

@main
struct SafeYoloCommandCentreApp: App {
    @StateObject private var controller: CommandCentreController
    private let presenter: ApprovalWindowPresenter
    private let settingsPresenter: ConnectionSettingsWindowPresenter

    init() {
        NSApplication.shared.setActivationPolicy(.accessory)
        let presenter = ApprovalWindowPresenter()
        let settingsPresenter = ConnectionSettingsWindowPresenter()
        let controller = CommandCentreController(presenter: presenter)
        self.presenter = presenter
        self.settingsPresenter = settingsPresenter
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
                settingsPresenter: settingsPresenter
            )
        } label: {
            Label(
                "SafeYolo",
                systemImage: controller.hasPendingApprovals
                    ? "exclamationmark.shield.fill"
                    : controller.client == nil
                        ? "shield.slash"
                        : "shield.lefthalf.filled"
            )
        }
        .menuBarExtraStyle(.menu)
    }
}
