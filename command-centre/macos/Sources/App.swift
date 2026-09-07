import AppKit
import SwiftUI

@main
struct SafeYoloCommandCentreApp: App {
    @StateObject private var controller: CommandCentreController
    private let presenter: ApprovalWindowPresenter
    private let settingsPresenter: ConnectionSettingsWindowPresenter
    private let securityPresenter: SecurityEventWindowPresenter
    private let errorPresenter = ErrorWindowPresenter()

    private var statusImage: NSImage {
        // MenuBarExtra extracts an image, rather than laying out arbitrary
        // SwiftUI views. Compose the mark and its indicator as one image.
        let mark = NSImage(named: "MenuBarTemplate")!
        let indicator = controller.hasSecurityEvents || controller.hasPendingApprovals
            ? "!" : controller.client == nil ? "×" : ""
        let image = NSImage(size: NSSize(width: 25, height: 18), flipped: false) { bounds in
            mark.draw(in: NSRect(x: 0, y: 0, width: 18, height: 18))
            (indicator as NSString).draw(at: NSPoint(x: 19, y: 2), withAttributes: [
                .font: NSFont.systemFont(ofSize: 11, weight: .bold), .foregroundColor: NSColor.black
            ])
            if controller.hasSecurityEvents {
                NSColor.systemRed.setFill()
                bounds.fill(using: .sourceAtop)
            }
            return true
        }
        image.isTemplate = !controller.hasSecurityEvents
        return image
    }

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
            Image(nsImage: statusImage)
            .accessibilityLabel(controller.hasSecurityEvents ? "SafeYolo, security events"
                                : controller.hasPendingApprovals ? "SafeYolo, approvals waiting"
                                : controller.client == nil ? "SafeYolo, not configured" : "SafeYolo")
        }
        .menuBarExtraStyle(.menu)
    }
}
