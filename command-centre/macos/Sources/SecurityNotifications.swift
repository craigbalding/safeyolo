import Combine
import Foundation
@preconcurrency import UserNotifications

@MainActor
final class SecurityNotificationPresenter: NSObject, ObservableObject, UNUserNotificationCenterDelegate {
    @Published private(set) var error: String?
    private let center = UNUserNotificationCenter.current()

    override init() {
        super.init()
        center.delegate = self
    }

    func show(_ event: SecurityObservation) {
        let title = "SafeYolo \(event.severity.capitalized) security event"
        let body = event.summary
        let identifier = "safeyolo-security-\(event.id)"
        Task {
            do {
                let granted = try await center.requestAuthorization(options: [.alert, .sound])
                guard granted else {
                    error = "Notifications are disabled for SafeYolo Command Centre. Enable them in macOS System Settings → Notifications. Security events remain available in the menu."
                    return
                }
                let content = UNMutableNotificationContent()
                content.title = title
                content.body = body
                content.sound = .default
                let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
                try await center.add(request)
                let settings = await center.notificationSettings()
                error = settings.alertSetting == .disabled || settings.alertStyle == .none
                    ? "Notification banners are disabled for SafeYolo Command Centre. Select Banners or Alerts in macOS System Settings → Notifications. Security events remain available in the menu."
                    : nil
            } catch {
                self.error = "macOS could not accept the security notification: \(error.localizedDescription)"
            }
        }
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .list, .sound])
    }
}
