import Foundation
@preconcurrency import UserNotifications

@MainActor
final class SecurityNotificationPresenter {
    func show(_ event: SecurityObservation) {
        let title = "SafeYolo \(event.severity.capitalized) security event"
        let body = event.summary
        let identifier = "safeyolo-security-\(event.id)"
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else { return }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = .default
            let request = UNNotificationRequest(
                identifier: identifier,
                content: content,
                trigger: nil
            )
            UNUserNotificationCenter.current().add(request)
        }
    }
}
