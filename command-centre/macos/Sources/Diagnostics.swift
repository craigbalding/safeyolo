import Foundation

// This report contains connection metadata, never headers, payloads, or NSError userInfo.
struct ConnectionDiagnostics {
    private struct Entry {
        let first: Date
        var last: Date
        let message: String
        var count = 1
    }

    private var entries: [Entry] = []
    private(set) var lastFailure: String?
    var attempts = 0
    var retries = 0
    var socketAttempts = 0
    var lastAdminSuccess: Date?
    var lastEventSuccess: Date?
    var lastEventReceived: Date?

    mutating func record(_ message: String, at date: Date = Date()) {
        if entries.last?.message == message {
            entries[entries.count - 1].last = date
            entries[entries.count - 1].count += 1
        } else {
            entries.append(Entry(first: date, last: date, message: message))
            // Bound session memory, not retry attempts or the operator's actions.
            if entries.count > 100 { entries.removeFirst() }
        }
    }

    mutating func failure(_ operation: String, error: Error) {
        let message = "\(operation): \(Self.describe(error))"
        lastFailure = "\(Self.timestamp(Date())) \(message)"
        record(message)
    }

    static func describe(_ error: Error) -> String {
        if let error = error as? URLError {
            // Use fixed explanations: the original description/userInfo may contain URLs.
            let reason: String
            switch error.code {
            case .cannotConnectToHost: reason = "Cannot connect to the server"
            case .cannotFindHost, .dnsLookupFailed: reason = "Cannot resolve the server hostname"
            case .networkConnectionLost: reason = "Network connection lost"
            case .notConnectedToInternet: reason = "Network unavailable"
            case .timedOut: reason = "Connection timed out"
            case .badServerResponse: reason = "Server rejected the request or WebSocket handshake"
            case .userAuthenticationRequired: reason = "Authentication required or rejected"
            case .secureConnectionFailed: reason = "TLS connection failed"
            case .serverCertificateUntrusted: reason = "Server certificate is not trusted"
            case .cancelled: reason = "Cancelled"
            default: reason = URLError(error.code).localizedDescription
            }
            return "NSURLErrorDomain (\(error.code.rawValue)): \(reason)"
        }
        if let error = error as? ClientError {
            switch error {
            case .requestFailed(let status, _): return "HTTP \(status) (response body omitted)"
            case .instanceMismatch: return "SafeYolo instance identity mismatch"
            case .invalidURL: return "Invalid endpoint URL"
            case .invalidResponse: return "Invalid server response"
            case .invalidApproval: return "Invalid approval response"
            }
        }
        if error is DecodingError { return "Invalid JSON response (DecodingError; payload omitted)" }
        if error is CancellationError { return "Cancelled" }
        let systemError = error as NSError
        if [NSPOSIXErrorDomain, NSCocoaErrorDomain].contains(systemError.domain) {
            let safeError = NSError(domain: systemError.domain, code: systemError.code)
            return "\(safeError.domain) (\(safeError.code)): \(safeError.localizedDescription)"
        }
        // Unknown error descriptions and domains may be supplied by a remote peer.
        return "Connection error (code \((error as NSError).code); details omitted)"
    }

    static func endpoint(_ url: URL) -> String {
        guard var parts = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return "Invalid URL" }
        parts.user = nil
        parts.password = nil
        parts.query = nil
        parts.fragment = nil
        // Endpoints need only their origin for troubleshooting. Paths can contain secrets.
        parts.path = ""
        return parts.string ?? "Invalid URL"
    }

    static func timestamp(_ date: Date?) -> String {
        date.map { ISO8601DateFormatter().string(from: $0) } ?? "Never"
    }

    func report() -> String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "test"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "test"
        let history = entries.map {
            "\(Self.timestamp($0.first)) — \(Self.timestamp($0.last)) [\($0.count)×] \($0.message)"
        }.joined(separator: "\n")
        return """
        SafeYolo Command Centre \(version) (\(build))
        Captured UTC: \(Self.timestamp(Date()))
        OS: \(ProcessInfo.processInfo.operatingSystemVersionString)
        Connection attempts: \(attempts)
        Scheduled retries: \(retries)
        WebSocket attempts: \(socketAttempts)
        Last Admin API success: \(Self.timestamp(lastAdminSuccess))
        Last WebSocket handshake/ping success: \(Self.timestamp(lastEventSuccess))
        Last live event received: \(Self.timestamp(lastEventReceived))
        Last failure (retained after recovery): \(lastFailure ?? "None")
        Recent connection history (session only; latest 100 entries; consecutive duplicates coalesced):
        \(history)
        """
    }
}
