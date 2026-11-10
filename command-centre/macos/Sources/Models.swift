import Foundation

struct InstanceInfo: Decodable {
    struct EventEndpoint: Decodable, Equatable {
        let enabled: Bool
        let port: Int?
    }
    let schemaVersion: Int
    let safeyoloInstanceID: String
    let hostUser: String?
    let hostExecutable: String?
    let hostRoot: String?
    let hostConfigPath: String?
    let webmitmURL: String?
    let commandCentreEvents: EventEndpoint?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case safeyoloInstanceID = "safeyolo_instance_id"
        case hostUser = "host_user"
        case hostExecutable = "host_executable"
        case hostRoot = "host_root"
        case hostConfigPath = "host_config_path"
        case webmitmURL = "webmitm_url"
        case commandCentreEvents = "command_centre_events"
    }
}

func validatePinnedInstanceID(actual: String, expected: String) throws -> String {
    guard actual == expected else {
        throw ClientError.instanceMismatch(expected: expected, actual: actual)
    }
    return actual
}

struct PendingApprovals: Decodable {
    let approvals: [ApprovalEvent]
}

struct AgentInventory: Decodable {
    let agents: [AgentInfo]
}

struct AgentInfo: Decodable, Equatable, Hashable, Identifiable {
    struct Launcher: Decodable, Equatable, Hashable {
        let kind: String
        let source: String
        let script: String?
    }
    struct HookFailure: Decodable, Equatable, Hashable {
        let hook: String
        let detail: String
        let exitCode: Int

        enum CodingKeys: String, CodingKey {
            case hook, detail
            case exitCode = "exit_code"
        }
    }
    let agentID: String
    let name: String
    let sandboxState: String
    let agentState: String
    var controlState: String? = nil
    var terminalState: String? = nil
    var runtimeError: String? = nil
    var nextAction: String? = nil
    var exec: Bool? = nil
    let launcher: Launcher?
    let attachable: Bool
    let error: String?
    var hookErrors: [HookFailure]? = nil
    var exitCode: Int? = nil
    var harness: String? = nil

    enum CodingKeys: String, CodingKey {
        case agentID = "agent_id"
        case name
        case sandboxState = "sandbox_state"
        case agentState = "agent_state"
        case controlState = "control_state"
        case terminalState = "terminal_state"
        case runtimeError = "runtime_error"
        case nextAction = "next_action"
        case exec
        case launcher, attachable, error, harness
        case hookErrors = "hook_errors"
        case exitCode = "exit_code"
    }

    var id: String { agentID }
    var sandboxReady: Bool { exec == true }
    var canStart: Bool {
        ["running", "stopped"].contains(sandboxState)
            && ["stopped", "exited", "failed"].contains(agentState)
    }
    var managed: Bool { ["supervisor", "manager"].contains(launcher?.kind ?? "") }
    var harnessLabel: String {
        switch harness {
        case "codex": return "Codex"
        case "pi": return "Pi"
        case "claude": return "Claude Code"
        case "shell": return "Shell"
        default: return "Custom or unknown"
        }
    }
    var harnessMark: String {
        switch harness {
        case "codex": return ">_"
        case "pi": return "π"
        case "claude": return "✳"
        default: return "⌨"
        }
    }
    var statusSymbol: String {
        switch agentState {
        case "running": return "play.circle.fill"
        case "stopped", "exited": return "stop.circle"
        case "starting", "launching", "restarting": return "arrow.triangle.2.circlepath"
        case "stopping", "finishing": return "hourglass"
        case "failed": return "exclamationmark.triangle.fill"
        default: return "questionmark.circle"
        }
    }
}

enum JSONValue: Decodable, Hashable, CustomStringConvertible {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer()
        if value.decodeNil() {
            self = .null
        } else if let decoded = try? value.decode(Bool.self) {
            self = .bool(decoded)
        } else if let decoded = try? value.decode(Double.self) {
            self = .number(decoded)
        } else if let decoded = try? value.decode(String.self) {
            self = .string(decoded)
        } else if let decoded = try? value.decode([String: JSONValue].self) {
            self = .object(decoded)
        } else {
            self = .array(try value.decode([JSONValue].self))
        }
    }

    var description: String {
        switch self {
        case .string(let value): return value
        case .number(let value): return value.formatted()
        case .bool(let value): return value ? "true" : "false"
        case .object(let value):
            return value.keys.sorted().map { "\($0): \(value[$0]!)" }.joined(separator: ", ")
        case .array(let value): return value.map(\.description).joined(separator: ", ")
        case .null: return "null"
        }
    }
}

extension JSONValue {
    subscript(_ key: String) -> JSONValue? {
        if case .object(let fields) = self { return fields[key] }
        return nil
    }

    var evidenceDescription: String {
        func lines(_ value: JSONValue, indent: String) -> [String] {
            switch value {
            case .object(let fields):
                return fields.keys.sorted().flatMap { key -> [String] in
                    let label = approvalDisplayText(key.replacingOccurrences(of: "_", with: " "))
                    return [indent + label + ":"] + lines(fields[key]!, indent: indent + "  ")
                }
            case .array(let values):
                if values.isEmpty { return [indent + "None"] }
                return values.flatMap { [indent + "–"] + lines($0, indent: indent + "  ") }
            case .null: return [indent + "Not reported"]
            default: return [indent + approvalDisplayText(value.description)]
            }
        }
        return lines(self, indent: "").joined(separator: "\n")
    }
}

// The canonical guidance repeats the assessment and alternatives. Show each
// once when they are identical; preserve distinct guidance in full.
func approvalGuidance(_ guidance: JSONValue, assessment: JSONValue?) -> JSONValue {
    guard case .object(var fields) = guidance, let assessment else { return guidance }
    if fields["assessment"] == assessment { fields.removeValue(forKey: "assessment") }
    if fields["alternatives"] == assessment["alternatives"] { fields.removeValue(forKey: "alternatives") }
    return .object(fields)
}

struct OperatorEventEnvelope: Decodable, Hashable {
    struct ApprovalMarker: Decodable, Hashable {
        let required: Bool
    }

    let eventID: String?
    let timestamp: String?
    let event: String
    let kind: String
    let severity: String
    let summary: String
    let requestID: String?
    let agent: String?
    let host: String?
    let decision: String?
    let approval: ApprovalMarker?
    let details: [String: JSONValue]?

    enum CodingKeys: String, CodingKey {
        case eventID = "event_id"
        case timestamp = "ts"
        case event
        case kind
        case severity
        case summary
        case requestID = "request_id"
        case agent
        case host
        case decision
        case approval
        case details
    }

    var needsApproval: Bool { approval?.required == true }
    var isSecurityObservation: Bool {
        if event == "ops.circuit_breaker.open" { return true }
        return ["security", "gateway"].contains(kind)
            && ["high", "critical"].contains(severity)
            && !needsApproval
    }

    var coalescingKey: String {
        [event, agent ?? "", host ?? "", decision ?? ""].joined(separator: ":")
    }
}

struct SecurityObservation: Hashable, Identifiable {
    let id: String
    let event: String
    let kind: String
    let severity: String
    let summary: String
    let agent: String?
    let host: String?
    let decision: String?
    let firstSeen: String?
    var lastSeen: String?
    var count: Int
    let details: [String: JSONValue]

    init(_ event: OperatorEventEnvelope) {
        id = event.coalescingKey
        self.event = event.event
        kind = event.kind
        severity = event.severity
        summary = event.summary
        agent = event.agent
        host = event.host
        decision = event.decision
        firstSeen = event.timestamp
        lastSeen = event.timestamp
        count = 1
        details = event.details ?? [:]
    }

    mutating func observe(_ event: OperatorEventEnvelope) {
        count += 1
        lastSeen = event.timestamp ?? lastSeen
    }
}

// Quoting contains line, terminal and Unicode direction controls. SwiftUI must
// also render this value verbatim so requester markup stays plain data.
func quotedRequesterText(_ value: String) -> String {
    var result = "\""
    for unit in value.utf16 {
        switch unit {
        case 0x22: result += "\\\""
        case 0x5c: result += "\\\\"
        case 0x20...0x7e: result += String(UnicodeScalar(unit)!)
        default: result += String(format: "\\u%04x", unit)
        }
    }
    return result + "\""
}

func approvalDisplayText(_ value: String) -> String {
    value.unicodeScalars.map { scalar in
        switch scalar.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator:
            return String(scalar).utf16.map { String(format: "\\u%04x", $0) }.joined()
        default: return String(scalar)
        }
    }.joined()
}

struct ApprovalRequestHistory: Decodable, Hashable {
    struct Refusal: Decodable, Hashable {
        let approvalID: String
        let decidedAt: Int?
        enum CodingKeys: String, CodingKey { case approvalID = "approval_id", decidedAt = "decided_at" }
    }
    let equivalentRequestCount: Int
    let approvalCount: Int
    let firstRequestedAt: Int
    let lastRequestedAt: Int
    let lastRefusal: Refusal?
    enum CodingKeys: String, CodingKey {
        case equivalentRequestCount = "equivalent_request_count", approvalCount = "approval_count"
        case firstRequestedAt = "first_requested_at", lastRequestedAt = "last_requested_at", lastRefusal = "last_refusal"
    }
    var display: String {
        var text = "Equivalent requests: \(equivalentRequestCount) across \(approvalCount) approvals."
        text += " First: \(Date(timeIntervalSince1970: TimeInterval(firstRequestedAt)).formatted()). Last: \(Date(timeIntervalSince1970: TimeInterval(lastRequestedAt)).formatted())."
        if let refusal = lastRefusal {
            text += " Last refusal: \(refusal.approvalID)."
            if let at = refusal.decidedAt { text += " Refused: \(Date(timeIntervalSince1970: TimeInterval(at)).formatted())." }
        }
        return text
    }
}

struct ApprovalAttentionDelivery: Decodable, Hashable { let status: String }
struct ApprovalAttentionClaim: Decodable { let notify: Bool }

struct ListObservation: Equatable {
    var observedAt: Date?
    var unavailable: String?

    mutating func succeeded() { observedAt = Date(); unavailable = nil }
    mutating func failed(_ reason: String) { unavailable = reason }
    mutating func interrupted() {
        if observedAt != nil && unavailable == nil {
            unavailable = "Live updates interrupted; refresh this list."
        }
    }

    func summary(_ list: String, count: Int) -> String {
        let previous = observedAt.map { "Last observed \(count) at \($0.formatted(date: .abbreviated, time: .standard))." }
        if let unavailable {
            return "\(list) unavailable. \(previous.map { $0 + " Snapshot is stale. " } ?? "No successful read yet. ")\(unavailable)"
        }
        guard let observedAt else { return "\(list) not loaded yet." }
        return "\(count == 0 ? "No " + list.lowercased() : list + ": " + String(count)). Observed \(observedAt.formatted(date: .abbreviated, time: .standard))."
    }
}

struct ApprovalEvent: Decodable, Hashable, Identifiable {
    struct Option: Decodable, Hashable, Identifiable {
        let id: String
        let effect: String
        let status: String?
        let parameters: JSONValue?
        var available: Bool { status == nil || status == "available" }
    }
    struct Authority: Decodable, Hashable {
        let expiresAt: Double?
        enum CodingKeys: String, CodingKey { case expiresAt = "expires_at" }
    }
    struct Request: Decodable, Hashable {
        struct Scope: Decodable, Hashable {
            let agentID: String?
            let port: Int?

            enum CodingKeys: String, CodingKey {
                case agentID = "agent_id"
                case port
            }
        }

        let required: Bool
        let approvalType: String
        let key: String
        let target: String
        let scopeHint: Scope?

        enum CodingKeys: String, CodingKey {
            case required
            case approvalType = "approval_type"
            case key
            case target
            case scopeHint = "scope_hint"
        }
    }

    struct Details: Decodable, Hashable {
        struct NetworkAction: Decodable, Hashable { let kind: String }
        let service: String?
        let method: String?
        let path: String?
        let reason: String?
        let networkAction: NetworkAction?
        let untrustedReasonText: String?
        let browserURL: String?
        let presentation: String?
        let ttlSeconds: Int?

        enum CodingKeys: String, CodingKey {
            case service, method, path, reason
            case networkAction = "network_action"
            case untrustedReasonText = "untrusted_reason_text"
            case browserURL = "browser_url"
            case presentation
            case ttlSeconds = "ttl_seconds"
        }
    }

    let approvalID: String?
    let options: [Option]?
    let authority: Authority?
    let assessment: JSONValue?
    let guidance: JSONValue?
    let assessmentChanged: Bool?
    let status: String?
    let createdAt: Double?
    let eventID: String?
    let requestID: String?
    let event: String
    let summary: String
    let agent: String?
    let host: String?
    let approval: Request
    let details: Details?
    let requestHistory: ApprovalRequestHistory?
    let attention: [String: ApprovalAttentionDelivery]?

    enum CodingKeys: String, CodingKey {
        case approvalID = "approval_id"
        case options, authority, assessment, guidance, status
        case assessmentChanged = "assessment_changed"
        case createdAt = "created_at"
        case eventID = "event_id"
        case requestID = "request_id"
        case event
        case summary
        case agent
        case host
        case approval
        case details
        case requestHistory = "request_history"
        case attention
    }

    var outcomeID: String? {
        approvalID ?? (details?.networkAction?.kind == "network_allow" ? requestID : nil)
    }

    var id: String {
        if let approvalID { return approvalID }
        if details?.networkAction?.kind == "network_allow", let requestID {
            return "network:\(requestID)"
        }
        return "\(approval.key):\(approval.target)"
    }

    var quotedUntrustedReason: String? {
        details?.untrustedReasonText.map(quotedRequesterText)
    }

    var title: String {
        let title = "\(agent ?? "Unknown agent"): \(approval.approvalType.replacingOccurrences(of: "_", with: " "))"
        if details?.networkAction?.kind == "network_allow", let requestID {
            let prepared = details?.untrustedReasonText == nil ? "" : " (prepared)"
            return "\(title)\(prepared): \(requestID)"
        }
        return title
    }

    var target: String {
        approval.target.isEmpty ? (host ?? "Unknown target") : approval.target
    }
}

struct DesktopPresentation: Decodable, Equatable {
    let agentID: String
    let agent: String
    let url: String
    let unlockCode: String
    let reused: Bool

    enum CodingKeys: String, CodingKey {
        case agentID = "agent_id"
        case agent
        case url
        case unlockCode = "unlock_code"
        case reused
    }
}

struct MutationPlan: Equatable {
    let path: String
    let body: [String: String]
    var payload: [String: Any] { body.mapValues { $0 as Any } }

    static func forApproval(_ event: ApprovalEvent, allow: Bool, option: String? = nil) throws -> MutationPlan {
        if let approvalID = event.approvalID {
            guard let encodedID = encodePathComponent(approvalID) else {
                throw ClientError.invalidApproval("Approval ID is unavailable")
            }
            var body = ["decision": allow ? "approve" : "reject"]
            if allow {
                let options = event.options ?? []
                if let option {
                    guard options.contains(where: { $0.id == option && $0.available }) else {
                        throw ClientError.invalidApproval("Select an available option from this approval")
                    }
                    body["option"] = option
                } else if options.count > 1 && !options.contains(where: { $0.id == "once" && $0.available }) {
                    throw ClientError.invalidApproval("Select one of this approval's fixed options")
                }
            }
            return MutationPlan(path: "/admin/approvals/\(encodedID)", body: body)
        }
        if ["network_egress", "credential"].contains(event.approval.approvalType) {
            throw ClientError.invalidApproval("Historical approval is read-only. Make a new request or use explicit policy controls.")
        }
        throw ClientError.invalidApproval("A canonical approval ID is required. Make a new request or use explicit operator controls.")
    }
}

struct ApprovalResolution: Decodable, Equatable {
    struct ActionResult: Decodable, Equatable {
        struct Diagnostic: Decodable, Equatable { let message: String }
        let status: String?
        let diagnostic: Diagnostic?
        let evidence: JSONValue

        enum CodingKeys: String, CodingKey { case status, diagnostic }
        init(from decoder: Decoder) throws {
            let fields = try decoder.container(keyedBy: CodingKeys.self)
            status = try fields.decodeIfPresent(String.self, forKey: .status)
            diagnostic = try fields.decodeIfPresent(Diagnostic.self, forKey: .diagnostic)
            evidence = try JSONValue(from: decoder)
        }
    }
    let approvalID: String?
    let requestID: String
    let status: String
    let effect: String
    let assessment: JSONValue?
    let guidance: JSONValue?
    let assessmentChanged: Bool?
    let option: String?
    let untrustedReasonText: String?
    let result: ActionResult?
    let operatorPreview: DesktopPresentation?
    let requestHistory: ApprovalRequestHistory?
    let attention: [String: ApprovalAttentionDelivery]?

    enum CodingKeys: String, CodingKey {
        case approvalID = "approval_id"
        case requestID = "request_id"
        case status, effect, assessment, guidance, option
        case assessmentChanged = "assessment_changed"
        case untrustedReasonText = "untrusted_reason_text"
        case result
        case operatorPreview = "operator_preview"
        case requestHistory = "request_history"
        case attention
    }

    var id: String { approvalID ?? requestID }
    var terminal: Bool { ["approved", "rejected", "expired", "superseded"].contains(status) }
    var display: String {
        let action = result?.status.map { " Preview result: \($0)." } ?? ""
        let diagnostic = result?.diagnostic.map { " \($0.message)" } ?? ""
        return "\(status.capitalized). \(effect)\(action)\(diagnostic)"
    }
    var quotedUntrustedReason: String? { untrustedReasonText.map(quotedRequesterText) }
}

enum ResolutionResult: Equatable {
    case decided(String)
    case desktop(DesktopPresentation)
}

enum DesktopOpenError: LocalizedError {
    case url, clipboard, browser
    var errorDescription: String? {
        switch self {
        case .url: return "Desktop presentation is ready, but its browser URL is invalid. Inspect this agent's presentation before retrying."
        case .clipboard: return "Desktop presentation is ready, but the unlock code could not be copied. Command Centre did not open the browser."
        case .browser: return "The desktop unlock code was copied, but macOS could not open the browser."
        }
    }
}

extension DesktopPresentation {
    var handoffNotice: String {
        "\(agent): unlock code copied. Paste it into the browser's Unlock preview page. The browser open request succeeded; desktop connection is checked in that page."
    }

    func open(copyCode: (String) -> Bool, openBrowser: (URL) -> Bool) throws {
        guard let target = URL(string: url), ["http", "https"].contains(target.scheme ?? "") else { throw DesktopOpenError.url }
        guard copyCode(unlockCode) else { throw DesktopOpenError.clipboard }
        guard openBrowser(target) else { throw DesktopOpenError.browser }
    }
}

enum WebMITMOpenError: LocalizedError {
    case unavailable, clipboard, browser

    var errorDescription: String? {
        switch self {
        case .unavailable: return "This SafeYolo host has not reported an active WebMITM URL."
        case .clipboard: return "Could not copy the WebMITM sign-in key. The browser was not opened."
        case .browser: return "The sign-in key was copied, but macOS could not open WebMITM in the browser."
        }
    }
}

enum ClientError: LocalizedError {
    case invalidURL(String)
    case invalidResponse
    case connectionUnavailable
    case requestFailed(Int, String)
    case invalidApproval(String)
    case instanceMismatch(expected: String, actual: String)

    var errorDescription: String? {
        switch self {
        case .invalidURL(let value):
            return "Invalid URL: \(value)"
        case .invalidResponse:
            return "SafeYolo returned an invalid response"
        case .connectionUnavailable:
            return "The selected SafeYolo instance could not be verified. Reconnect that instance and retry."
        case .requestFailed(let status, let message):
            return "SafeYolo returned HTTP \(status): \(message)"
        case .invalidApproval(let message):
            return message
        case .instanceMismatch(let expected, let actual):
            return "SafeYolo instance changed: expected \(expected), received \(actual)"
        }
    }
}

func encodePathComponent(_ value: String) -> String? {
    var allowed = CharacterSet.alphanumerics
    allowed.insert(charactersIn: "-._~")
    guard !value.isEmpty else {
        return nil
    }
    return value.addingPercentEncoding(withAllowedCharacters: allowed)
}

// These are owner reads of existing records. Receipt identity includes the
// initiator because two initiators can select the same operation ID.
struct SupportReceipt: Decodable, Hashable, Identifiable {
    let fields: [String: JSONValue]
    let operationID: String
    let instanceID: String
    let initiator: String
    var id: String { "\(instanceID)/\(initiator)/\(operationID)" }
    var targetID: String { fields["target_id"]?.text ?? "unavailable" }
    var title: String {
        "\(fields["action"]?.text ?? "Action unavailable") → \(fields["target_name"]?.text ?? targetID): \(fields["state"]?.text ?? "unknown")"
    }

    init(from decoder: Decoder) throws {
        let fields = try [String: JSONValue](from: decoder)
        guard let operation = fields["operation_id"]?.text,
              let instance = fields["instance_id"]?.text,
              let initiator = fields["initiator_principal"]?.text,
              fields["target_id"]?.text != nil else {
            throw ClientError.invalidResponse
        }
        self.fields = fields
        operationID = operation
        instanceID = instance
        self.initiator = initiator
    }

    var summary: String {
        let labels = [
            ("Original operation ID", "operation_id"), ("Owning instance", "instance_id"),
            ("Initiator principal", "initiator_principal"), ("Initiator and original run", "initiator"),
            ("Target", "target_name"), ("Durable target", "target_id"), ("Original target run", "target_run"),
            ("Recorded action", "action"), ("Action selections", "recorded_action"),
            ("Lifecycle action", "lifecycle_operation"), ("Grant at admission", "grant"),
            ("Grant revision at admission", "grant_revision"), ("Grant expiry at admission", "grant_expires_at"),
            ("Requested (Unix seconds)", "requested_at"), ("Finished (Unix seconds)", "finished_at"),
            ("Outcome", "state"), ("Execution started", "execution_started"),
            ("Completion verified", "completion_verified"), ("Resulting run", "resulting_run"),
            ("Canonical audit event", "audit_event_id"), ("Canonical audit delivered", "audit_delivered"),
            ("Audit delivery", "audit_status"), ("Diagnostic", "diagnostic"), ("Recovery", "recovery")
        ]
        return labels.compactMap { label, key -> String? in
            guard let value = fields[key] else { return nil }
            if value == .null {
                if key == "grant_expires_at" { return "Grant lifetime at admission: standing" }
                if key == "audit_event_id" { return "Canonical audit reference: pending or unavailable" }
                return nil
            }
            return "\(label): \(supportEvidence(value))"
        }.joined(separator: "\n")
    }
}

struct SupportReceiptPage: Decodable {
    let instanceID: String
    let receipts: [SupportReceipt]
    let total: Int
    let omitted: Int
    enum CodingKeys: String, CodingKey { case instanceID = "instance_id", receipts, total, omitted }
}

struct SupportReceiptDetail: Decodable {
    let receipt: SupportReceipt
    let outputIncluded: Bool
    let currentTarget: JSONValue?
    let currentGrant: JSONValue?
    let recordedResult: JSONValue?
    let recovery: String
    enum CodingKeys: String, CodingKey {
        case receipt, recovery
        case outputIncluded = "output_included", currentTarget = "current_target", currentGrant = "current_grant"
        case recordedResult = "recorded_result"
    }
}

struct OperatorSignal: Decodable, Hashable, Identifiable {
    let signalID: String
    let roomID: String
    let revision: Int
    let kind: String
    let author: JSONValue
    var id: String { signalID }
    enum CodingKeys: String, CodingKey { case signalID = "signal_id", roomID = "room_id", revision, kind, author }
}

struct OperatorSignalPage: Decodable {
    let items: [OperatorSignal]
    let total: Int
    let nextAfter: String?
    enum CodingKeys: String, CodingKey { case items, total, nextAfter = "next_after" }
}

extension JSONValue {
    var text: String? { if case .string(let value) = self { return value }; return nil }
    var fields: [String: JSONValue]? { if case .object(let value) = self { return value }; return nil }
    var values: [JSONValue]? { if case .array(let value) = self { return value }; return nil }
}

func supportEvidence(_ value: JSONValue) -> String {
    switch value {
    case .null: return "Not reported"
    case .object(let fields):
        return fields.keys.sorted().filter { fields[$0] != .null }.map {
            "\($0.replacingOccurrences(of: "_", with: " ").capitalized): \(supportEvidence(fields[$0]!))"
        }.joined(separator: "\n")
    case .array(let values): return values.isEmpty ? "None reported" : values.map(supportEvidence).joined(separator: "\n\n")
    default: return value.description
    }
}
