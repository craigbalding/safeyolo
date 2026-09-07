import Foundation

struct InstanceInfo: Decodable {
    let schemaVersion: Int
    let safeyoloInstanceID: String
    let hostUser: String?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case safeyoloInstanceID = "safeyolo_instance_id"
        case hostUser = "host_user"
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
    let launcher: Launcher?
    let attachable: Bool
    let error: String?
    var hookErrors: [HookFailure]? = nil
    var exitCode: Int? = nil

    enum CodingKeys: String, CodingKey {
        case agentID = "agent_id"
        case name
        case sandboxState = "sandbox_state"
        case agentState = "agent_state"
        case launcher, attachable, error
        case hookErrors = "hook_errors"
        case exitCode = "exit_code"
    }

    var id: String { agentID }
    var sandboxReady: Bool { sandboxState == "ready" }
    var canStart: Bool { ["stopped", "exited", "failed"].contains(agentState) }
    var managed: Bool { ["supervisor", "manager"].contains(launcher?.kind ?? "") }
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

struct ApprovalEvent: Decodable, Hashable, Identifiable {
    struct Request: Decodable, Hashable {
        struct Scope: Decodable, Hashable {
            let agentID: String?

            enum CodingKeys: String, CodingKey {
                case agentID = "agent_id"
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
        let service: String?
        let method: String?
        let path: String?
        let reason: String?
    }

    let eventID: String?
    let requestID: String?
    let event: String
    let summary: String
    let agent: String?
    let host: String?
    let approval: Request
    let details: Details?

    enum CodingKeys: String, CodingKey {
        case eventID = "event_id"
        case requestID = "request_id"
        case event
        case summary
        case agent
        case host
        case approval
        case details
    }

    var id: String {
        "\(approval.key):\(approval.target)"
    }

    var title: String {
        "\(agent ?? "Unknown agent"): \(approval.approvalType.replacingOccurrences(of: "_", with: " "))"
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
    let expectsDesktop: Bool

    static func forApproval(_ event: ApprovalEvent, allow: Bool) throws -> MutationPlan {
        if event.approval.approvalType == "desktop_present", allow {
            guard let agentID = event.approval.scopeHint?.agentID,
                  let encodedAgentID = encodePathComponent(agentID)
            else {
                throw ClientError.invalidApproval("Desktop presentation is missing agent_id")
            }
            return MutationPlan(
                path: "/admin/agents/\(encodedAgentID)/desktop/present",
                body: event.requestID.map { ["approval_request_id": $0] } ?? [:],
                expectsDesktop: true
            )
        }

        guard event.approval.approvalType == "credential" ||
              event.approval.approvalType == "desktop_present"
        else {
            throw ClientError.invalidApproval(
                "This native client does not handle \(event.approval.approvalType)"
            )
        }

        var body = [
            "destination": event.approval.target,
            "cred_id": event.approval.key,
        ]
        if !allow {
            body["reason"] = "user_denied"
        }
        if event.approval.approvalType == "desktop_present",
           let requestID = event.requestID {
            body["approval_request_id"] = requestID
        }
        return MutationPlan(
            path: allow ? "/admin/policy/baseline/approve" : "/admin/policy/baseline/deny",
            body: body,
            expectsDesktop: false
        )
    }
}

enum ResolutionResult: Equatable {
    case decided(String)
    case desktop(DesktopPresentation)
}

enum ClientError: LocalizedError {
    case invalidURL(String)
    case invalidResponse
    case requestFailed(Int, String)
    case invalidApproval(String)
    case instanceMismatch(expected: String, actual: String)

    var errorDescription: String? {
        switch self {
        case .invalidURL(let value):
            return "Invalid URL: \(value)"
        case .invalidResponse:
            return "SafeYolo returned an invalid response"
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
