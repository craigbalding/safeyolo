import Foundation

struct InstanceInfo: Decodable {
    let schemaVersion: Int
    let safeyoloInstanceID: String

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case safeyoloInstanceID = "safeyolo_instance_id"
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

private func encodePathComponent(_ value: String) -> String? {
    var allowed = CharacterSet.alphanumerics
    allowed.insert(charactersIn: "-._~")
    guard !value.isEmpty else {
        return nil
    }
    return value.addingPercentEncoding(withAllowedCharacters: allowed)
}
