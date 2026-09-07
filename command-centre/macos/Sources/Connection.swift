import Foundation

enum RemoteTransport: String, Codable, CaseIterable {
    case tailnet
    case sshTunnel = "ssh-tunnel"

    var label: String { self == .tailnet ? "Tailscale" : "SSH tunnel" }
}

struct RemoteConnectionProfile: Codable, Equatable {
    let friendlyName: String
    let adminURL: String
    let eventsURL: String
    let instanceID: String
    var terminalTarget: String? = nil
    var transport: RemoteTransport? = nil
}

protocol ConnectionProfileStore {
    func load() throws -> RemoteConnectionProfile?
    func save(_ profile: RemoteConnectionProfile) throws
    func delete() throws
}

struct UserDefaultsConnectionProfileStore: ConnectionProfileStore {
    private let defaults: UserDefaults
    private let key = "remoteConnectionProfile"

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func load() throws -> RemoteConnectionProfile? {
        guard let data = defaults.data(forKey: key) else {
            return nil
        }
        return try JSONDecoder().decode(RemoteConnectionProfile.self, from: data)
    }

    func save(_ profile: RemoteConnectionProfile) throws {
        defaults.set(try JSONEncoder().encode(profile), forKey: key)
    }

    func delete() throws {
        defaults.removeObject(forKey: key)
    }
}

struct RemoteConnectionInput {
    let friendlyName: String
    let adminURL: String
    let eventsURL: String
    let token: String
    var terminalTarget: String? = nil
    var transport: RemoteTransport = .tailnet
}

final class RemoteConnectionVerifier {
    private let session: URLSession

    init(session: URLSession = .shared) {
        self.session = session
    }

    func verify(
        _ input: RemoteConnectionInput,
        completion: @escaping (Result<RemoteConnectionProfile, Error>) -> Void
    ) {
        do {
            let adminURL = try validatedRemoteURL(input.adminURL, scheme: "https", transport: input.transport)
            _ = try validatedRemoteURL(input.eventsURL, scheme: "wss", transport: input.transport)
            guard !input.token.isEmpty else {
                throw ConnectionError.missingToken
            }
            let identityURL = adminURL.appending(path: "admin/instance")
            var request = URLRequest(url: identityURL)
            request.setValue("Bearer \(input.token)", forHTTPHeaderField: "Authorization")
            session.dataTask(with: request) { data, response, error in
                let result: Result<RemoteConnectionProfile, Error>
                if let error {
                    result = .failure(error)
                } else if !(response is HTTPURLResponse) {
                    result = .failure(ClientError.invalidResponse)
                } else if let response = response as? HTTPURLResponse,
                          !(200..<300).contains(response.statusCode) {
                    result = .failure(ConnectionError.requestFailed(response.statusCode))
                } else {
                    do {
                        guard let data else {
                            throw ClientError.invalidResponse
                        }
                        let identity = try JSONDecoder().decode(InstanceInfo.self, from: data)
                        guard !identity.safeyoloInstanceID.isEmpty else {
                            throw ClientError.invalidResponse
                        }
                        result = .success(
                            RemoteConnectionProfile(
                                friendlyName: input.friendlyName.isEmpty
                                    ? identity.safeyoloInstanceID
                                    : input.friendlyName,
                                adminURL: adminURL.absoluteString.trimmingCharacters(
                                    in: CharacterSet(charactersIn: "/")
                                ),
                                eventsURL: input.eventsURL,
                                instanceID: identity.safeyoloInstanceID,
                                terminalTarget: input.terminalTarget,
                                transport: input.transport
                            )
                        )
                    } catch {
                        result = .failure(error)
                    }
                }
                DispatchQueue.main.async {
                    completion(result)
                }
            }.resume()
        } catch {
            DispatchQueue.main.async {
                completion(.failure(error))
            }
        }
    }
}

enum AgentTerminalAction: String {
    case attach
    case shell
}

func agentTerminalCommand(
    name: String, remote: Bool, terminalTarget: String?,
    adminURL: String? = nil, hostUser: String? = nil, hostPython: String? = nil,
    transport: RemoteTransport = .tailnet, action: AgentTerminalAction = .attach
) throws -> String {
    func quoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
    let actionArguments = action == .shell ? "shell --persistent" : "attach"
    guard remote else { return "safeyolo agent \(actionArguments) -- " + quoted(name) }
    let target: String
    if let override = terminalTarget?.trimmingCharacters(in: .whitespacesAndNewlines), !override.isEmpty {
        target = override
    } else if transport == .tailnet,
              let host = URL(string: adminURL ?? "")?.host,
              let user = hostUser, !user.isEmpty {
        target = user + "@" + host
    } else {
        throw ConnectionError.missingTerminalTarget
    }
    guard let python = hostPython, !python.isEmpty else {
        throw ConnectionError.missingRemoteInstallation
    }
    // Keep the interpreter's venv path intact: resolving its symlink would
    // select the base Python and lose the installed SafeYolo package.
    let command = quoted(python) + " -m safeyolo.cli agent \(actionArguments) -- " + quoted(name)
    // Both sessions survive viewer disconnection. The persistent shell is independent
    // of the coding-agent terminal; neither action starts the coding agent.
    // SSH credentials are separate from the Admin API credential.
    return "ssh -t -- " + quoted(target) + " " + quoted(command)
}

func validatedRemoteURL(_ value: String, scheme: String, transport: RemoteTransport) throws -> URL {
    let parsed = URL(string: value)
    let tunnelLoopback = transport == .sshTunnel
        && ["127.0.0.1", "localhost", "::1", "[::1]"].contains(parsed?.host ?? "")
    let allowedSchemes = tunnelLoopback ? [scheme, scheme == "https" ? "http" : "ws"] : [scheme]
    guard let url = URL(string: value),
          allowedSchemes.contains(url.scheme ?? ""),
          url.host != nil,
          url.user == nil,
          url.password == nil,
          url.query == nil,
          url.fragment == nil
    else {
        throw ConnectionError.invalidRemoteURL(value, scheme)
    }
    return url
}

enum ConnectionError: LocalizedError {
    case invalidRemoteURL(String, String)
    case missingToken
    case missingCredential(String)
    case requestFailed(Int)
    case missingTerminalTarget
    case missingRemoteInstallation

    var errorDescription: String? {
        switch self {
        case .invalidRemoteURL(let value, let scheme):
            return "Expected a \(scheme) URL without credentials, query, or fragment: \(value)"
        case .missingToken:
            return "Enter the remote Admin API credential"
        case .missingTerminalTarget:
            return "The remote terminal target is unavailable. Tailscale uses the connected host and its reported username. For an SSH tunnel or a different login, set user@host or an SSH alias in Connection Settings. Run Agent does not need SSH."
        case .missingRemoteInstallation:
            return "The connected SafeYolo server did not report its Python executable. Update and restart that server, then reconnect Command Centre. Terminal attachment uses the server's installation without relying on the SSH shell's PATH."
        case .missingCredential(let instanceID):
            return "No Keychain credential is stored for \(instanceID)"
        case .requestFailed(let status):
            return "Remote SafeYolo returned HTTP \(status) while verifying its identity"
        }
    }
}
