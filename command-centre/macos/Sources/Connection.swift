import Foundation

struct RemoteConnectionProfile: Codable, Equatable {
    let friendlyName: String
    let adminURL: String
    let eventsURL: String
    let instanceID: String
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
            let adminURL = try validatedRemoteURL(input.adminURL, scheme: "https")
            _ = try validatedRemoteURL(input.eventsURL, scheme: "wss")
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
                                instanceID: identity.safeyoloInstanceID
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

private func validatedRemoteURL(_ value: String, scheme: String) throws -> URL {
    guard let url = URL(string: value),
          url.scheme == scheme,
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

    var errorDescription: String? {
        switch self {
        case .invalidRemoteURL(let value, let scheme):
            return "Expected a \(scheme) URL without credentials, query, or fragment: \(value)"
        case .missingToken:
            return "Enter the remote Admin API credential"
        case .missingCredential(let instanceID):
            return "No Keychain credential is stored for \(instanceID)"
        case .requestFailed(let status):
            return "Remote SafeYolo returned HTTP \(status) while verifying its identity"
        }
    }
}
