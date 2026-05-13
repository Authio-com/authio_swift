// Authio Swift SDK. iOS / macOS / visionOS support for passwordless,
// multi-org auth using native passkey APIs (ASAuthorizationPlatformPublicKeyCredentialProvider).
//
// Multi-org-first: a single end-user identity can belong to many
// organizations. `Session.userId` always identifies the person; `orgId`
// is the active organization (may be nil when the user has authenticated
// but not yet selected an org).

import Foundation

public enum AuthioError: Error {
    case missingApiKey
    case requestFailed(status: Int, code: String, message: String)
    case decodeFailed
}

public struct User: Codable, Equatable {
    public let id: String
    public let projectId: String
    public let email: String
    public let emailVerified: Bool
    public let name: String?
    public let avatarUrl: String?
    public let defaultOrganizationId: String?

    enum CodingKeys: String, CodingKey {
        case id
        case projectId = "project_id"
        case email
        case emailVerified = "email_verified"
        case name
        case avatarUrl = "avatar_url"
        case defaultOrganizationId = "default_organization_id"
    }
}

public struct Organization: Codable, Equatable {
    public let id: String
    public let projectId: String
    public let name: String
    public let slug: String

    enum CodingKeys: String, CodingKey {
        case id
        case projectId = "project_id"
        case name
        case slug
    }
}

public enum MembershipStatus: String, Codable {
    case invited, active, suspended, deactivated
}

public struct Membership: Codable, Equatable {
    public let id: String
    public let projectId: String
    public let userId: String
    public let organizationId: String
    public let role: String
    public let status: MembershipStatus

    enum CodingKeys: String, CodingKey {
        case id
        case projectId = "project_id"
        case userId = "user_id"
        case organizationId = "organization_id"
        case role
        case status
    }
}

public struct Session: Codable, Equatable {
    public let sessionId: String
    public let userId: String
    public let orgId: String?
    public let role: String?
}

public final class Authio {
    public let apiKey: String
    public let baseURL: URL
    private let session: URLSession

    public init(apiKey: String, baseURL: URL = URL(string: "https://api.authio.com")!) throws {
        guard !apiKey.isEmpty else { throw AuthioError.missingApiKey }
        self.apiKey = apiKey
        self.baseURL = baseURL
        self.session = URLSession(configuration: .default)
    }

    public func getUser(id: String) async throws -> User {
        try await request("/v1/users/\(id)")
    }

    public func listMemberships(userId: String) async throws -> [Membership] {
        try await request("/v1/users/\(userId)/memberships")
    }

    public func switchOrganization(organizationId: String) async throws -> Session {
        try await request("/v1/sessions/switch-org",
                          method: "POST",
                          body: ["organization_id": organizationId])
    }

    private func request<T: Decodable>(_ path: String,
                                       method: String = "GET",
                                       body: [String: String]? = nil) async throws -> T {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = method
        req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        req.setValue("authio-swift/0.1.0", forHTTPHeaderField: "User-Agent")
        if let body = body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONEncoder().encode(body)
        }
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw AuthioError.decodeFailed
        }
        if http.statusCode >= 400 {
            struct APIError: Codable { let code: String?; let message: String? }
            let err = (try? JSONDecoder().decode(APIError.self, from: data)) ?? APIError(code: nil, message: nil)
            throw AuthioError.requestFailed(
                status: http.statusCode,
                code: err.code ?? "request_failed",
                message: err.message ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            )
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
}
