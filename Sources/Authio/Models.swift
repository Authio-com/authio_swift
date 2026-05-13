// Models.swift — the typed shapes Authio's REST API returns.
//
// Authio's REST API uses snake_case on the wire (`session_id`,
// `access_token`, etc.). Every wire type below declares an explicit
// `CodingKeys` mapping rather than relying on a global
// `convertFromSnakeCase` strategy — we don't want a global key
// converter that would also mangle the W3C-camelCase WebAuthn options
// (`rawId`, `clientDataJSON`) that flow through the same decoder.

import Foundation

public struct User: Codable, Equatable, Sendable {
    public let id: String
    public let projectId: String
    public let email: String
    public let emailVerified: Bool
    public let name: String?
    public let avatarUrl: String?
    public let defaultOrganizationId: String?
    public let createdAt: Date?
    public let updatedAt: Date?

    enum CodingKeys: String, CodingKey {
        case id
        case projectId             = "project_id"
        case email
        case emailVerified         = "email_verified"
        case name
        case avatarUrl             = "avatar_url"
        case defaultOrganizationId = "default_organization_id"
        case createdAt             = "created_at"
        case updatedAt             = "updated_at"
    }
}

public struct Organization: Codable, Equatable, Sendable {
    public let id: String
    public let projectId: String
    public let name: String
    public let slug: String
    public let createdAt: Date?

    enum CodingKeys: String, CodingKey {
        case id
        case projectId = "project_id"
        case name
        case slug
        case createdAt = "created_at"
    }
}

public enum MembershipStatus: String, Codable, Sendable {
    case invited, active, suspended, deactivated
}

public struct Membership: Codable, Equatable, Sendable {
    public let id: String
    public let projectId: String
    public let userId: String
    public let organizationId: String
    public let role: String
    public let status: MembershipStatus
    public let joinedAt: Date?
    public let lastActiveAt: Date?
    public let preferredLoginMethod: String?
    public let invitedBy: String?

    enum CodingKeys: String, CodingKey {
        case id
        case projectId            = "project_id"
        case userId               = "user_id"
        case organizationId       = "organization_id"
        case role
        case status
        case joinedAt             = "joined_at"
        case lastActiveAt         = "last_active_at"
        case preferredLoginMethod = "preferred_login_method"
        case invitedBy            = "invited_by"
    }
}

/// A membership plus its embedded Organization. This is what
/// `/v1/me/organizations` returns: every org the current user can switch
/// into, with the org payload inlined for one-call rendering of the
/// SwitchOrganization picker.
public struct MembershipWithOrg: Codable, Equatable, Sendable {
    public let id: String
    public let projectId: String
    public let userId: String
    public let organizationId: String
    public let role: String
    public let status: MembershipStatus
    public let joinedAt: Date?
    public let lastActiveAt: Date?
    public let organization: Organization

    enum CodingKeys: String, CodingKey {
        case id
        case projectId      = "project_id"
        case userId         = "user_id"
        case organizationId = "organization_id"
        case role
        case status
        case joinedAt       = "joined_at"
        case lastActiveAt   = "last_active_at"
        case organization
    }
}

/// What the caller stores (in Keychain, typically) after a successful
/// sign-in. `accessToken` is short-lived (~15 min); call
/// `Authio.Client.verify(session:)` on app launch and run
/// `signInWithPasskey` again if invalid.
///
/// `orgId` is nil when the user has authenticated but not yet selected an
/// organization — common for multi-org users at first login. Render an
/// org picker (`listMyOrganizations()` → `switchOrganization(to:)`) before
/// allowing org-scoped requests.
public struct AuthioSession: Codable, Equatable, Sendable {
    public let sessionId: String
    public let userId: String
    public let orgId: String?
    public let role: String?
    public let accessToken: String
    public let refreshToken: String?
    public let expiresAt: Date

    enum CodingKeys: String, CodingKey {
        case sessionId    = "session_id"
        case userId       = "user_id"
        case orgId        = "org_id"
        case role
        case accessToken  = "access_token"
        case refreshToken = "refresh_token"
        case expiresAt    = "expires_at"
    }

    public init(
        sessionId: String,
        userId: String,
        orgId: String?,
        role: String?,
        accessToken: String,
        refreshToken: String?,
        expiresAt: Date
    ) {
        self.sessionId = sessionId
        self.userId = userId
        self.orgId = orgId
        self.role = role
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresAt = expiresAt
    }
}

// =====================================================================
// Wire-only response shapes the SDK decodes server payloads into.
// These are internal but kept here so the wire mapping is one file.
// =====================================================================

/// Mirror of auth-core's `session.Envelope`. Always returned by the
/// passkey verify, magic-link consume, and oauth callback endpoints.
struct SessionEnvelopeDTO: Decodable {
    let sessionId: String
    let accessToken: String
    let refreshToken: String?
    let expiresAt: Date
    let user: User?
    let activeOrganization: Organization?
    let activeRole: String?
    let memberships: [MembershipWithOrg]?

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case expiresAt = "expires_at"
        case user
        case activeOrganization = "active_organization"
        case activeRole = "active_role"
        case memberships
    }

    func toSession() -> AuthioSession {
        AuthioSession(
            sessionId: sessionId,
            userId: user?.id ?? "",
            orgId: activeOrganization?.id,
            role: activeRole,
            accessToken: accessToken,
            refreshToken: refreshToken,
            expiresAt: expiresAt
        )
    }
}

/// Auth-core's `PublicKeyCredentialCreationOptions` / `RequestOptions`
/// don't have a single canonical struct in WebAuthn — the JSON varies by
/// flow. We carry it as opaque metadata + the few fields the native
/// passkey API actually needs.
///
/// All field names below are exact-match camelCase to the W3C WebAuthn
/// JSON shape — no CodingKeys needed because the wire and Swift names
/// align.
struct PasskeyOptionsDTO: Decodable {
    let publicKey: PublicKey

    struct PublicKey: Decodable {
        let challenge: String                // base64url
        let rp: RelyingParty?                // present on register
        let user: UserHandle?                // present on register
        let pubKeyCredParams: [PubKeyParam]?
        let timeout: Int?
        let attestation: String?
        let authenticatorSelection: AuthenticatorSelection?
        let rpId: String?                    // present on login
        let allowCredentials: [Credential]?  // present on login
        let userVerification: String?
    }
    struct RelyingParty: Decodable { let id: String; let name: String }
    struct UserHandle: Decodable {
        let id: String                       // base64url
        let name: String
        let displayName: String?
    }
    struct PubKeyParam: Decodable {
        let type: String
        let alg: Int
    }
    struct AuthenticatorSelection: Decodable {
        let userVerification: String?
        let residentKey: String?
        let authenticatorAttachment: String?
    }
    struct Credential: Decodable {
        let type: String
        let id: String                       // base64url
        let transports: [String]?
    }
}
