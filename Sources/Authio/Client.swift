// Client.swift — public entry point.
//
// All authentication flows hang off `Authio.Client`. Construct one per
// app launch, with the project's `pk_live_` publishable key. The client
// is thread-safe (HTTPClient uses URLSession which is) and may be
// shared across the app.
//
// Mobile clients only ever carry the publishable key — NEVER a
// `sk_live_` secret key. Server-side CRUD lives behind the Management
// API and needs the secret; that's deliberately out of scope for this
// SDK.

import Foundation

/// The Authio namespace. The actual client is `Authio.Client`.
public enum Authio {

    public final class Client: @unchecked Sendable {

        let http: HTTPClient
        public let keychain: AuthioKeychain

        /// - Parameter publishableKey: project's `pk_live_…` or
        ///   `pk_test_…` key from the Authio dashboard. Safe to embed in
        ///   the app binary.
        /// - Parameter apiURL: defaults to production. Override for
        ///   self-hosted or testing.
        /// - Parameter urlSession: inject a custom URLSession (or a
        ///   mock conforming to the `URLSessionProtocol` test seam).
        /// - Parameter keychain: override the keychain wrapper to
        ///   change the service identifier.
        public init(
            publishableKey: String,
            apiURL: URL = URL(string: "https://api.authio.com")!,
            urlSession: URLSession = .shared,
            keychain: AuthioKeychain = AuthioKeychain()
        ) throws {
            guard !publishableKey.isEmpty else {
                throw AuthioError.missingPublishableKey
            }
            self.http = HTTPClient(
                baseURL: apiURL,
                publishableKey: publishableKey,
                session: urlSession,
                userAgent: "authio-swift/0.2.0"
            )
            self.keychain = keychain
        }

        /// Test-only initialiser that accepts the URLSession seam
        /// directly. Internal so production callers can't bypass the
        /// real URLSession.
        internal init(
            publishableKey: String,
            apiURL: URL,
            session: URLSessionProtocol,
            keychain: AuthioKeychain = AuthioKeychain()
        ) throws {
            guard !publishableKey.isEmpty else {
                throw AuthioError.missingPublishableKey
            }
            self.http = HTTPClient(
                baseURL: apiURL,
                publishableKey: publishableKey,
                session: session,
                userAgent: "authio-swift/0.2.0"
            )
            self.keychain = keychain
        }

        // ----------------------------------------------------------
        // MARK: - Session verification + refresh
        // ----------------------------------------------------------

        /// Call on app launch with the cached session. Returns true if
        /// the access token is still valid (server checked). False
        /// means the caller should re-authenticate.
        ///
        /// Roadmap: local JWT verification against `/v1/jwks` cached
        /// for 10 minutes. For v0.2 we round-trip to the server.
        public func verify(session: AuthioSession) async throws -> Bool {
            // Fast path: locally expired (skip the network round-trip).
            if session.expiresAt < Date() { return false }
            do {
                let _: User = try await http.send(
                    "GET",
                    "/v1/me",
                    bearer: session.accessToken
                )
                return true
            } catch AuthioError.requestFailed(let status, _, _, _)
                where status == 401 || status == 403 {
                return false
            }
        }

        // ----------------------------------------------------------
        // MARK: - Multi-organization support (the differentiator)
        // ----------------------------------------------------------

        /// All organizations the current user can switch into. Useful
        /// for rendering an org picker on multi-org users.
        ///
        /// Requires an authenticated session — call `signInWithPasskey`
        /// or one of the other flows first, then keep the returned
        /// session around to pass in here.
        public func listMyOrganizations(
            session: AuthioSession
        ) async throws -> [MembershipWithOrg] {
            struct Response: Decodable { let data: [MembershipWithOrg] }
            let r: Response = try await http.send(
                "GET",
                "/v1/me/organizations",
                bearer: session.accessToken
            )
            return r.data
        }

        /// Pivot the session to a different organization the user is a
        /// member of. The returned session has the new `orgId` and
        /// `role`, but a fresh `accessToken` — store this and discard
        /// the previous one.
        public func switchOrganization(
            session: AuthioSession,
            to organizationId: String
        ) async throws -> AuthioSession {
            struct Req: Encodable {
                let organizationId: String
                enum CodingKeys: String, CodingKey {
                    case organizationId = "organization_id"
                }
            }
            let env: SessionEnvelopeDTO = try await http.send(
                "POST",
                "/v1/sessions/select-org",
                body: Req(organizationId: organizationId),
                bearer: session.accessToken
            )
            return env.toSession()
        }

        // ----------------------------------------------------------
        // MARK: - Sign out
        // ----------------------------------------------------------

        /// Revoke the given session server-side. After this returns,
        /// the access token is rejected by every Authio endpoint.
        /// Also wipes the session from Keychain.
        public func revokeSession(_ session: AuthioSession,
                                  keychainAccount: String = "default") async throws {
            struct Req: Encodable { let sessionId: String
                enum CodingKeys: String, CodingKey { case sessionId = "session_id" }
            }
            let _: EmptyResponse = try await http.send(
                "POST",
                "/v1/sessions/revoke",
                body: Req(sessionId: session.sessionId),
                bearer: session.accessToken
            )
            try? keychain.delete(account: keychainAccount)
        }
    }
}
