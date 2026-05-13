// OAuth.swift — third-party identity provider login via
// `ASWebAuthenticationSession`, the system-managed in-app browser that
// shares cookies with Safari (so existing Google/Apple/Microsoft
// sessions are picked up automatically).
//
// Flow:
//   1. Build {apiURL}/v1/auth/oauth/{provider}/authorize?redirect_uri=…
//   2. Hand to ASWebAuthenticationSession with `callbackURLScheme`
//      pulled from `redirectURI` (everything before `://`).
//   3. The session resolves with a callback URL of shape
//      `myapp://auth-callback?access_token=…&session_id=…`
//      (or `?error=…&error_description=…` on rejection).
//   4. Parse, build the session locally without needing a follow-up
//      server call — the access_token and session_id are everything
//      the SDK needs for subsequent API calls.

#if canImport(AuthenticationServices) && (os(iOS) || os(macOS) || os(visionOS))

import Foundation
import AuthenticationServices

/// Built-in IdPs Authio supports. The wire name matches the path
/// segment in `/v1/auth/oauth/{provider}/authorize`.
public enum OAuthProvider: String, Sendable {
    case google, microsoft, apple, github, slack, gitlab, linkedin
}

extension Authio.Client {

    /// Run an OAuth login via system-provided in-app browser.
    ///
    /// - Parameter provider: which IdP.
    /// - Parameter redirectURI: must use a custom URL scheme registered
    ///   for the app (e.g. `myapp://auth-callback`). The scheme is what
    ///   ASWebAuthenticationSession watches to know the flow finished.
    /// - Parameter presentationAnchor: the window to anchor the browser
    ///   sheet on.
    /// - Parameter prefersEphemeralWebBrowserSession: when true, the
    ///   sheet uses a private session that doesn't share cookies with
    ///   Safari — useful for "use a different account" buttons.
    public func signInWithOAuth(
        provider: OAuthProvider,
        redirectURI: String,
        presentationAnchor: ASPresentationAnchor,
        prefersEphemeralWebBrowserSession: Bool = false
    ) async throws -> AuthioSession {
        guard let scheme = redirectURI.components(separatedBy: "://").first,
              !scheme.isEmpty else {
            throw AuthioError.oauthRejected(
                code: "invalid_redirect_uri",
                description: "redirectURI must use a custom URL scheme"
            )
        }
        var urlBuilder = URLComponents(
            string: http.baseURL.absoluteString + "/v1/auth/oauth/\(provider.rawValue)/authorize"
        )
        urlBuilder?.queryItems = [
            URLQueryItem(name: "redirect_uri",     value: redirectURI),
            URLQueryItem(name: "publishable_key",  value: http.publishableKey),
        ]
        guard let authURL = urlBuilder?.url else {
            throw AuthioError.oauthRejected(code: "invalid_url", description: nil)
        }

        let callbackURL = try await OAuthWebSession.run(
            url: authURL,
            scheme: scheme,
            anchor: presentationAnchor,
            ephemeral: prefersEphemeralWebBrowserSession
        )
        return try parseOAuthCallback(callbackURL)
    }

    /// Visible for testing — parses the redirect query params into a
    /// fully-formed AuthioSession or throws AuthioError.oauthRejected.
    internal func parseOAuthCallback(_ url: URL) throws -> AuthioSession {
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let items = components?.queryItems ?? []
        func q(_ name: String) -> String? {
            items.first(where: { $0.name == name })?.value
        }
        if let errCode = q("error") {
            throw AuthioError.oauthRejected(
                code: errCode,
                description: q("error_description")
            )
        }
        guard let access = q("access_token"),
              let sid    = q("session_id") else {
            throw AuthioError.oauthRejected(
                code: "missing_tokens",
                description: "callback URL missing access_token or session_id"
            )
        }
        let expiresIn = Int(q("expires_in") ?? "") ?? 900
        return AuthioSession(
            sessionId:    sid,
            userId:       q("user_id") ?? "",
            orgId:        q("org_id"),
            role:         q("role"),
            accessToken:  access,
            refreshToken: q("refresh_token"),
            expiresAt:    Date().addingTimeInterval(TimeInterval(expiresIn))
        )
    }
}

// =====================================================================
// ASWebAuthenticationSession ↔ async/await bridge.
//
// Similar pattern to PasskeyCeremony: a self-retaining presentation
// provider that holds the session strongly until the callback fires.
// =====================================================================

private enum OAuthWebSession {

    static func run(
        url: URL,
        scheme: String,
        anchor: ASPresentationAnchor,
        ephemeral: Bool
    ) async throws -> URL {
        try await withCheckedThrowingContinuation { cont in
            Task { @MainActor in
                let presenter = PresentationProvider(anchor: anchor)
                let session = ASWebAuthenticationSession(
                    url: url,
                    callbackURLScheme: scheme
                ) { callbackURL, error in
                    _ = presenter // keep alive until callback fires
                    if let error {
                        if let asErr = error as? ASWebAuthenticationSessionError,
                           asErr.code == .canceledLogin {
                            cont.resume(throwing: AuthioError.oauthRejected(
                                code: "user_cancelled",
                                description: nil
                            ))
                            return
                        }
                        cont.resume(throwing: AuthioError.oauthRejected(
                            code: "web_session_failed",
                            description: error.localizedDescription
                        ))
                        return
                    }
                    guard let url = callbackURL else {
                        cont.resume(throwing: AuthioError.oauthRejected(
                            code: "missing_callback",
                            description: nil
                        ))
                        return
                    }
                    cont.resume(returning: url)
                }
                session.presentationContextProvider = presenter
                session.prefersEphemeralWebBrowserSession = ephemeral
                _ = session.start()
            }
        }
    }
}

private final class PresentationProvider:
    NSObject,
    ASWebAuthenticationPresentationContextProviding,
    @unchecked Sendable
{
    let anchor: ASPresentationAnchor
    init(anchor: ASPresentationAnchor) { self.anchor = anchor }
    func presentationAnchor(
        for session: ASWebAuthenticationSession
    ) -> ASPresentationAnchor {
        return anchor
    }
}

#endif
