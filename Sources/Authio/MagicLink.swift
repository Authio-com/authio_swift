// MagicLink.swift — email/SMS magic-link flow.
//
// Two halves:
//   1. sendMagicLink(destination:redirectURI:) — fire-and-forget POST.
//      Server sends the email/SMS containing a URL that opens the
//      caller's app via a custom-scheme deep link.
//   2. consumeMagicLinkCallback(url:) — the app's URL handler hands us
//      the deep-link URL. We pull out `token`, exchange it at the
//      server, return the session.
//
// The server-side callback endpoint historically returned a 302 redirect
// for browsers; we ask it to JSON-respond by sending
// `Accept: application/json` (HTTPClient sets that header by default).

import Foundation

extension Authio.Client {

    /// Send a one-time magic link to `destination`. The server emits
    /// the email/SMS asynchronously; this call returns once the request
    /// is accepted (typically <100ms).
    ///
    /// `redirectURI` is what the server embeds in the link's `redirect`
    /// query param; when the user opens the link the server redirects
    /// here with the session token attached. Use a custom scheme
    /// (`myapp://auth-callback`) so iOS routes back into your app.
    public func sendMagicLink(
        destination: String,
        redirectURI: String,
        organizationId: String? = nil
    ) async throws {
        struct Req: Encodable {
            let destination: String
            let redirectUri: String
            let organizationId: String?

            enum CodingKeys: String, CodingKey {
                case destination
                case redirectUri    = "redirect_uri"
                case organizationId = "organization_id"
            }
        }
        let _: EmptyResponse = try await http.send(
            "POST",
            "/v1/auth/magic-link/send",
            body: Req(
                destination: destination,
                redirectUri: redirectURI,
                organizationId: organizationId
            )
        )
    }

    /// Exchange a magic-link callback URL for a session. Call this from
    /// the app's `onOpenURL` / Scene delegate URL handler.
    ///
    /// The URL is expected to look like:
    /// `myapp://auth-callback?token=<one-time-token>` — that token is
    /// what the link's `?token=` carries; the app's deep-link handler
    /// preserves it.
    public func consumeMagicLinkCallback(url: URL) async throws -> AuthioSession {
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let token = components?.queryItems?.first(where: { $0.name == "token" })?.value
        guard let token, !token.isEmpty else {
            throw AuthioError.missingMagicLinkToken
        }
        // Server may return either the envelope JSON (mobile path; we ask
        // for it via Accept: application/json) OR a 302 with a session
        // cookie (browser path; URLSession won't follow a custom-scheme
        // redirect, so we'd get an error). We tell URLSession to look
        // for JSON by setting the Accept header explicitly.
        let env: SessionEnvelopeDTO = try await http.send(
            "GET",
            "/v1/auth/magic-link/callback?token=\(token)",
            extraHeaders: ["Accept": "application/json"]
        )
        return env.toSession()
    }
}
