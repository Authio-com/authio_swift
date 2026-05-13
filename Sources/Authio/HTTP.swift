// HTTP.swift — thin URLSession wrapper.
//
// All requests flow through `HTTPClient.send(...)`. Why a wrapper instead
// of inlining URLSession calls in Client.swift?
//   1. Tests inject a fake URLSession (via the `URLSessionProtocol`
//      seam below) to assert request shape without a live network.
//   2. Centralised error decoding: the server's JSON error envelope
//      (`{code, message, request_id}`) is mapped to AuthioError exactly
//      once, here.
//   3. Single place to attach the publishable-key header, user-agent,
//      and bearer token when the caller is authenticated.

import Foundation

/// URLSession-shaped seam for tests. URLSession itself conforms below.
protocol URLSessionProtocol: Sendable {
    func authioData(for request: URLRequest) async throws -> (Data, URLResponse)
}

extension URLSession: URLSessionProtocol {
    func authioData(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await self.data(for: request)
    }
}

final class HTTPClient: @unchecked Sendable {
    let baseURL: URL
    let publishableKey: String
    let session: URLSessionProtocol
    let userAgent: String

    init(baseURL: URL, publishableKey: String, session: URLSessionProtocol, userAgent: String) {
        // Trim trailing slash so appendingPathComponent doesn't double-slash.
        var s = baseURL.absoluteString
        while s.hasSuffix("/") { s.removeLast() }
        self.baseURL = URL(string: s) ?? baseURL
        self.publishableKey = publishableKey
        self.session = session
        self.userAgent = userAgent
    }

    /// GET / POST / DELETE. `path` MUST start with `/`. `body` is encoded
    /// with the shared snake_case encoder. `bearer` is the user's
    /// `access_token` for authenticated endpoints; omit for anonymous
    /// auth flows.
    func send<T: Decodable, B: Encodable>(
        _ method: String,
        _ path: String,
        body: B?,
        bearer: String? = nil,
        extraHeaders: [String: String] = [:]
    ) async throws -> T {
        // appendingPathComponent URL-encodes `?` and `&`, which breaks
        // any path that already carries a query string. Build the final
        // URL with naive string concat instead — both `baseURL` and
        // `path` are tightly controlled by the SDK.
        guard let url = URL(string: baseURL.absoluteString + path) else {
            throw AuthioError.decodeFailed(message: "invalid url: \(path)")
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue(publishableKey, forHTTPHeaderField: "X-Authio-Publishable-Key")
        if let bearer { req.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization") }
        for (k, v) in extraHeaders { req.setValue(v, forHTTPHeaderField: k) }
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try AuthioJSON.encoder.encode(body)
        }

        let (data, response) = try await session.authioData(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw AuthioError.decodeFailed(message: "no HTTPURLResponse")
        }
        if http.statusCode >= 400 {
            let requestId = http.value(forHTTPHeaderField: "X-Request-Id")
            let err = (try? JSONDecoder().decode(APIErrorEnvelope.self, from: data))
                ?? APIErrorEnvelope(code: nil, message: nil, requestId: nil)
            throw AuthioError.requestFailed(
                status: http.statusCode,
                code: err.code ?? "request_failed",
                message: err.message
                    ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode),
                requestId: err.requestId ?? requestId
            )
        }
        if T.self == EmptyResponse.self {
            return EmptyResponse() as! T
        }
        do {
            return try AuthioJSON.decoder.decode(T.self, from: data)
        } catch {
            throw AuthioError.decodeFailed(message: String(describing: error))
        }
    }

    /// Convenience for endpoints with no body.
    func send<T: Decodable>(
        _ method: String,
        _ path: String,
        bearer: String? = nil,
        extraHeaders: [String: String] = [:]
    ) async throws -> T {
        try await send(method, path, body: Optional<EmptyBody>.none, bearer: bearer, extraHeaders: extraHeaders)
    }
}

/// Stand-in for endpoints that return 202 / 204 / "{}".
public struct EmptyResponse: Decodable, Sendable {}

struct EmptyBody: Encodable {}

/// Authio's standard JSON error shape: `{code, message, request_id}`.
struct APIErrorEnvelope: Decodable {
    let code: String?
    let message: String?
    let requestId: String?

    enum CodingKeys: String, CodingKey {
        case code, message
        case requestId = "request_id"
    }
}
