// JwtVerifier.swift — local access-token verification against Authio JWKS.
//
// Mirrors @authio/node's JwtVerifier: fetch `/v1/auth/.well-known/jwks.json`,
// cache for 10 minutes, verify EdDSA signatures without a `/v1/me` round-trip.

import CryptoKit
import Foundation

private actor JWKSStore {
    var cachedAt: Date?
    var keysByKid: [String: Curve25519.Signing.PublicKey] = [:]

    func get(kid: String, maxAge: TimeInterval) -> Curve25519.Signing.PublicKey? {
        guard let cachedAt, Date().timeIntervalSince(cachedAt) < maxAge else { return nil }
        return keysByKid[kid]
    }

    func put(_ keys: [String: Curve25519.Signing.PublicKey]) {
        keysByKid = keys
        cachedAt = Date()
    }

    func staleSince() -> Date? { cachedAt }
}

/// Cached JWKS document + lookup by `kid`.
final class JwtVerifier: @unchecked Sendable {
    private let jwksURL: URL
    private let issuer: String
    private let audience: String
    private let cacheMaxAge: TimeInterval
    private let cooldown: TimeInterval
    private let session: URLSessionProtocol
    private let store = JWKSStore()

    init(
        apiURL: URL,
        issuer: String = "https://api.authio.com",
        audience: String = "authio",
        cacheMaxAge: TimeInterval = 600,
        cooldown: TimeInterval = 30,
        session: URLSessionProtocol = URLSession.shared
    ) {
        var base = apiURL.absoluteString
        while base.hasSuffix("/") { base.removeLast() }
        self.jwksURL = URL(string: base + "/v1/auth/.well-known/jwks.json")!
        self.issuer = issuer
        self.audience = audience
        self.cacheMaxAge = cacheMaxAge
        self.cooldown = cooldown
        self.session = session
    }

    /// Returns true when the JWT signature + standard claims are valid.
    func verify(accessToken: String) async throws -> Bool {
        let parts = accessToken.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { return false }

        let headerData = Data(base64URLEncoded: String(parts[0]))
        let payloadData = Data(base64URLEncoded: String(parts[1]))
        let sigData = Data(base64URLEncoded: String(parts[2]))
        guard let headerData, let payloadData, let sigData else { return false }

        guard
            let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
            let kid = header["kid"] as? String,
            let alg = header["alg"] as? String,
            alg == "EdDSA"
        else { return false }

        let signingInput = Data((String(parts[0]) + "." + String(parts[1])).utf8)
        let pubKey = try await publicKey(forKid: kid)
        guard pubKey.isValidSignature(sigData, for: signingInput) else { return false }

        guard
            let payload = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any]
        else { return false }

        if let iss = payload["iss"] as? String, iss != issuer { return false }
        if let aud = payload["aud"] as? String, aud != audience { return false }
        if let exp = payload["exp"] as? TimeInterval, Date(timeIntervalSince1970: exp) < Date() {
            return false
        }
        if payload["sub"] as? String == nil { return false }
        return true
    }

    private func publicKey(forKid kid: String) async throws -> Curve25519.Signing.PublicKey {
        if let cached = await store.get(kid: kid, maxAge: cacheMaxAge) {
            return cached
        }
        if let stale = await store.staleSince(),
           Date().timeIntervalSince(stale) < cooldown,
           await store.get(kid: kid, maxAge: .infinity) == nil {
            throw AuthioError.decodeFailed(message: "jwks kid not found")
        }

        var req = URLRequest(url: jwksURL)
        req.httpMethod = "GET"
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, response) = try await session.authioData(for: req)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw AuthioError.decodeFailed(message: "jwks fetch failed")
        }
        guard
            let doc = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let keys = doc["keys"] as? [[String: Any]]
        else {
            throw AuthioError.decodeFailed(message: "jwks parse failed")
        }

        var parsed: [String: Curve25519.Signing.PublicKey] = [:]
        for k in keys {
            guard
                let kid = k["kid"] as? String,
                let kty = k["kty"] as? String, kty == "OKP",
                let crv = k["crv"] as? String, crv == "Ed25519",
                let x = k["x"] as? String,
                let raw = Data(base64URLEncoded: x)
            else { continue }
            parsed[kid] = try Curve25519.Signing.PublicKey(rawRepresentation: raw)
        }

        await store.put(parsed)
        guard let key = parsed[kid] else {
            throw AuthioError.decodeFailed(message: "jwks kid not found")
        }
        return key
    }
}
