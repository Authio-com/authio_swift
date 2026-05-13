// JSON.swift — shared JSONEncoder / JSONDecoder configured to match
// Authio's REST contract:
//   * snake_case keys on the wire ↔ camelCase in Swift
//   * RFC3339 with fractional seconds for timestamps
//
// Built-in `.convertFromSnakeCase` would handle the snake-to-camel
// mapping, except some structs (SessionEnvelopeDTO, PasskeyOptionsDTO)
// declare explicit CodingKeys because of WebAuthn-specific fields whose
// generic conversion would mangle them (e.g. `pubKeyCredParams` →
// `pubKeyCredParams` not `pub_key_cred_params`). To avoid two different
// decoders, those types are written WITH explicit CodingKeys and the
// shared decoder leaves keyDecodingStrategy alone.

import Foundation

enum AuthioJSON {
    // Two-track approach (intentional):
    //
    // * Authio's REST envelope is snake_case (`session_id`, `access_token`)
    // * WebAuthn payloads are camelCase per the W3C spec
    //   (`clientDataJSON`, `rawId`)
    //
    // Earlier versions of this file tried `keyEncodingStrategy =
    // .convertToSnakeCase` — that's a global override that mangles
    // WebAuthn keys (`rawId` → `raw_id`) and can't be opted out of per
    // call. Explicit `CodingKeys` on every wire type is more verbose
    // but ambiguity-free.
    static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601withFractional
        return e
    }()

    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601withFractional
        return d
    }()
}

extension JSONEncoder.DateEncodingStrategy {
    static let iso8601withFractional: JSONEncoder.DateEncodingStrategy = .custom { date, enc in
        let fmt = ISO8601DateFormatter()
        fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        var c = enc.singleValueContainer()
        try c.encode(fmt.string(from: date))
    }
}

extension JSONDecoder.DateDecodingStrategy {
    /// Accept either RFC3339 with or without fractional seconds. The
    /// server emits fractional, but tests pin plain ISO too so we don't
    /// brittle-fail on either format.
    static let iso8601withFractional: JSONDecoder.DateDecodingStrategy = .custom { dec in
        let c = try dec.singleValueContainer()
        let s = try c.decode(String.self)
        let withFrac = ISO8601DateFormatter()
        withFrac.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = withFrac.date(from: s) { return d }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        if let d = plain.date(from: s) { return d }
        throw DecodingError.dataCorruptedError(
            in: c, debugDescription: "not a valid RFC3339 date: \(s)"
        )
    }
}
