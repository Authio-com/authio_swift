// Base64URL.swift — WebAuthn speaks unpadded base64url everywhere; the
// platform passkey APIs hand us raw `Data`. This extension is the
// one-stop shop for encoding/decoding between the two.

import Foundation

extension Data {
    /// Initialise from a base64url-encoded string (RFC 4648 §5, no
    /// padding). Returns nil on invalid input.
    init?(base64URLEncoded input: String) {
        var s = input
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let pad = (4 - s.count % 4) % 4
        s.append(String(repeating: "=", count: pad))
        guard let data = Data(base64Encoded: s) else { return nil }
        self = data
    }

    /// Encode as unpadded base64url (the WebAuthn wire format).
    func base64URLEncodedString() -> String {
        return self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
