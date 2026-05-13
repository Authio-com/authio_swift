// Errors.swift — the typed error surface for the SDK.

import Foundation

/// Every fallible `Authio.Client` call throws `AuthioError`. Always
/// branch on `.code` (a stable machine-readable string) rather than the
/// message (which may change).
public enum AuthioError: Error, Equatable, Sendable {
    /// SDK was constructed without a publishable key.
    case missingPublishableKey
    /// The hosted-UI redirect handed back an error rather than a token.
    case oauthRejected(code: String, description: String?)
    /// Native passkey ceremony cancelled by the user, or the platform
    /// authenticator is unavailable on this device.
    case passkeyCancelled
    /// Some other passkey/WebAuthn error from the OS APIs.
    case passkeyFailed(message: String)
    /// The server returned a non-2xx response.
    case requestFailed(status: Int, code: String, message: String, requestId: String?)
    /// The response couldn't be decoded as the expected shape.
    case decodeFailed(message: String)
    /// Magic-link callback URL didn't carry a `token` query param.
    case missingMagicLinkToken
    /// Keychain SecItem* returned a non-success status.
    case keychainError(status: OSStatus)
    /// The session token has expired locally (exp < now).
    case sessionExpired
}

extension AuthioError {
    /// Stable string code for branching in caller logic.
    public var code: String {
        switch self {
        case .missingPublishableKey:           return "missing_publishable_key"
        case .oauthRejected(let c, _):         return c
        case .passkeyCancelled:                return "passkey_cancelled"
        case .passkeyFailed:                   return "passkey_failed"
        case .requestFailed(_, let c, _, _):   return c
        case .decodeFailed:                    return "decode_failed"
        case .missingMagicLinkToken:           return "missing_magic_link_token"
        case .keychainError:                   return "keychain_error"
        case .sessionExpired:                  return "session_expired"
        }
    }
}
