// Keychain.swift — small wrapper over Security framework's SecItem*
// APIs for storing/retrieving an `AuthioSession`.
//
// The service identifier is hardcoded to `com.authio.session`; callers
// pass an `account` label (default: "default") if their app stores
// multiple sessions (e.g. a "test" session alongside production).
//
// On macOS the access control attribute we use,
// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, is enough; on iOS
// we additionally bind to the current device. We deliberately do NOT
// set `kSecAttrAccessControl` — callers who need TouchID/biometric gate
// can post-process the load (call LocalAuthentication.LAContext first
// then load) without us forcing it on every read.

import Foundation
import Security

/// Encapsulates Keychain access. The default service id is
/// `com.authio.session`; override only when isolating multiple Authio
/// instances inside the same app (rare).
public struct AuthioKeychain: Sendable {
    public let service: String

    public init(service: String = "com.authio.session") {
        self.service = service
    }

    /// Persist `session` under `account`. Replaces any existing entry.
    public func store(_ session: AuthioSession, account: String = "default") throws {
        let data = try AuthioJSON.encoder.encode(session)
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let attrs: [String: Any] = [
            kSecValueData as String:      data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        var status = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var add = query
            add.merge(attrs) { _, new in new }
            status = SecItemAdd(add as CFDictionary, nil)
        }
        if status != errSecSuccess {
            throw AuthioError.keychainError(status: status)
        }
    }

    /// Returns the stored session for `account`, or nil if not present.
    public func load(account: String = "default") throws -> AuthioSession? {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String:  true,
            kSecMatchLimit as String:  kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        if status != errSecSuccess {
            throw AuthioError.keychainError(status: status)
        }
        guard let data = item as? Data else { return nil }
        do {
            return try AuthioJSON.decoder.decode(AuthioSession.self, from: data)
        } catch {
            throw AuthioError.decodeFailed(message: "keychain payload corrupt: \(error)")
        }
    }

    /// Removes the stored session. No-op if not present.
    public func delete(account: String = "default") throws {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw AuthioError.keychainError(status: status)
        }
    }
}
