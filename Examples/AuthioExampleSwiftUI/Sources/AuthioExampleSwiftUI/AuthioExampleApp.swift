// AuthioExampleApp.swift — SwiftUI app entry point.
//
// This file isn't built as an executable here (the example is a library
// target so it compiles on any platform). Drop it into an Xcode iOS App
// target to actually run it.

#if canImport(SwiftUI) && (os(iOS) || os(macOS) || os(visionOS))

import SwiftUI
import Authio

/// Production: replace with your project's `pk_live_…` publishable key.
/// Dev/staging: use a `pk_test_…` key against `https://api.authio.com`
/// or your local auth-core.
public enum AuthioExampleConfig {
    public static let publishableKey =
        ProcessInfo.processInfo.environment["AUTHIO_PUBLISHABLE_KEY"]
        ?? "pk_test_REPLACE_ME"
    public static let apiURL =
        URL(string: ProcessInfo.processInfo.environment["AUTHIO_API_URL"]
                    ?? "https://api.authio.com")!
    /// Your app's custom URL scheme for deep-link callbacks. Register
    /// this in Info.plist (`CFBundleURLTypes`).
    public static let redirectURI = "authioexample://auth-callback"
}

/// Shared Authio client. Made `@MainActor` to keep SwiftUI usage simple
/// — every public method is async and threadsafe regardless.
@MainActor
public final class AuthioStore: ObservableObject {

    @Published public var session: AuthioSession?
    @Published public var memberships: [MembershipWithOrg] = []
    @Published public var lastError: String?

    public let client: Authio.Client

    public init() throws {
        self.client = try Authio.Client(
            publishableKey: AuthioExampleConfig.publishableKey,
            apiURL: AuthioExampleConfig.apiURL
        )
        // Restore any saved session from Keychain on launch.
        self.session = (try? self.client.keychain.load()) ?? nil
    }

    public func signInWithPasskey(anchor: ASPresentationAnchor) async {
        do {
            let s = try await client.signInWithPasskey(presentationAnchor: anchor)
            try? client.keychain.store(s)
            self.session = s
            await loadOrganizations()
        } catch {
            self.lastError = String(describing: error)
        }
    }

    public func signUpWithPasskey(email: String, anchor: ASPresentationAnchor) async {
        do {
            let s = try await client.signUpWithPasskey(
                email: email, presentationAnchor: anchor
            )
            try? client.keychain.store(s)
            self.session = s
            await loadOrganizations()
        } catch {
            self.lastError = String(describing: error)
        }
    }

    public func loadOrganizations() async {
        guard let s = session else { return }
        do {
            self.memberships = try await client.listMyOrganizations(session: s)
        } catch {
            self.lastError = String(describing: error)
        }
    }

    public func switchOrg(_ orgId: String) async {
        guard let s = session else { return }
        do {
            let updated = try await client.switchOrganization(session: s, to: orgId)
            try? client.keychain.store(updated)
            self.session = updated
        } catch {
            self.lastError = String(describing: error)
        }
    }

    public func signOut() async {
        guard let s = session else { return }
        try? await client.revokeSession(s)
        self.session = nil
        self.memberships = []
    }

    public func handleDeepLink(_ url: URL) async {
        do {
            let s = try await client.consumeMagicLinkCallback(url: url)
            try? client.keychain.store(s)
            self.session = s
            await loadOrganizations()
        } catch {
            self.lastError = String(describing: error)
        }
    }
}

import AuthenticationServices

@available(iOS 16, macOS 13, visionOS 1, *)
@MainActor
public struct AuthioExampleRootView: View {
    @StateObject var store: AuthioStore

    public init(store: AuthioStore) {
        _store = StateObject(wrappedValue: store)
    }

    public var body: some View {
        Group {
            if store.session != nil {
                SignedInView(store: store)
            } else {
                SignInView(store: store)
            }
        }
        .onOpenURL { url in
            Task { await store.handleDeepLink(url) }
        }
    }
}

#endif
