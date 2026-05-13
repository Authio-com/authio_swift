// SignInView.swift — the "out" state. Three buttons:
//   1. "Sign in with passkey" (discoverable credential picker)
//   2. "Sign up with passkey" (collects email first)
//   3. "Send magic link" (collects email first)

#if canImport(SwiftUI) && (os(iOS) || os(macOS) || os(visionOS))

import SwiftUI
import AuthenticationServices
import Authio

@available(iOS 16, macOS 13, visionOS 1, *)
@MainActor
struct SignInView: View {
    @ObservedObject var store: AuthioStore
    @State private var email = ""
    @State private var didSendMagicLink = false

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "key.fill")
                .font(.system(size: 48))
                .foregroundStyle(.tint)
            Text("Welcome back").font(.title.bold())
            Text("Sign in with your passkey, or get a magic link emailed to you.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .padding(.horizontal)

            VStack(spacing: 12) {
                AnchorButton("Sign in with passkey") { anchor in
                    await store.signInWithPasskey(anchor: anchor)
                }

                Divider()

                TextField("you@example.com", text: $email)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    #if os(iOS) || os(visionOS)
                    .keyboardType(.emailAddress)
                    .textInputAutocapitalization(.never)
                    #endif

                AnchorButton("Sign up with new passkey",
                             tint: .blue.opacity(0.85)) { anchor in
                    await store.signUpWithPasskey(email: email, anchor: anchor)
                }

                Button(didSendMagicLink ? "Magic link sent ✓" : "Send magic link") {
                    Task {
                        do {
                            try await store.client.sendMagicLink(
                                destination: email,
                                redirectURI: AuthioExampleConfig.redirectURI
                            )
                            didSendMagicLink = true
                        } catch {
                            store.lastError = String(describing: error)
                        }
                    }
                }
                .disabled(email.isEmpty || didSendMagicLink)
            }
            .padding()

            if let err = store.lastError {
                Text(err)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .padding(.horizontal)
            }
        }
        .padding()
    }
}

/// Button helper that resolves the platform's presentation anchor and
/// passes it to the supplied callback. ASAuthorization APIs require an
/// ASPresentationAnchor; this hides the per-platform fetch.
@available(iOS 16, macOS 13, visionOS 1, *)
struct AnchorButton: View {
    let title: String
    var tint: Color = .accentColor
    let action: (ASPresentationAnchor) async -> Void

    init(_ title: String,
         tint: Color = .accentColor,
         action: @escaping (ASPresentationAnchor) async -> Void) {
        self.title = title
        self.tint = tint
        self.action = action
    }

    var body: some View {
        Button(title) {
            Task {
                let anchor = await resolveAnchor()
                await action(anchor)
            }
        }
        .buttonStyle(.borderedProminent)
        .tint(tint)
    }

    @MainActor
    private func resolveAnchor() async -> ASPresentationAnchor {
        #if os(iOS) || os(visionOS)
        if let scene = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene }).first,
           let window = scene.windows.first {
            return window
        }
        return ASPresentationAnchor()
        #elseif os(macOS)
        return NSApplication.shared.keyWindow ?? ASPresentationAnchor()
        #endif
    }
}

#endif
