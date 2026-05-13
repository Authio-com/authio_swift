# authio-swift

The official Swift SDK for [Authio](https://authio.com) — passwordless
authentication for iOS, macOS, and visionOS apps. Native passkeys via
`ASAuthorizationController`, magic links, OAuth (Google / Microsoft /
Apple / GitHub / GitLab / Slack / LinkedIn), and first-class multi-org
sessions — a single user identity can belong to many organizations and
switch between them in-session.

## Install

Add Authio to your Xcode project:

1. **File → Add Package Dependencies…**
2. Enter `https://github.com/tcast/authio_swift.git`
3. Pick the latest release.

Or in your `Package.swift`:

```swift
.package(url: "https://github.com/tcast/authio_swift.git", from: "0.2.0")
```

## Requirements

- **iOS 16+**, **macOS 13+**, **visionOS 1+**
- Swift 5.9 / Xcode 15+
- Zero external dependencies — only Apple's `Foundation`,
  `AuthenticationServices`, `Security`, and `CryptoKit`.

Passkeys require iOS 16+ / macOS 13+. Earlier OS versions are not
supported.

## Quickstart

```swift
import Authio
import AuthenticationServices

let authio = try Authio.Client(
    publishableKey: "pk_live_…",
    apiURL: URL(string: "https://api.authio.com")!
)

// Sign in with a passkey
let session = try await authio.signInWithPasskey(
    presentationAnchor: window  // any ASPresentationAnchor
)

// Persist the session in Keychain
try authio.keychain.store(session)

// Later: restore on launch
if let saved = try authio.keychain.load(),
   try await authio.verify(session: saved) {
    // user is still signed in
}
```

## Common flows

### Sign up a new user with passkey
```swift
let session = try await authio.signUpWithPasskey(
    email: "alice@example.com",
    presentationAnchor: window
)
```

### Magic link
```swift
// 1. Kick off the email/SMS
try await authio.sendMagicLink(
    destination: "alice@example.com",
    redirectURI: "myapp://auth-callback"
)

// 2. In your App / Scene's onOpenURL handler
.onOpenURL { url in
    Task {
        let session = try await authio.consumeMagicLinkCallback(url: url)
        try authio.keychain.store(session)
    }
}
```

### OAuth (system-managed in-app browser)
```swift
let session = try await authio.signInWithOAuth(
    provider: .google,
    redirectURI: "myapp://auth-callback",
    presentationAnchor: window
)
```

### Multi-organization

```swift
let memberships = try await authio.listMyOrganizations(session: session)
// Show a picker, then:
let updated = try await authio.switchOrganization(
    session: session,
    to: memberships[1].organizationId
)
try authio.keychain.store(updated)
```

### Sign out
```swift
try await authio.revokeSession(session)
```

## Error handling

Every fallible call throws `AuthioError`. Branch on `.code` (a stable
machine-readable string), not the message:

```swift
do {
    let session = try await authio.signInWithPasskey(presentationAnchor: window)
} catch let err as AuthioError {
    switch err.code {
    case "passkey_cancelled":
        // user dismissed the sheet
    case "rate_limited":
        // too many attempts; show a cooldown UI
    default:
        print("Authio error:", err)
    }
}
```

## Example app

See [`Examples/AuthioExampleSwiftUI`](Examples/AuthioExampleSwiftUI) for
a complete SwiftUI implementation showing passkey sign-in, magic-link
deep-link handling, Keychain persistence, multi-org switching, and
sign-out.

## Security notes

- The SDK only carries the project's **publishable key** (`pk_…`).
  Server-side CRUD on users, organizations, webhooks, etc. requires a
  `sk_live_` secret key and runs through the [Management
  API](https://docs.authio.com/management-api) — never embed secret
  keys in a mobile app.
- Sessions are stored under
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` by default. If you
  need biometric gating, wrap `keychain.load()` with a
  `LAContext.evaluatePolicy` check before unlocking the session.
- Access tokens are short-lived (15 min). On expiry, the SDK currently
  asks the user to re-authenticate. Local JWT verification + refresh
  via JWKS is on the roadmap.

## Testing

```bash
swift test
```

The passkey ceremony itself can't be unit-tested in a CLI test
environment — it needs a real authenticator. The example app is the
end-to-end harness; everything else (model decoding, base64url,
HTTP request shape, error mapping, Keychain round-trip) is covered.

## License

MIT — see [LICENSE](LICENSE).
