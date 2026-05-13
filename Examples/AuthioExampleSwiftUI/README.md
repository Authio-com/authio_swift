# AuthioExampleSwiftUI

A minimal SwiftUI example demonstrating the Authio Swift SDK.

## What it shows

- **Passkey sign-in** with the OS-native passkey picker (`ASAuthorizationController`).
- **Passkey sign-up** with email, creating a new credential on the device.
- **Magic-link send + deep-link handling** — kick off `sendMagicLink`,
  let the user tap the link in their inbox, your app receives the
  callback URL via `onOpenURL` and `consumeMagicLinkCallback` exchanges
  it for an `AuthioSession`.
- **Keychain persistence** — saved session is restored on launch.
- **Multi-org switching** — when the signed-in user belongs to more than
  one org, the signed-in view shows a picker and calls
  `switchOrganization` on tap.
- **Sign-out** — revokes the session server-side and wipes Keychain.

## Run it

1. Open `Package.swift` from this folder in Xcode.
2. Add a new iOS App (or macOS, or visionOS) target. SwiftUI Lifecycle.
3. Drop the files in `Sources/AuthioExampleSwiftUI/` into the new target.
4. Link the `Authio` Swift Package (the parent `authio_swift` folder).
5. In your app's `Info.plist`, register a URL scheme so the magic-link
   callback works:
   ```
   <key>CFBundleURLTypes</key>
   <array>
     <dict>
       <key>CFBundleURLSchemes</key>
       <array><string>authioexample</string></array>
     </dict>
   </array>
   ```
6. Set `AUTHIO_PUBLISHABLE_KEY` in the scheme's environment, or replace
   the default in `AuthioExampleApp.swift`.
7. Run on a physical device — the Simulator doesn't have a real
   authenticator. iOS 16+ / macOS 13+ required for passkeys.

## Wire-up sketch

```swift
@main
struct MyApp: App {
    @State var store = (try? AuthioStore()) ?? defaultStore
    var body: some Scene {
        WindowGroup {
            AuthioExampleRootView(store: store)
        }
    }
}
```
