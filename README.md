# Authio.swift

Authio iOS / macOS SDK. Native passkey support (`ASAuthorizationPlatformPublicKeyCredentialProvider`), multi-org-first models.

## Install

Swift Package Manager:

```swift
.package(url: "https://github.com/tcast/authio_swift.git", from: "0.1.0")
```

## Quick start

```swift
import Authio

let authio = try Authio(apiKey: ProcessInfo.processInfo.environment["AUTHIO_SECRET_KEY"]!)
let memberships = try await authio.listMemberships(userId: "user_01HX...")
```

## License

MIT
