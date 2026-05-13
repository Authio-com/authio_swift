// swift-tools-version:5.9
//
// AuthioExampleSwiftUI — a working SwiftUI example for the Authio
// Swift SDK. This is structured as a sibling Swift Package (not a
// target inside the SDK package) so the SDK has no SwiftUI dependency
// of its own.
//
// To run on a real device:
//   1. open Package.swift in Xcode
//   2. add an iOS App target, drop SignInView etc. into it
//   3. add the Authio package (this folder's parent) as a Swift Package
//   4. set your project's pk_live_... key in `AuthioExampleApp.swift`
//
// To verify it at least compiles cleanly: `swift build` from this dir.

import PackageDescription

let package = Package(
    name: "AuthioExampleSwiftUI",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "AuthioExampleSwiftUI", targets: ["AuthioExampleSwiftUI"]),
    ],
    dependencies: [
        .package(path: "../.."),
    ],
    targets: [
        .target(
            name: "AuthioExampleSwiftUI",
            dependencies: [
                .product(name: "Authio", package: "authio_swift"),
            ],
            path: "Sources/AuthioExampleSwiftUI"
        ),
    ]
)
