// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Authio",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "Authio", targets: ["Authio"]),
    ],
    targets: [
        .target(
            name: "Authio",
            path: "Sources/Authio"
        ),
        .testTarget(
            name: "AuthioTests",
            dependencies: ["Authio"],
            path: "Tests/AuthioTests"
        ),
    ]
)
