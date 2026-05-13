// Passkey ceremony tests would need to drive the OS-level authenticator,
// which isn't reachable from `swift test` (no UI test bundle, no real
// keychain prompt). We skip with a clear message rather than silently
// pass — running the example app on a real device is the only way to
// exercise the full passkey flow.

import XCTest
@testable import Authio

final class PasskeyCeremonySkippedTests: XCTestCase {

    func testPasskeyCeremonyRequiresUITestBundle() throws {
        throw XCTSkip("""
        The native passkey ceremony cannot be unit-tested in the swift-test \
        environment — it requires a real iOS/macOS authenticator and an \
        UI test target that can interact with the system passkey sheet.

        To verify end-to-end, open `Examples/AuthioExampleSwiftUI` in Xcode, \
        run on a device with passkey support, and watch the sign-in button \
        return a valid AuthioSession.

        The non-UI parts of the passkey flow (options decoding, base64url \
        round-trips, verify request shape) ARE covered by ModelsTests and \
        Base64URLTests.
        """)
    }
}
