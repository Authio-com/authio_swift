// Keychain integration tests. They use a randomised service identifier
// per test so we don't pollute the user's default keychain — the entries
// are scoped to test runs and cleaned up afterward.

import XCTest
@testable import Authio

final class KeychainTests: XCTestCase {

    var keychain: AuthioKeychain!

    override func setUp() {
        super.setUp()
        keychain = AuthioKeychain(service: "com.authio.session.tests.\(UUID().uuidString)")
    }

    override func tearDown() {
        try? keychain.delete()
        super.tearDown()
    }

    func testStoreLoadRoundTrip() throws {
        let session = AuthioSession(
            sessionId: "sess_x", userId: "user_x",
            orgId: "org_x", role: "admin",
            accessToken: "tok", refreshToken: "rt",
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000)
        )
        try keychain.store(session)
        let loaded = try XCTUnwrap(try keychain.load())
        XCTAssertEqual(loaded, session)
    }

    func testLoadMissingReturnsNil() throws {
        XCTAssertNil(try keychain.load(account: "does-not-exist"))
    }

    func testDeleteIsIdempotent() throws {
        // Calling delete twice in a row shouldn't throw.
        try keychain.delete()
        try keychain.delete()
    }

    func testReplaceOverwrites() throws {
        let s1 = AuthioSession(
            sessionId: "s1", userId: "u", orgId: nil, role: nil,
            accessToken: "t1", refreshToken: nil, expiresAt: Date()
        )
        let s2 = AuthioSession(
            sessionId: "s2", userId: "u", orgId: nil, role: nil,
            accessToken: "t2", refreshToken: nil, expiresAt: Date()
        )
        try keychain.store(s1)
        try keychain.store(s2)
        let loaded = try XCTUnwrap(try keychain.load())
        XCTAssertEqual(loaded.sessionId, "s2")
    }
}
