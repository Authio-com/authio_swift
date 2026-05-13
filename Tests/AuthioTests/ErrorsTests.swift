import XCTest
@testable import Authio

final class ErrorsTests: XCTestCase {

    func testCodesAreStable() {
        // The strings in `.code` are PUBLIC contract; changing them is
        // a breaking change for callers branching on them. This test
        // pins them down.
        XCTAssertEqual(AuthioError.missingPublishableKey.code,
                       "missing_publishable_key")
        XCTAssertEqual(AuthioError.passkeyCancelled.code, "passkey_cancelled")
        XCTAssertEqual(AuthioError.missingMagicLinkToken.code,
                       "missing_magic_link_token")
        XCTAssertEqual(AuthioError.sessionExpired.code, "session_expired")
    }

    func testRequestFailedCarriesStatusAndRequestId() {
        let err = AuthioError.requestFailed(
            status: 429, code: "rate_limited",
            message: "Slow down", requestId: "req_abc123"
        )
        XCTAssertEqual(err.code, "rate_limited")
        switch err {
        case .requestFailed(let s, _, _, let rid):
            XCTAssertEqual(s, 429)
            XCTAssertEqual(rid, "req_abc123")
        default:
            XCTFail("wrong case")
        }
    }

    func testOAuthRejectedCarriesProviderCode() {
        let err = AuthioError.oauthRejected(code: "access_denied",
                                            description: "user said no")
        XCTAssertEqual(err.code, "access_denied")
    }
}
