#if canImport(AuthenticationServices) && (os(iOS) || os(macOS) || os(visionOS))
import XCTest
@testable import Authio

final class OAuthCallbackTests: XCTestCase {

    func testParseSuccessfulCallback() throws {
        let c = try Authio.Client(
            publishableKey: "pk_test_x",
            apiURL: URL(string: "https://api.authio.com")!,
            session: MockURLSession()
        )
        let url = URL(string:
            "myapp://cb?access_token=tok123&session_id=sess_oauth" +
            "&user_id=user_oauth&org_id=org_1&role=member&expires_in=900"
        )!
        let session = try c.parseOAuthCallback(url)
        XCTAssertEqual(session.accessToken, "tok123")
        XCTAssertEqual(session.sessionId,   "sess_oauth")
        XCTAssertEqual(session.userId,      "user_oauth")
        XCTAssertEqual(session.orgId,       "org_1")
        XCTAssertEqual(session.role,        "member")
        XCTAssertGreaterThan(session.expiresAt, Date())
    }

    func testParseProviderRejection() throws {
        let c = try Authio.Client(
            publishableKey: "pk_test_x",
            apiURL: URL(string: "https://api.authio.com")!,
            session: MockURLSession()
        )
        let url = URL(string:
            "myapp://cb?error=access_denied&error_description=user%20cancelled"
        )!
        XCTAssertThrowsError(try c.parseOAuthCallback(url)) { err in
            guard let authio = err as? AuthioError else {
                XCTFail("not AuthioError"); return
            }
            XCTAssertEqual(authio.code, "access_denied")
        }
    }

    func testParseMissingTokens() throws {
        let c = try Authio.Client(
            publishableKey: "pk_test_x",
            apiURL: URL(string: "https://api.authio.com")!,
            session: MockURLSession()
        )
        // No access_token, no error → "missing_tokens".
        let url = URL(string: "myapp://cb?state=xyz")!
        XCTAssertThrowsError(try c.parseOAuthCallback(url)) { err in
            XCTAssertEqual((err as? AuthioError)?.code, "missing_tokens")
        }
    }
}
#endif
