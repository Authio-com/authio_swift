import XCTest
@testable import Authio

final class ClientTests: XCTestCase {

    func testInitRejectsEmptyPublishableKey() {
        XCTAssertThrowsError(try Authio.Client(publishableKey: "")) { err in
            XCTAssertEqual((err as? AuthioError)?.code, "missing_publishable_key")
        }
    }

    func testInitAcceptsCustomBaseURL() throws {
        let mock = MockURLSession()
        let c = try Authio.Client(
            publishableKey: "pk_test_xyz",
            apiURL: URL(string: "https://custom.example.com/")!,
            session: mock
        )
        XCTAssertEqual(c.http.publishableKey, "pk_test_xyz")
        // baseURL stored without trailing slash so path concatenation
        // doesn't double up.
        XCTAssertEqual(c.http.baseURL.absoluteString, "https://custom.example.com")
    }

    func testSendMagicLinkRequestShape() async throws {
        let mock = MockURLSession()
        mock.responses = [(202, Data("{}".utf8))]
        let c = try Authio.Client(
            publishableKey: "pk_live_abc",
            apiURL: URL(string: "https://api.authio.com")!,
            session: mock
        )
        try await c.sendMagicLink(
            destination: "alice@example.com",
            redirectURI: "myapp://callback"
        )
        let req = try XCTUnwrap(mock.requests.first)
        XCTAssertEqual(req.httpMethod, "POST")
        XCTAssertEqual(req.url?.path, "/v1/auth/magic-link/send")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Content-Type"), "application/json")
        XCTAssertEqual(req.value(forHTTPHeaderField: "X-Authio-Publishable-Key"), "pk_live_abc")
        let body = try XCTUnwrap(req.httpBody)
        let parsed = try XCTUnwrap(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(parsed["destination"] as? String, "alice@example.com")
        XCTAssertEqual(parsed["redirect_uri"] as? String, "myapp://callback")
    }

    func testConsumeMagicLinkCallbackParsesEnvelope() async throws {
        let mock = MockURLSession()
        let body = """
        {
          "session_id": "sess_mlc",
          "access_token": "tok_xyz",
          "refresh_token": null,
          "expires_at": "2030-01-01T00:00:00.000Z",
          "user": {
            "id": "user_x", "project_id": "p", "email": "x@y.com", "email_verified": true
          }
        }
        """.data(using: .utf8)!
        mock.responses = [(200, body)]
        let c = try Authio.Client(
            publishableKey: "pk_test_x",
            apiURL: URL(string: "https://api.authio.com")!,
            session: mock
        )
        let url = URL(string: "myapp://callback?token=ONE_TIME_TOKEN")!
        let session = try await c.consumeMagicLinkCallback(url: url)
        XCTAssertEqual(session.sessionId, "sess_mlc")
        XCTAssertEqual(session.accessToken, "tok_xyz")
        XCTAssertEqual(session.userId, "user_x")

        let req = try XCTUnwrap(mock.requests.first)
        XCTAssertEqual(req.httpMethod, "GET")
        XCTAssertEqual(req.url?.absoluteString,
                       "https://api.authio.com/v1/auth/magic-link/callback?token=ONE_TIME_TOKEN")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Accept"), "application/json")
    }

    func testConsumeMagicLinkCallbackMissingToken() async throws {
        let c = try Authio.Client(
            publishableKey: "pk_test_x",
            apiURL: URL(string: "https://api.authio.com")!,
            session: MockURLSession()
        )
        do {
            _ = try await c.consumeMagicLinkCallback(
                url: URL(string: "myapp://callback")!
            )
            XCTFail("expected throw")
        } catch let err as AuthioError {
            XCTAssertEqual(err.code, "missing_magic_link_token")
        }
    }

    func testServerErrorMappedToAuthioError() async throws {
        let mock = MockURLSession()
        let body = """
        {"code":"rate_limited","message":"slow down","request_id":"req_42"}
        """.data(using: .utf8)!
        mock.responses = [(429, body)]
        let c = try Authio.Client(
            publishableKey: "pk_test_x",
            apiURL: URL(string: "https://api.authio.com")!,
            session: mock
        )
        do {
            try await c.sendMagicLink(
                destination: "x@y.com", redirectURI: "app://x"
            )
            XCTFail("expected throw")
        } catch let err as AuthioError {
            switch err {
            case .requestFailed(let s, let code, _, let rid):
                XCTAssertEqual(s, 429)
                XCTAssertEqual(code, "rate_limited")
                XCTAssertEqual(rid, "req_42")
            default:
                XCTFail("wrong case: \(err)")
            }
        }
    }

    func testSwitchOrganizationSendsCorrectBody() async throws {
        let mock = MockURLSession()
        let body = """
        {
          "session_id": "sess_new",
          "access_token": "tok_new",
          "expires_at": "2030-01-01T00:00:00.000Z",
          "user": {"id": "user_1","project_id":"p","email":"x@y","email_verified":true},
          "active_organization": {"id":"org_target","project_id":"p","name":"X","slug":"x"},
          "active_role": "admin"
        }
        """.data(using: .utf8)!
        mock.responses = [(200, body)]
        let c = try Authio.Client(
            publishableKey: "pk_test_x",
            apiURL: URL(string: "https://api.authio.com")!,
            session: mock
        )
        let stored = AuthioSession(
            sessionId: "old", userId: "user_1", orgId: nil, role: nil,
            accessToken: "tok_old", refreshToken: nil,
            expiresAt: Date().addingTimeInterval(900)
        )
        let updated = try await c.switchOrganization(session: stored, to: "org_target")
        XCTAssertEqual(updated.orgId, "org_target")
        XCTAssertEqual(updated.accessToken, "tok_new")

        let req = try XCTUnwrap(mock.requests.first)
        XCTAssertEqual(req.httpMethod, "POST")
        XCTAssertEqual(req.url?.path, "/v1/sessions/select-org")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer tok_old")
        let parsed = try XCTUnwrap(try JSONSerialization.jsonObject(with: req.httpBody!) as? [String: Any])
        XCTAssertEqual(parsed["organization_id"] as? String, "org_target")
    }

    func testVerifyFastPathOnExpiredSession() async throws {
        let mock = MockURLSession()
        let c = try Authio.Client(
            publishableKey: "pk_test_x",
            apiURL: URL(string: "https://api.authio.com")!,
            session: mock
        )
        let expired = AuthioSession(
            sessionId: "s", userId: "u", orgId: nil, role: nil,
            accessToken: "t", refreshToken: nil,
            expiresAt: Date(timeIntervalSinceNow: -3600)
        )
        let ok = try await c.verify(session: expired)
        XCTAssertFalse(ok)
        // Crucially: NO network call should have happened — fast path
        // is a local-only check on `expiresAt`.
        XCTAssertEqual(mock.requests.count, 0)
    }
}
