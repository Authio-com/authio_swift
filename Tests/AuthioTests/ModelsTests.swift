import XCTest
@testable import Authio

final class ModelsTests: XCTestCase {

    func testAuthioSessionRoundTrip() throws {
        let original = AuthioSession(
            sessionId: "sess_123",
            userId: "user_456",
            orgId: "org_789",
            role: "admin",
            accessToken: "jwt.value.here",
            refreshToken: "rt_abc",
            expiresAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let data = try AuthioJSON.encoder.encode(original)
        let decoded = try AuthioJSON.decoder.decode(AuthioSession.self, from: data)
        XCTAssertEqual(decoded, original)
    }

    func testAuthioSessionSnakeCaseOnWire() throws {
        let session = AuthioSession(
            sessionId: "sess_1", userId: "u_1", orgId: nil, role: nil,
            accessToken: "tok", refreshToken: nil,
            expiresAt: Date(timeIntervalSince1970: 0)
        )
        let data = try AuthioJSON.encoder.encode(session)
        let json = try XCTUnwrap(String(data: data, encoding: .utf8))
        XCTAssertTrue(json.contains("\"session_id\""), "expected snake_case: \(json)")
        XCTAssertTrue(json.contains("\"access_token\""), "expected snake_case: \(json)")
        XCTAssertTrue(json.contains("\"expires_at\""), "expected snake_case: \(json)")
        XCTAssertFalse(json.contains("\"sessionId\""))
    }

    func testSessionEnvelopeDTODecode() throws {
        let json = """
        {
          "session_id": "sess_99",
          "access_token": "tok_xyz",
          "refresh_token": "rt_xyz",
          "expires_at": "2030-01-01T00:00:00.000Z",
          "user": {
            "id": "user_1",
            "project_id": "proj_1",
            "email": "x@y.com",
            "email_verified": true
          },
          "active_organization": {
            "id": "org_1",
            "project_id": "proj_1",
            "name": "Acme",
            "slug": "acme"
          },
          "active_role": "owner"
        }
        """.data(using: .utf8)!

        let env = try AuthioJSON.decoder.decode(SessionEnvelopeDTO.self, from: json)
        let session = env.toSession()
        XCTAssertEqual(session.sessionId, "sess_99")
        XCTAssertEqual(session.accessToken, "tok_xyz")
        XCTAssertEqual(session.userId, "user_1")
        XCTAssertEqual(session.orgId, "org_1")
        XCTAssertEqual(session.role, "owner")
    }

    func testMembershipDecode() throws {
        let json = """
        {
          "id": "mem_1",
          "project_id": "proj_1",
          "user_id": "user_1",
          "organization_id": "org_1",
          "role": "admin",
          "status": "active"
        }
        """.data(using: .utf8)!
        let mem = try AuthioJSON.decoder.decode(Membership.self, from: json)
        XCTAssertEqual(mem.organizationId, "org_1")
        XCTAssertEqual(mem.status, .active)
    }

    func testMembershipStatusUnknownIsLenient() {
        let json = """
        {"id":"x","project_id":"p","user_id":"u","organization_id":"o","role":"r","status":"banned"}
        """.data(using: .utf8)!
        // We choose to fail closed: unrecognised statuses throw rather
        // than silently mapping to .deactivated. This catches schema
        // drift before it becomes a security bug.
        XCTAssertThrowsError(try AuthioJSON.decoder.decode(Membership.self, from: json))
    }

    func testPasskeyOptionsDTODecodeLogin() throws {
        let json = """
        {
          "publicKey": {
            "challenge": "Y2hhbGxlbmdl",
            "rpId": "auth.example.com",
            "allowCredentials": [
              {"type": "public-key", "id": "Y3JlZF8x", "transports": ["internal"]}
            ],
            "userVerification": "preferred",
            "timeout": 60000
          }
        }
        """.data(using: .utf8)!
        let opts = try JSONDecoder().decode(PasskeyOptionsDTO.self, from: json)
        XCTAssertEqual(opts.publicKey.rpId, "auth.example.com")
        XCTAssertEqual(opts.publicKey.allowCredentials?.count, 1)
        XCTAssertEqual(opts.publicKey.allowCredentials?.first?.id, "Y3JlZF8x")
    }

    func testPasskeyOptionsDTODecodeRegister() throws {
        let json = """
        {
          "publicKey": {
            "challenge": "Y2hhbGw",
            "rp": {"id": "auth.example.com", "name": "Acme"},
            "user": {"id": "dXNlcl8x", "name": "alice@example.com", "displayName": "Alice"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {
              "userVerification": "required",
              "residentKey": "preferred"
            }
          }
        }
        """.data(using: .utf8)!
        let opts = try JSONDecoder().decode(PasskeyOptionsDTO.self, from: json)
        XCTAssertEqual(opts.publicKey.rp?.id, "auth.example.com")
        XCTAssertEqual(opts.publicKey.user?.name, "alice@example.com")
        XCTAssertEqual(opts.publicKey.pubKeyCredParams?.first?.alg, -7)
    }
}
