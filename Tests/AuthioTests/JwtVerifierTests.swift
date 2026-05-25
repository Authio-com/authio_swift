import CryptoKit
import XCTest
@testable import Authio

final class JwtVerifierTests: XCTestCase {

    func testVerifyValidEdDSAToken() async throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let kid = "test_kid"
        let x = publicKey.rawRepresentation.base64URLEncodedString()

        let headerJSON = #"{"alg":"EdDSA","kid":"test_kid","typ":"JWT"}"#
        let payloadJSON = #"{"sub":"user_1","iss":"https://api.authio.com","aud":"authio","exp":4102444800}"#
        let header = Data(headerJSON.utf8).base64URLEncodedString()
        let payload = Data(payloadJSON.utf8).base64URLEncodedString()
        let signingInput = Data((header + "." + payload).utf8)
        let sig = try privateKey.signature(for: signingInput).base64URLEncodedString()
        let token = header + "." + payload + "." + sig

        let mock = MockURLSession()
        let jwks = """
        {"keys":[{"kty":"OKP","crv":"Ed25519","kid":"test_kid","x":"\(x)","alg":"EdDSA"}]}
        """.data(using: .utf8)!
        mock.responses = [(200, jwks)]

        let verifier = JwtVerifier(
            apiURL: URL(string: "https://api.authio.com")!,
            session: mock
        )
        let ok = try await verifier.verify(accessToken: token)
        XCTAssertTrue(ok)
        XCTAssertEqual(mock.requests.count, 1)
        XCTAssertEqual(mock.requests.first?.url?.path, "/v1/auth/.well-known/jwks.json")
    }

    func testVerifyRejectsExpiredToken() async throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let x = publicKey.rawRepresentation.base64URLEncodedString()

        let header = Data(#"{"alg":"EdDSA","kid":"k1","typ":"JWT"}"#.utf8).base64URLEncodedString()
        let payload = Data(#"{"sub":"u","iss":"https://api.authio.com","aud":"authio","exp":1}"#.utf8)
            .base64URLEncodedString()
        let signingInput = Data((header + "." + payload).utf8)
        let sig = try privateKey.signature(for: signingInput).base64URLEncodedString()
        let token = header + "." + payload + "." + sig

        let mock = MockURLSession()
        mock.responses = [(200, Data("""
        {"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"\(x)","alg":"EdDSA"}]}
        """.utf8))]
        let verifier = JwtVerifier(apiURL: URL(string: "https://api.authio.com")!, session: mock)
        let ok = try await verifier.verify(accessToken: token)
        XCTAssertFalse(ok)
    }
}
