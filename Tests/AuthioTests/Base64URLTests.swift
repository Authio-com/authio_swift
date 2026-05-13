import XCTest
@testable import Authio

final class Base64URLTests: XCTestCase {

    func testRoundTrip() {
        let raw = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x12, 0x34])
        let encoded = raw.base64URLEncodedString()
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertFalse(encoded.contains("="))
        let decoded = Data(base64URLEncoded: encoded)
        XCTAssertEqual(decoded, raw)
    }

    func testKnownVectors() {
        // From RFC 4648 §10 (adapted to base64url).
        let cases: [(Data, String)] = [
            (Data("f".utf8),     "Zg"),
            (Data("fo".utf8),    "Zm8"),
            (Data("foo".utf8),   "Zm9v"),
            (Data("foob".utf8),  "Zm9vYg"),
            (Data("fooba".utf8), "Zm9vYmE"),
        ]
        for (raw, expected) in cases {
            XCTAssertEqual(raw.base64URLEncodedString(), expected,
                           "encoding \(raw) → expected \(expected)")
            XCTAssertEqual(Data(base64URLEncoded: expected), raw,
                           "decoding \(expected) → expected \(raw)")
        }
    }

    func testUrlSafeChars() {
        // 0xFB 0xFF → standard base64 "+/8=", url-safe "-_8".
        let raw = Data([0xFB, 0xFF])
        let encoded = raw.base64URLEncodedString()
        XCTAssertEqual(encoded, "-_8")
        XCTAssertEqual(Data(base64URLEncoded: encoded), raw)
    }

    func testInvalidInputReturnsNil() {
        XCTAssertNil(Data(base64URLEncoded: "!!!"))
        XCTAssertNil(Data(base64URLEncoded: "@@@"))
    }
}
