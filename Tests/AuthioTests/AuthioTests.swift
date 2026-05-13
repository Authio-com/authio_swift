import XCTest
@testable import Authio

final class AuthioTests: XCTestCase {
    func testMissingApiKey() {
        XCTAssertThrowsError(try Authio(apiKey: ""))
    }

    func testConstructWithApiKey() throws {
        let c = try Authio(apiKey: "sk_test_x")
        XCTAssertEqual(c.apiKey, "sk_test_x")
        XCTAssertEqual(c.baseURL.absoluteString, "https://api.authio.com")
    }
}
