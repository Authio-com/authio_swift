// Test-only stand-in for `URLSessionProtocol`. Captures the request
// the SDK sent, plays back a canned response. Lets tests assert on the
// full request shape (method, headers, body, URL) without a live
// network.

import Foundation
@testable import Authio

final class MockURLSession: URLSessionProtocol, @unchecked Sendable {

    /// One programmed response per call.
    var responses: [(statusCode: Int, body: Data)] = []
    /// Captures of every request that came through.
    var requests: [URLRequest] = []
    /// If non-nil, the next call throws this error.
    var nextError: Error?

    func authioData(for request: URLRequest) async throws -> (Data, URLResponse) {
        requests.append(request)
        if let nextError {
            self.nextError = nil
            throw nextError
        }
        let r: (statusCode: Int, body: Data) =
            responses.isEmpty
            ? (200, Data("{}".utf8))
            : responses.removeFirst()
        let http = HTTPURLResponse(
            url: request.url!,
            statusCode: r.statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        return (r.body, http)
    }
}
