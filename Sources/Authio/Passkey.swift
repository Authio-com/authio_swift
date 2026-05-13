// Passkey.swift — native WebAuthn ceremony over Apple's
// AuthenticationServices framework.
//
// Flow (login):
//   1. POST /v1/auth/passkey/login/options  → PublicKeyCredentialRequestOptions
//   2. Build ASAuthorizationPlatformPublicKeyCredentialAssertionRequest
//      with the challenge bytes and rpId from (1).
//   3. ASAuthorizationController runs the system passkey UI.
//   4. POST /v1/auth/passkey/login/verify with the assertion fields
//      re-encoded as base64url.
//
// Flow (register) is identical, swapping
// CredentialAssertionRequest for CredentialRegistrationRequest and the
// two endpoints (.../register/options, .../register/verify). For
// register we also pass `{email}` so the server knows whose credential
// it is.
//
// Concurrency: ASAuthorizationController is delegate-based. We bridge
// it to async/await with `withCheckedThrowingContinuation`, wrapping
// the delegate in an internal class that resumes exactly once. The
// delegate holds a strong reference to itself (`retained`) until the
// continuation fires so it doesn't get deallocated mid-ceremony.

#if canImport(AuthenticationServices) && (os(iOS) || os(macOS) || os(visionOS))

import Foundation
import AuthenticationServices

// =====================================================================
// MARK: - Public entry points (called from Authio.Client)
// =====================================================================

extension Authio.Client {

    /// Sign in with an existing passkey. The OS-native passkey sheet
    /// shows the user any platform credentials for the relying party;
    /// they pick one, biometrics gate the assertion, and the server
    /// verifies.
    ///
    /// - Parameter presentationAnchor: the window the system sheet should
    ///   be presented over. On macOS, the keyWindow; on iOS, the active
    ///   UIWindow; on visionOS, the scene's window.
    /// - Parameter email: optional. When omitted, login uses discoverable
    ///   credentials (user picks any account). When provided, the
    ///   server can scope `allowCredentials` to that user.
    public func signInWithPasskey(
        presentationAnchor: ASPresentationAnchor,
        email: String? = nil
    ) async throws -> AuthioSession {
        struct OptionsReq: Encodable { let email: String? }
        let options: PasskeyOptionsDTO = try await http.send(
            "POST",
            "/v1/auth/passkey/login/options",
            body: OptionsReq(email: email)
        )
        let assertion = try await PasskeyCeremony.login(
            options: options.publicKey, anchor: presentationAnchor
        )
        return try await verifyLoginAssertion(assertion: assertion)
    }

    /// Register a new passkey for `email`. The user must already exist
    /// or be auto-created by the server (controlled by the project's
    /// `signup_open` setting). The OS sheet asks the user to use Face
    /// ID/Touch ID/passcode to create the credential.
    public func signUpWithPasskey(
        email: String,
        presentationAnchor: ASPresentationAnchor
    ) async throws -> AuthioSession {
        struct OptionsReq: Encodable { let email: String }
        let options: PasskeyOptionsDTO = try await http.send(
            "POST",
            "/v1/auth/passkey/register/options",
            body: OptionsReq(email: email)
        )
        let attestation = try await PasskeyCeremony.register(
            options: options.publicKey, anchor: presentationAnchor
        )
        return try await verifyRegistrationAttestation(email: email, attestation: attestation)
    }

    // ------------------------------------------------------------------
    // Internal: pack the OS-returned assertion/attestation into the
    // WebAuthn `PublicKeyCredential` JSON the server expects.
    // ------------------------------------------------------------------

    // The server's verify endpoints accept the W3C `PublicKeyCredential`
    // JSON shape (camelCase) wrapped in `{"credential": ...}`. Server's
    // register/verify additionally wants `{"email": "..."}` at the top
    // level so it can re-look-up the user across the two-step ceremony.
    //
    // We send these structs with the SDK's standard encoder, which has
    // no key-conversion strategy — so the camelCase Swift property
    // names go to the wire verbatim.

    fileprivate func verifyLoginAssertion(assertion: PasskeyCeremony.Assertion) async throws -> AuthioSession {
        struct AssertionCredential: Encodable {
            let id: String
            let rawId: String
            let type: String
            let response: Response
            struct Response: Encodable {
                let clientDataJSON: String
                let authenticatorData: String
                let signature: String
                let userHandle: String?
            }
        }
        struct LoginVerifyReq: Encodable {
            let credential: AssertionCredential
        }
        let credId = assertion.credentialID.base64URLEncodedString()
        let req = LoginVerifyReq(credential: .init(
            id:    credId,
            rawId: credId,
            type:  "public-key",
            response: .init(
                clientDataJSON:    assertion.clientDataJSON.base64URLEncodedString(),
                authenticatorData: assertion.authenticatorData.base64URLEncodedString(),
                signature:         assertion.signature.base64URLEncodedString(),
                userHandle:        assertion.userHandle?.base64URLEncodedString()
            )
        ))
        let env: SessionEnvelopeDTO = try await http.send(
            "POST",
            "/v1/auth/passkey/login/verify",
            body: req
        )
        return env.toSession()
    }

    fileprivate func verifyRegistrationAttestation(
        email: String,
        attestation: PasskeyCeremony.Attestation
    ) async throws -> AuthioSession {
        struct AttestationCredential: Encodable {
            let id: String
            let rawId: String
            let type: String
            let response: Response
            struct Response: Encodable {
                let clientDataJSON: String
                let attestationObject: String
            }
        }
        struct RegisterVerifyReq: Encodable {
            let email: String
            let credential: AttestationCredential
        }
        let credId = attestation.credentialID.base64URLEncodedString()
        let req = RegisterVerifyReq(
            email: email,
            credential: .init(
                id:    credId,
                rawId: credId,
                type:  "public-key",
                response: .init(
                    clientDataJSON:    attestation.clientDataJSON.base64URLEncodedString(),
                    attestationObject: attestation.rawAttestationObject.base64URLEncodedString()
                )
            )
        )
        let env: SessionEnvelopeDTO = try await http.send(
            "POST",
            "/v1/auth/passkey/register/verify",
            body: req
        )
        return env.toSession()
    }
}

// =====================================================================
// MARK: - The ceremony driver (delegate + continuation bridge)
// =====================================================================

enum PasskeyCeremony {

    /// What the OS hands back on a successful assertion.
    struct Assertion {
        let credentialID: Data
        let clientDataJSON: Data
        let authenticatorData: Data
        let signature: Data
        let userHandle: Data?
    }

    /// What the OS hands back on a successful registration.
    struct Attestation {
        let credentialID: Data
        let clientDataJSON: Data
        let rawAttestationObject: Data
    }

    static func login(
        options: PasskeyOptionsDTO.PublicKey,
        anchor: ASPresentationAnchor
    ) async throws -> Assertion {
        guard let rpId = options.rpId, !rpId.isEmpty else {
            throw AuthioError.passkeyFailed(message: "options.publicKey.rpId missing")
        }
        guard let challenge = Data(base64URLEncoded: options.challenge) else {
            throw AuthioError.passkeyFailed(message: "options.publicKey.challenge not base64url")
        }
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: rpId
        )
        let request = provider.createCredentialAssertionRequest(challenge: challenge)
        if let allow = options.allowCredentials {
            request.allowedCredentials = allow.compactMap { c in
                guard let id = Data(base64URLEncoded: c.id) else { return nil }
                return ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: id)
            }
        }
        if let uv = options.userVerification {
            request.userVerificationPreference = .init(rawValue: uv)
        }
        return try await withCheckedThrowingContinuation { cont in
            Task { @MainActor in
                let delegate = LoginDelegate(anchor: anchor) { result in
                    switch result {
                    case .success(let a): cont.resume(returning: a)
                    case .failure(let e): cont.resume(throwing: e)
                    }
                }
                delegate.start(request: request)
            }
        }
    }

    static func register(
        options: PasskeyOptionsDTO.PublicKey,
        anchor: ASPresentationAnchor
    ) async throws -> Attestation {
        guard let rp = options.rp, !rp.id.isEmpty else {
            throw AuthioError.passkeyFailed(message: "options.publicKey.rp.id missing")
        }
        guard let user = options.user,
              let userId = Data(base64URLEncoded: user.id) else {
            throw AuthioError.passkeyFailed(message: "options.publicKey.user.id missing")
        }
        guard let challenge = Data(base64URLEncoded: options.challenge) else {
            throw AuthioError.passkeyFailed(message: "options.publicKey.challenge not base64url")
        }
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: rp.id
        )
        let request = provider.createCredentialRegistrationRequest(
            challenge: challenge,
            name: user.name,
            userID: userId
        )
        if let uv = options.authenticatorSelection?.userVerification {
            request.userVerificationPreference = .init(rawValue: uv)
        }
        return try await withCheckedThrowingContinuation { cont in
            Task { @MainActor in
                let delegate = RegisterDelegate(anchor: anchor) { result in
                    switch result {
                    case .success(let a): cont.resume(returning: a)
                    case .failure(let e): cont.resume(throwing: e)
                    }
                }
                delegate.start(request: request)
            }
        }
    }
}

// =====================================================================
// MARK: - Delegate implementations
//
// Both delegates self-retain via `retained = self` so they survive past
// the start(request:) call frame, then nil it out in the callbacks so
// ARC reclaims them. The Sendable warnings are silenced with @unchecked
// because ASAuthorizationController insists on hopping back to the
// main actor, and we route everything through the captured callback
// closure (which can be marked @MainActor by callers if they need it).
// =====================================================================

private final class LoginDelegate:
    NSObject,
    ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding,
    @unchecked Sendable
{
    private let anchor: ASPresentationAnchor
    private let completion: (Result<PasskeyCeremony.Assertion, AuthioError>) -> Void
    private var retained: LoginDelegate?

    init(anchor: ASPresentationAnchor,
         completion: @escaping (Result<PasskeyCeremony.Assertion, AuthioError>) -> Void) {
        self.anchor = anchor
        self.completion = completion
    }

    func start(request: ASAuthorizationPlatformPublicKeyCredentialAssertionRequest) {
        self.retained = self
        let controller = ASAuthorizationController(authorizationRequests: [request])
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return anchor
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        defer { retained = nil }
        guard let cred = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
            completion(.failure(.passkeyFailed(message: "unexpected credential type")))
            return
        }
        completion(.success(.init(
            credentialID:      cred.credentialID,
            clientDataJSON:    cred.rawClientDataJSON,
            authenticatorData: cred.rawAuthenticatorData,
            signature:         cred.signature,
            userHandle:        cred.userID
        )))
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        defer { retained = nil }
        completion(.failure(mapPasskeyError(error)))
    }
}

private final class RegisterDelegate:
    NSObject,
    ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding,
    @unchecked Sendable
{
    private let anchor: ASPresentationAnchor
    private let completion: (Result<PasskeyCeremony.Attestation, AuthioError>) -> Void
    private var retained: RegisterDelegate?

    init(anchor: ASPresentationAnchor,
         completion: @escaping (Result<PasskeyCeremony.Attestation, AuthioError>) -> Void) {
        self.anchor = anchor
        self.completion = completion
    }

    func start(request: ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest) {
        self.retained = self
        let controller = ASAuthorizationController(authorizationRequests: [request])
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return anchor
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        defer { retained = nil }
        guard let cred = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialRegistration,
              let rawAtt = cred.rawAttestationObject else {
            completion(.failure(.passkeyFailed(message: "unexpected credential type")))
            return
        }
        completion(.success(.init(
            credentialID:         cred.credentialID,
            clientDataJSON:       cred.rawClientDataJSON,
            rawAttestationObject: rawAtt
        )))
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        defer { retained = nil }
        completion(.failure(mapPasskeyError(error)))
    }
}

/// Translate ASAuthorizationError.canceled (NSError code 1001) into the
/// SDK's user-friendly `.passkeyCancelled`. Everything else stays as
/// `.passkeyFailed(message:)` with the underlying description so
/// callers can show it.
private func mapPasskeyError(_ error: Error) -> AuthioError {
    if let asErr = error as? ASAuthorizationError {
        switch asErr.code {
        case .canceled:
            return .passkeyCancelled
        default:
            return .passkeyFailed(message: asErr.localizedDescription)
        }
    }
    return .passkeyFailed(message: error.localizedDescription)
}

#endif
