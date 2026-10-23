// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// Every certificate here is made in the process, from keys the platform
// holds, so the suite runs on macOS and on the iOS simulator alike. On a Mac
// with a Secure Enclave the client's key is made in it; the simulator has
// none, and there the same test uses a software key.
#if canImport(Network)
import Dispatch
import Foundation
import LocalAuthentication
import Network
import Security
import XCTest
@testable import Sipral

/// Keys, and certificates signed with them, for one test.
enum TestPki {
    static let serverAuth: [UInt] = [1, 3, 6, 1, 5, 5, 7, 3, 1]
    static let clientAuth: [UInt] = [1, 3, 6, 1, 5, 5, 7, 3, 2]

    /// A P-256 key the process holds, kept nowhere.
    static func softwareKey() throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false],
        ]
        var failure: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &failure) else {
            throw failure!.takeRetainedValue() as Error
        }
        return key
    }

    /// A certificate for `publicKey` naming `subject`, signed by `signer` as
    /// `issuer`: an authority when `authority`, else a leaf for `usage`,
    /// with `dnsName` in its subjectAltName when given.
    static func certificate(
        subject: String, publicKey: SecKey, issuer: String, signer: SecKey, authority: Bool = false,
        usage: [UInt] = clientAuth, dnsName: String? = nil,
        from notBefore: Date = Date(timeIntervalSinceNow: -3600), until notAfter: Date = Date(timeIntervalSinceNow: 86400)
    ) throws -> SecCertificate {
        func extensionField(_ oid: [UInt], critical: Bool, _ value: [UInt8]) -> [UInt8] {
            Der.sequence([Der.oid(oid)] + (critical ? [Der.boolean(true)] : []) + [Der.octetString(value)])
        }
        var extensions = [
            extensionField([2, 5, 29, 19], critical: true, Der.sequence(authority ? [Der.boolean(true)] : [])),
            // keyCertSign and cRLSign for an authority, digitalSignature for a leaf
            extensionField([2, 5, 29, 15], critical: true, Der.element(0x03, authority ? [0x01, 0x06] : [0x07, 0x80])),
        ]
        if !authority {
            extensions.append(extensionField([2, 5, 29, 37], critical: false, Der.sequence([Der.oid(usage)])))
        }
        if let dnsName {
            extensions.append(extensionField(
                [2, 5, 29, 17], critical: false, Der.sequence([Der.contextPrimitive(2, Array(dnsName.utf8))])
            ))
        }
        var serial = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, serial.count, &serial)
        serial[0] &= 0x7F
        let tbs = Der.sequence([
            Der.contextConstructed(0, Der.integer([2])),
            Der.integer(serial),
            Der.sequence([Der.oid(Der.ecdsaWithSha256)]),
            Der.name(commonName: issuer),
            Der.sequence([Der.time(notBefore), Der.time(notAfter)]),
            Der.name(commonName: subject),
            try ClientIdentity.subjectPublicKeyInfo(publicKey).0,
            Der.contextConstructed(3, Der.sequence(extensions)),
        ])
        var failure: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            signer, .ecdsaSignatureMessageX962SHA256, Data(tbs) as CFData, &failure
        ) else {
            throw failure!.takeRetainedValue() as Error
        }
        let der = Der.sequence([tbs, Der.sequence([Der.oid(Der.ecdsaWithSha256)]), Der.bitString([UInt8](signature as Data))])
        return try XCTUnwrap(SecCertificateCreateWithData(nil, Data(der) as CFData), "the certificate did not parse")
    }

    /// An authority: its key and its self-signed certificate.
    struct Authority {
        let name: String
        let key: SecKey
        let certificate: SecCertificate

        init(_ name: String) throws {
            self.name = name
            key = try TestPki.softwareKey()
            certificate = try TestPki.certificate(
                subject: name, publicKey: SecKeyCopyPublicKey(key)!, issuer: name, signer: key, authority: true
            )
        }

        var der: [UInt8] { [UInt8](SecCertificateCopyData(certificate) as Data) }

        /// A leaf for `key`, signed by this authority.
        func issue(
            _ subject: String, for key: SecKey, usage: [UInt] = TestPki.clientAuth, dnsName: String? = nil,
            from notBefore: Date = Date(timeIntervalSinceNow: -3600), until notAfter: Date = Date(timeIntervalSinceNow: 86400)
        ) throws -> SecCertificate {
            try TestPki.certificate(
                subject: subject, publicKey: SecKeyCopyPublicKey(key)!, issuer: name, signer: self.key,
                usage: usage, dnsName: dnsName, from: notBefore, until: notAfter
            )
        }

        /// An intermediate authority this one signs.
        func intermediate(_ name: String) throws -> (Authority, SecCertificate) {
            let key = try TestPki.softwareKey()
            let certificate = try TestPki.certificate(
                subject: name, publicKey: SecKeyCopyPublicKey(key)!, issuer: self.name, signer: self.key,
                authority: true
            )
            return (Authority(name: name, key: key, certificate: certificate), certificate)
        }

        private init(name: String, key: SecKey, certificate: SecCertificate) {
            self.name = name
            self.key = key
            self.certificate = certificate
        }
    }
}

/// A registrar on loopback that takes TLS only from a client whose
/// certificate `authority` signed, at the TLS versions given. It records
/// each connection it accepted, the common name of each client certificate
/// it was shown, and every REGISTER, answering each 200.
final class CertificateRegistrar: @unchecked Sendable {
    static let serverName = "registrar.sipral.test"

    private let listener: NWListener
    private let queue = DispatchQueue(label: "org.sipral.test.certificate-registrar")
    private let lock = NSLock()
    private var _connections = 0
    private let seen = Seen()
    private var _registers: [String] = []

    /// The common names the trust check was shown, written on its queue.
    private final class Seen: @unchecked Sendable {
        private let lock = NSLock()
        private var names: [String] = []
        func add(_ name: String) { lock.withLock { names.append(name) } }
        var all: [String] { lock.withLock { names } }
    }
    private var open: [NWConnection] = []
    let port: UInt16

    init(authority: TestPki.Authority, serverAuthority: TestPki.Authority, version: tls_protocol_version_t) throws {
        let key = try TestPki.softwareKey()
        let certificate = try serverAuthority.issue(
            "registrar", for: key, usage: TestPki.serverAuth, dnsName: Self.serverName
        )
        let identity = try XCTUnwrap(SecIdentityCreate(nil, certificate, key))
        let tls = NWProtocolTLS.Options()
        let security = tls.securityProtocolOptions
        sec_protocol_options_set_local_identity(security, sec_identity_create(identity)!)
        sec_protocol_options_set_peer_authentication_required(security, true)
        sec_protocol_options_set_min_tls_protocol_version(security, version)
        sec_protocol_options_set_max_tls_protocol_version(security, version)
        let anchors = [authority.certificate]
        let record = seen
        sec_protocol_options_set_verify_block(security, { _, trust, complete in
            let evaluated = sec_trust_copy_ref(trust).takeRetainedValue()
            SecTrustSetPolicies(evaluated, SecPolicyCreateSSL(false, nil))
            SecTrustSetAnchorCertificates(evaluated, anchors as CFArray)
            SecTrustSetAnchorCertificatesOnly(evaluated, true)
            let chain = SecTrustCopyCertificateChain(evaluated) as? [SecCertificate] ?? []
            var name: CFString?
            if let leaf = chain.first, SecCertificateCopyCommonName(leaf, &name) == errSecSuccess, let name {
                record.add(name as String)
            }
            complete(SecTrustEvaluateWithError(evaluated, nil))
        }, DispatchQueue(label: "org.sipral.test.certificate-registrar.trust"))
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.signal() }
        }
        var accepted: (NWConnection) -> Void = { _ in }
        listener.newConnectionHandler = { accepted($0) }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 5) == .success, let bound = listener.port?.rawValue else {
            throw XCTSkip("the registrar could not listen")
        }
        port = bound
        accepted = { [weak self] connection in self?.serve(connection) }
    }

    var address: String { "127.0.0.1:\(port)" }
    var connections: Int { lock.withLock { _connections } }
    var shown: [String] { seen.all }
    var registers: [String] { lock.withLock { _registers } }

    func stop() {
        let all = lock.withLock { () -> [NWConnection] in
            defer { open = [] }
            return open
        }
        all.forEach { $0.cancel() }
        listener.cancel()
    }

    private func serve(_ connection: NWConnection) {
        lock.withLock {
            _connections += 1
            open.append(connection)
        }
        connection.start(queue: queue)
        read(connection, held: "")
    }

    private func read(_ connection: NWConnection, held: String) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, complete, error in
            guard let self else { return }
            var held = held + (data.map { String(decoding: $0, as: UTF8.self) } ?? "")
            while let end = held.range(of: "\r\n\r\n") {
                let head = String(held[..<end.lowerBound])
                let length = Int(Self.header("Content-Length", head) ?? "0") ?? 0
                let body = held[end.upperBound...]
                guard body.utf8.count >= length else { break }
                held = String(body.dropFirst(length))
                if head.hasPrefix("REGISTER ") {
                    self.lock.withLock { self._registers.append(head) }
                    connection.send(content: Data(Self.ok(head).utf8), completion: .idempotent)
                }
            }
            if complete || error != nil {
                connection.cancel()
                return
            }
            self.read(connection, held: held)
        }
    }

    static func header(_ name: String, _ message: String) -> String? {
        message.components(separatedBy: "\r\n")
            .first { $0.lowercased().hasPrefix(name.lowercased() + ":") }
            .map { String($0.drop(while: { $0 != ":" }).dropFirst()).trimmingCharacters(in: .whitespaces) }
    }

    private static func ok(_ request: String) -> String {
        var lines = ["SIP/2.0 200 OK"]
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            let value = header(name, request) ?? ""
            lines.append(name == "To" ? "To: \(value);tag=registrar" : "\(name): \(value)")
        }
        lines.append("Contact: \(header("Contact", request) ?? "");expires=3600")
        lines.append("Content-Length: 0")
        return lines.joined(separator: "\r\n") + "\r\n\r\n"
    }
}

/// A client certificate on SIP over TLS: presented and accepted, with its
/// key in the Secure Enclave where there is one; and each way it can fail,
/// told as its own `SipralTlsFailure`.
final class ClientCertificateTests: XCTestCase {
    private let authority = try! TestPki.Authority("Sipral test client authority")
    private let serverAuthority = try! TestPki.Authority("Sipral test server authority")

    private func registrar(_ version: tls_protocol_version_t = .TLSv13) throws -> CertificateRegistrar {
        try CertificateRegistrar(authority: authority, serverAuthority: serverAuthority, version: version)
    }

    private func stack(_ registrar: CertificateRegistrar, _ identity: ClientIdentity?) throws -> SipralStack {
        try SipralStack(
            audio: .application, signalling: .tls, signallingServer: registrar.address,
            tlsServerName: CertificateRegistrar.serverName, tlsTrust: .onlyAuthority(serverAuthority.der),
            tlsClientIdentity: identity
        )
    }

    /// A key in the Secure Enclave, or, on the simulator, which has none, a
    /// software key the process holds.
    private func platformKey() throws -> SecKey {
        #if targetEnvironment(simulator)
        return try TestPki.softwareKey()
        #else
        return try ClientIdentity.secureEnclaveKey()
        #endif
    }

    private func identity(
        _ name: String = "alice", by signer: TestPki.Authority? = nil,
        from notBefore: Date = Date(timeIntervalSinceNow: -3600), until notAfter: Date = Date(timeIntervalSinceNow: 86400)
    ) throws -> ClientIdentity {
        let key = try TestPki.softwareKey()
        let certificate = try (signer ?? authority).issue(name, for: key, from: notBefore, until: notAfter)
        return try ClientIdentity(certificate: certificate, privateKey: key)
    }

    private func refusal(_ stack: SipralStack) async throws -> TransportFailedEventData {
        let event = await firstOne(of: stack.events(), within: 10) { $0.kind == .transportFailed }
        let said = try XCTUnwrap(event, "the stack never said why the connection failed")
        return try XCTUnwrap(said.transportFailedData)
    }

    private func registers(_ stack: SipralStack, _ registrar: CertificateRegistrar) async throws {
        let account = try stack.addAccount(
            aor: "sip:alice@\(CertificateRegistrar.serverName)", registrarAddress: registrar.address,
            registrar: "sip:\(CertificateRegistrar.serverName)"
        )
        try account.register()
        for _ in 0..<100 {
            if try account.registrationState == .registered { return }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTFail("the account never registered")
    }

    func testAKeyThePlatformHoldsRegistersWhereTheServerRequiresACertificate() async throws {
        let registrar = try registrar()
        defer { registrar.stop() }
        let key = try platformKey()
        let certificate = try authority.issue("alice-enclave", for: key)
        let stack = try stack(registrar, try ClientIdentity(certificate: certificate, privateKey: key))
        defer { stack.close() }
        XCTAssertTrue(stack.connected)
        try await registers(stack, registrar)
        XCTAssertEqual(registrar.shown, ["alice-enclave"])
        XCTAssertEqual(registrar.registers.count, 1)
    }

    func testAnAccountOnItsOwnConnectionPresentsItsOwnCertificate() async throws {
        let registrar = try registrar()
        defer { registrar.stop() }
        let stack = try SipralStack(
            audio: .application, bindHost: "127.0.0.1", tlsServerName: CertificateRegistrar.serverName,
            tlsTrust: .onlyAuthority(serverAuthority.der), tlsClientIdentity: try identity("the-stacks")
        )
        defer { stack.close() }
        let account = try stack.addAccount(
            aor: "sip:alice@\(CertificateRegistrar.serverName)", registrarAddress: registrar.address,
            tlsClientIdentity: try identity("alice-own"), streamProtocol: .tls,
            registrar: "sip:\(CertificateRegistrar.serverName)"
        )
        try account.register()
        for _ in 0..<100 where try account.registrationState != .registered {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTAssertEqual(try account.registrationState, .registered)
        XCTAssertEqual(registrar.shown, ["alice-own"])
    }

    func testTheCertificateIsAcceptedOverTls12Too() async throws {
        let registrar = try registrar(.TLSv12)
        defer { registrar.stop() }
        let stack = try stack(registrar, try identity())
        defer { stack.close() }
        try await registers(stack, registrar)
        XCTAssertEqual(registrar.shown, ["alice"])
    }

    func testTheIntermediatesAreSentAfterTheLeaf() async throws {
        let registrar = try registrar()
        defer { registrar.stop() }
        let (intermediate, certificate) = try authority.intermediate("Sipral test intermediate")
        let key = try TestPki.softwareKey()
        let leaf = try intermediate.issue("alice-chained", for: key)
        let stack = try stack(
            registrar, try ClientIdentity(certificate: leaf, privateKey: key, intermediates: [certificate])
        )
        defer { stack.close() }
        try await registers(stack, registrar)
        XCTAssertEqual(registrar.shown, ["alice-chained"])
    }

    func testNoCertificateWhereOneIsRequiredIsSaidSo() async throws {
        for version in [tls_protocol_version_t.TLSv13, .TLSv12] {
            let registrar = try registrar(version)
            defer { registrar.stop() }
            let stack = try stack(registrar, nil)
            defer { stack.close() }
            let failed = try await refusal(stack)
            XCTAssertEqual(failed.tls, .clientCertificateRequired, "\(version): \(failed.detail ?? "")")
            XCTAssertEqual(failed.error, .connectionReset)
        }
    }

    func testACertificateTheServerDoesNotTrustIsRefused() async throws {
        let stranger = try TestPki.Authority("Sipral test stranger")
        for version in [tls_protocol_version_t.TLSv13, .TLSv12] {
            let registrar = try registrar(version)
            defer { registrar.stop() }
            let stack = try stack(registrar, try identity("mallory", by: stranger))
            defer { stack.close() }
            let failed = try await refusal(stack)
            XCTAssertEqual(failed.tls, .clientCertificateRefused, "\(version): \(failed.detail ?? "")")
            XCTAssertEqual(registrar.shown, ["mallory"])
        }
    }

    func testAnExpiredCertificateIsNeverPresented() async throws {
        let registrar = try registrar()
        defer { registrar.stop() }
        let lapsed = try identity(
            from: Date(timeIntervalSince1970: 1_577_836_800), until: Date(timeIntervalSince1970: 1_577_923_200)
        )
        let stack = try stack(registrar, lapsed)
        defer { stack.close() }
        let failed = try await refusal(stack)
        XCTAssertEqual(failed.tls, .clientCertificateExpired, failed.detail ?? "")
        XCTAssertEqual(failed.error, .other)
        XCTAssertTrue(failed.detail?.contains("2020-01-01") == true, failed.detail ?? "")
        XCTAssertEqual(registrar.connections, 0, "nothing reached the server")
    }

    func testACertificateNotValidYetIsNeverPresented() async throws {
        let registrar = try registrar()
        defer { registrar.stop() }
        let early = try identity(from: Date(timeIntervalSinceNow: 86400), until: Date(timeIntervalSinceNow: 2 * 86400))
        let stack = try stack(registrar, early)
        defer { stack.close() }
        let failed = try await refusal(stack)
        XCTAssertEqual(failed.tls, .clientCertificateExpired, failed.detail ?? "")
        XCTAssertEqual(registrar.connections, 0)
    }

    func testAnIdentityTheKeychainDoesNotHoldIsUnavailable() async throws {
        let registrar = try registrar()
        defer { registrar.stop() }
        let stack = try stack(registrar, ClientIdentity.keychain(label: "sipral-test-\(UUID().uuidString)"))
        defer { stack.close() }
        let failed = try await refusal(stack)
        XCTAssertEqual(failed.tls, .clientKeyUnavailable, failed.detail ?? "")
        XCTAssertTrue(failed.detail?.contains("Keychain") == true, failed.detail ?? "")
        XCTAssertEqual(registrar.connections, 0)
    }

    #if !targetEnvironment(simulator)
    /// A Secure Enclave key that needs the user's presence, on a context
    /// that may not ask: the handshake cannot be signed, which is the key
    /// unavailable, as on a phone whose user has not unlocked it.
    func testAKeyThatWillNotSignIsUnavailable() async throws {
        let registrar = try registrar()
        defer { registrar.stop() }
        let context = LAContext()
        context.interactionNotAllowed = true
        var failure: Unmanaged<CFError>?
        let access = try XCTUnwrap(SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &failure
        ))
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseAuthenticationContext as String: context,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false, kSecAttrAccessControl as String: access,
            ],
        ]
        let key = try XCTUnwrap(SecKeyCreateRandomKey(attributes as CFDictionary, &failure))
        let certificate = try authority.issue("alice-locked", for: key)
        let stack = try stack(registrar, try ClientIdentity(certificate: certificate, privateKey: key))
        defer { stack.close() }
        let failed = try await refusal(stack)
        XCTAssertEqual(failed.tls, .clientKeyUnavailable, failed.detail ?? "")
    }
    #endif

    func testAKeyThatIsNotTheCertificatesIsRefusedUpFront() throws {
        let certificate = try authority.issue("alice", for: try TestPki.softwareKey())
        XCTAssertThrowsError(try ClientIdentity(certificate: certificate, privateKey: try TestPki.softwareKey())) {
            XCTAssertEqual(($0 as? SipralError)?.status, .invalidArgument)
        }
    }

    func testTheRequestIsSignedByTheKeyItNames() throws {
        let key = try platformKey()
        let request = try ClientIdentity.certificateRequest(commonName: "alice@sipral.test", privateKey: key)
        let outer = try XCTUnwrap(Der.read(request, at: 0))
        XCTAssertEqual(outer.tag, 0x30)
        let info = try XCTUnwrap(Der.read(request, at: outer.start))
        let infoBytes = Array(request[outer.start..<info.start + info.length])
        let algorithm = try XCTUnwrap(Der.read(request, at: info.start + info.length))
        let signature = try XCTUnwrap(Der.read(request, at: algorithm.start + algorithm.length))
        XCTAssertEqual(signature.tag, 0x03)
        XCTAssertEqual(signature.start + signature.length, request.count)
        let signed = Array(request[signature.start + 1..<signature.start + signature.length])
        XCTAssertTrue(SecKeyVerifySignature(
            SecKeyCopyPublicKey(key)!, .ecdsaSignatureMessageX962SHA256, Data(infoBytes) as CFData,
            Data(signed) as CFData, nil
        ))
        XCTAssertTrue(infoBytes.containsSequence(Array("alice@sipral.test".utf8)))
        let spki = try ClientIdentity.subjectPublicKeyInfo(SecKeyCopyPublicKey(key)!).0
        XCTAssertTrue(infoBytes.containsSequence(spki))
    }

    func testTheDatesAreReadFromTheCertificate() throws {
        let from = Date(timeIntervalSince1970: 1_577_836_800)
        let until = Date(timeIntervalSince1970: 2_556_143_999)
        let certificate = try authority.issue("alice", for: try TestPki.softwareKey(), from: from, until: until)
        let dates = try XCTUnwrap(Der.validity(ofCertificate: [UInt8](SecCertificateCopyData(certificate) as Data)))
        XCTAssertEqual(dates.0, from)
        XCTAssertEqual(dates.1, until, "a GeneralizedTime from 2050 is read as such")
    }

    func testEachAlertIsReadAsWhatItSaysAboutTheCertificate() {
        XCTAssertEqual(ClientIdentity.refusal(status: errSSLPeerBadCert, presented: true, asked: true), .clientCertificateRefused)
        XCTAssertEqual(ClientIdentity.refusal(status: errSSLPeerUnknownCA, presented: true, asked: true), .clientCertificateRefused)
        XCTAssertEqual(ClientIdentity.refusal(status: errSSLPeerCertExpired, presented: true, asked: true), .clientCertificateExpired)
        XCTAssertEqual(ClientIdentity.refusal(status: errSecInteractionNotAllowed, presented: true, asked: true), .clientKeyUnavailable)
        XCTAssertEqual(ClientIdentity.refusal(status: errSSLCertificateRequired, presented: false, asked: true), .clientCertificateRequired)
        XCTAssertEqual(ClientIdentity.refusal(status: errSSLPeerHandshakeFail, presented: false, asked: true), .clientCertificateRequired)
        XCTAssertNil(ClientIdentity.refusal(status: errSSLPeerHandshakeFail, presented: false, asked: false))
        XCTAssertNil(ClientIdentity.refusal(status: errSSLPeerHandshakeFail, presented: true, asked: true))
        XCTAssertEqual(ClientIdentity.refusal(status: errSSLHandshakeFail, presented: true, asked: true), .clientKeyUnavailable)
        XCTAssertNil(ClientIdentity.refusal(status: errSSLHandshakeFail, presented: true, asked: false))
        XCTAssertNil(ClientIdentity.refusal(status: errSSLHandshakeFail, presented: false, asked: true))
        XCTAssertNil(ClientIdentity.refusal(status: errSSLPeerProtocolVersion, presented: false, asked: false))
    }
}

extension Array where Element == UInt8 {
    fileprivate func containsSequence(_ part: [UInt8]) -> Bool {
        guard !part.isEmpty, part.count <= count else { return false }
        return (0...(count - part.count)).contains { Array(self[$0..<$0 + part.count]) == part }
    }
}
#endif
