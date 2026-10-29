// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Network)
import CryptoKit
import Foundation
import Security
#endif

/// The certificate this end presents when a TLS server asks for one (RFC
/// 8446 §4.4.2), with a private key the platform holds and signs with: a
/// `SecIdentity` from the Keychain, one made from a certificate and a
/// Secure Enclave key, or one looked up by its label at every connection.
/// The key never leaves the platform; the layer hands the identity to
/// Network.framework and nothing else (`docs/22-tls.md`, "A client
/// certificate"). Apple platforms only: elsewhere the type exists and
/// cannot be made, as TLS cannot be had.
public final class ClientIdentity: @unchecked Sendable {
    #if canImport(Network)
    private enum Source {
        case identity(SecIdentity)
        case keychain(String)
    }

    private let source: Source
    /// Sent after the leaf, nearest to it first.
    public let intermediates: [SecCertificate]

    /// An identity the application already holds.
    public init(identity: SecIdentity, intermediates: [SecCertificate] = []) {
        source = .identity(identity)
        self.intermediates = intermediates
    }

    /// A certificate and the platform's key for it, such as one made in the
    /// Secure Enclave with `secureEnclaveKey(tag:accessControl:)`. Throws
    /// `.invalidArgument` when the key is not the certificate's.
    public convenience init(
        certificate: SecCertificate, privateKey: SecKey, intermediates: [SecCertificate] = []
    ) throws {
        guard let identity = SecIdentityCreate(nil, certificate, privateKey) else {
            throw SipralError(status: .invalidArgument, message: "the private key is not the one the certificate names")
        }
        self.init(identity: identity, intermediates: intermediates)
    }

    private init(label: String, intermediates: [SecCertificate]) {
        source = .keychain(label)
        self.intermediates = intermediates
    }

    /// The identity whose certificate carries `label` in the Keychain
    /// (`kSecAttrLabel`), looked up again before every connection: a phone
    /// woken while locked finds it, or is told
    /// `SipralTlsFailure.clientKeyUnavailable`, at that moment rather than
    /// when the account was added.
    public static func keychain(label: String, intermediates: [SecCertificate] = []) -> ClientIdentity {
        ClientIdentity(label: label, intermediates: intermediates)
    }

    /// A new P-256 key made inside the Secure Enclave, which signs and is
    /// never readable. With `tag` it is kept in the Keychain under that
    /// application tag (which needs the application's keychain entitlement);
    /// without, it lives as long as the returned reference. The default
    /// access control lets it sign after the first unlock, so a phone woken
    /// by a push while locked can still connect; one that asks for the
    /// user's presence fails then as `.clientKeyUnavailable`.
    public static func secureEnclaveKey(tag: [UInt8]? = nil, accessControl: SecAccessControl? = nil) throws -> SecKey {
        var failure: Unmanaged<CFError>?
        guard let access = accessControl ?? SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &failure
        ) else {
            throw keyError(failure, "no access control for the key")
        }
        var privateAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: tag != nil,
            kSecAttrAccessControl as String: access,
        ]
        if let tag {
            privateAttributes[kSecAttrApplicationTag as String] = Data(tag)
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateAttributes,
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &failure) else {
            throw keyError(failure, "the Secure Enclave made no key")
        }
        return key
    }

    /// A PKCS#10 certification request (RFC 2986) for `privateKey`'s public
    /// half, naming `commonName`, signed by the key itself: what a private
    /// authority signs to issue the certificate. P-256 keys sign it with
    /// ECDSA and SHA-256, RSA keys with PKCS #1 v1.5 and SHA-256; DER.
    public static func certificateRequest(commonName: String, privateKey: SecKey) throws -> [UInt8] {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SipralError(status: .invalidArgument, message: "the key has no public half")
        }
        let (spki, algorithm, signing) = try subjectPublicKeyInfo(publicKey)
        let info = Der.sequence([
            Der.integer([0]),
            Der.name(commonName: commonName),
            spki,
            Der.contextConstructed(0, []),
        ])
        var failure: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, signing, Data(info) as CFData, &failure) else {
            throw keyError(failure, "the key would not sign the request")
        }
        return Der.sequence([info, algorithm, Der.bitString([UInt8](signature as Data))])
    }

    /// The public key as a SubjectPublicKeyInfo, the signature algorithm
    /// that goes with it and the one `SecKeyCreateSignature` is asked for.
    static func subjectPublicKeyInfo(_ publicKey: SecKey) throws -> ([UInt8], [UInt8], SecKeyAlgorithm) {
        var failure: Unmanaged<CFError>?
        guard let external = SecKeyCopyExternalRepresentation(publicKey, &failure) as Data? else {
            throw keyError(failure, "the public key could not be read")
        }
        let attributes = SecKeyCopyAttributes(publicKey) as? [String: Any] ?? [:]
        let type = attributes[kSecAttrKeyType as String] as? String
        if type == (kSecAttrKeyTypeECSECPrimeRandom as String), external.count == 65 {
            let spki = Der.sequence([
                Der.sequence([Der.oid(Der.ecPublicKey), Der.oid(Der.prime256v1)]),
                Der.bitString([UInt8](external)),
            ])
            return (spki, Der.sequence([Der.oid(Der.ecdsaWithSha256)]), .ecdsaSignatureMessageX962SHA256)
        }
        if type == (kSecAttrKeyTypeRSA as String) {
            let spki = Der.sequence([
                Der.sequence([Der.oid(Der.rsaEncryption), Der.null()]),
                Der.bitString([UInt8](external)),
            ])
            return (
                spki, Der.sequence([Der.oid(Der.sha256WithRsa), Der.null()]), .rsaSignatureMessagePKCS1v15SHA256
            )
        }
        throw SipralError(status: .notSupported, message: "a key for a client certificate is P-256 or RSA")
    }

    private static func keyError(_ failure: Unmanaged<CFError>?, _ what: String) -> SipralError {
        let said = failure.map { CFErrorCopyDescription($0.takeRetainedValue()) as String } ?? ""
        return SipralError(status: .invalidArgument, message: said.isEmpty ? what : "\(what): \(said)")
    }

    /// What a connection presents, or why it cannot present it now: the
    /// identity found, its key reachable and its leaf inside its dates.
    func presentable(at now: Date) -> Result<sec_identity_t, SignallingRefusal> {
        let identity: SecIdentity
        switch source {
        case .identity(let held):
            identity = held
        case .keychain(let label):
            // the data protection keychain on macOS too, as on iOS: never the
            // login keychain, whose items may ask the user for access
            let query: [String: Any] = [
                kSecClass as String: kSecClassIdentity,
                kSecAttrLabel as String: label,
                kSecReturnRef as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecUseDataProtectionKeychain as String: true,
            ]
            var found: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &found)
            guard status == errSecSuccess, let found, CFGetTypeID(found) == SecIdentityGetTypeID() else {
                let said = SecCopyErrorMessageString(status, nil) as String? ?? "status \(status)"
                return .failure(Self.unavailable("no identity labelled \(label) could be read from the Keychain: \(said)"))
            }
            identity = found as! SecIdentity
        }
        var certificate: SecCertificate?
        var key: SecKey?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else {
            return .failure(Self.unavailable("the identity has no certificate"))
        }
        guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key else {
            return .failure(Self.unavailable("the identity's private key could not be reached"))
        }
        let signs = SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256)
            || SecKeyIsAlgorithmSupported(key, .sign, .rsaSignatureMessagePKCS1v15SHA256)
            || SecKeyIsAlgorithmSupported(key, .sign, .rsaSignatureDigestPSSSHA256)
        guard signs else {
            return .failure(Self.unavailable("the identity's private key does not sign"))
        }
        let leaf = [UInt8](SecCertificateCopyData(certificate) as Data)
        guard let (notBefore, notAfter) = Der.validity(ofCertificate: leaf) else {
            return .failure(Self.unavailable("the client certificate's dates could not be read"))
        }
        if now < notBefore || now > notAfter {
            let format = ISO8601DateFormatter()
            return .failure(SignallingRefusal(
                error: .other, tls: .clientCertificateExpired,
                detail: "the client certificate is valid from \(format.string(from: notBefore)) "
                    + "to \(format.string(from: notAfter))"
            ))
        }
        let made = intermediates.isEmpty
            ? sec_identity_create(identity)
            : sec_identity_create_with_certificates(identity, ([certificate] + intermediates) as CFArray)
        guard let made else {
            return .failure(Self.unavailable("Network.framework would not take the identity"))
        }
        return .success(made)
    }

    private static func unavailable(_ detail: String) -> SignallingRefusal {
        SignallingRefusal(error: .other, tls: .clientKeyUnavailable, detail: SignallingRefusal.sentence(detail))
    }

    /// What a received alert, or a key that would not sign, says about the
    /// client certificate (`docs/22-tls.md`, "A client certificate"); `nil`
    /// for anything else. `presented` is whether this end sent one, `asked`
    /// whether the server's CertificateRequest reached the challenge block.
    static func refusal(status: Int32, presented: Bool, asked: Bool) -> SipralTlsFailure? {
        let alerts: Set<Int32> = [
            errSSLPeerBadCert, errSSLPeerUnsupportedCert, errSSLPeerCertRevoked, errSSLPeerCertUnknown,
            errSSLPeerUnknownCA, errSSLPeerAccessDenied, errSSLCertificateRequired,
        ]
        let keys: Set<Int32> = [
            errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled, errSecItemNotFound,
            errSecMissingEntitlement, errSecNoAccessForItem,
        ]
        if presented {
            if status == errSSLPeerCertExpired { return .clientCertificateExpired }
            // this end's own handshake failure once it had to sign the
            // CertificateVerify is the key refusing to: locked, or waiting
            // for a user who may not be asked
            if keys.contains(status) || (asked && status == errSSLHandshakeFail) { return .clientKeyUnavailable }
            if alerts.contains(status) { return .clientCertificateRefused }
            return nil
        }
        if alerts.contains(status) || (asked && status == errSSLPeerHandshakeFail) {
            return .clientCertificateRequired
        }
        return nil
    }

    /// What tells this certificate apart for the stack, the same each time
    /// (`sipral_account_config_t::tls_client_tag`): the SHA-256 of the
    /// leaf's DER for an identity held, of the label for one the Keychain is
    /// asked for at each connection. Accounts whose tags match share a TLS
    /// connection; the others never do, since a connection presents one.
    var tag: String {
        switch source {
        case .identity(let held):
            var certificate: SecCertificate?
            if SecIdentityCopyCertificate(held, &certificate) == errSecSuccess, let certificate {
                return "leaf " + Self.hex(SHA256.hash(data: SecCertificateCopyData(certificate) as Data))
            }
            // no certificate to read: this identity alone, which
            // `presentable(at:)` then refuses
            return "identity \(UInt(bitPattern: ObjectIdentifier(self).hashValue))"
        case .keychain(let label):
            return "keychain " + Self.hex(SHA256.hash(data: Data(label.utf8)))
        }
    }

    private static func hex(_ digest: SHA256.Digest) -> String {
        digest.map { String(format: "%02x", $0) }.joined()
    }
    #else
    /// No certificate can be had where TLS cannot.
    var tag: String { "" }
    #endif
}

#if canImport(Network)
/// The few DER encodings (ITU-T X.690) a certification request takes and a
/// certificate's dates are read from.
enum Der {
    static let ecPublicKey: [UInt] = [1, 2, 840, 10045, 2, 1]
    static let prime256v1: [UInt] = [1, 2, 840, 10045, 3, 1, 7]
    static let ecdsaWithSha256: [UInt] = [1, 2, 840, 10045, 4, 3, 2]
    static let rsaEncryption: [UInt] = [1, 2, 840, 113549, 1, 1, 1]
    static let sha256WithRsa: [UInt] = [1, 2, 840, 113549, 1, 1, 11]
    static let commonName: [UInt] = [2, 5, 4, 3]

    static func element(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        var out = [tag]
        let count = content.count
        if count < 0x80 {
            out.append(UInt8(count))
        } else {
            var octets: [UInt8] = []
            var rest = count
            while rest > 0 {
                octets.insert(UInt8(rest & 0xFF), at: 0)
                rest >>= 8
            }
            out.append(0x80 | UInt8(octets.count))
            out += octets
        }
        return out + content
    }

    static func sequence(_ parts: [[UInt8]]) -> [UInt8] { element(0x30, parts.flatMap { $0 }) }
    static func set(_ parts: [[UInt8]]) -> [UInt8] { element(0x31, parts.flatMap { $0 }) }
    static func null() -> [UInt8] { [0x05, 0x00] }
    static func boolean(_ value: Bool) -> [UInt8] { [0x01, 0x01, value ? 0xFF : 0x00] }
    static func octetString(_ bytes: [UInt8]) -> [UInt8] { element(0x04, bytes) }
    static func utf8String(_ text: String) -> [UInt8] { element(0x0C, Array(text.utf8)) }
    /// No unused bits: every key and signature here is whole octets.
    static func bitString(_ bytes: [UInt8]) -> [UInt8] { element(0x03, [0] + bytes) }
    static func contextConstructed(_ number: UInt8, _ content: [UInt8]) -> [UInt8] {
        element(0xA0 | number, content)
    }
    static func contextPrimitive(_ number: UInt8, _ content: [UInt8]) -> [UInt8] {
        element(0x80 | number, content)
    }

    /// A non-negative integer from its big-endian magnitude.
    static func integer(_ magnitude: [UInt8]) -> [UInt8] {
        var bytes = Array(magnitude.drop { $0 == 0 })
        if bytes.isEmpty { bytes = [0] }
        if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
        return element(0x02, bytes)
    }

    static func oid(_ arcs: [UInt]) -> [UInt8] {
        var body = [UInt8(arcs[0] * 40 + arcs[1])]
        for arc in arcs.dropFirst(2) {
            var chunk = [UInt8(arc & 0x7F)]
            var rest = arc >> 7
            while rest > 0 {
                chunk.insert(UInt8(rest & 0x7F) | 0x80, at: 0)
                rest >>= 7
            }
            body += chunk
        }
        return element(0x06, body)
    }

    /// A Name of one common name (RFC 5280 §4.1.2.4).
    static func name(commonName text: String) -> [UInt8] {
        sequence([set([sequence([oid(commonName), utf8String(text)])])])
    }

    /// UTCTime through 2049, GeneralizedTime from 2050 (RFC 5280 §4.1.2.5).
    static func time(_ date: Date) -> [UInt8] {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let parts = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        let year = parts.year ?? 1970
        func two(_ value: Int?) -> String { String(format: "%02d", value ?? 0) }
        let rest = two(parts.month) + two(parts.day) + two(parts.hour) + two(parts.minute) + two(parts.second) + "Z"
        if year < 2050 {
            return element(0x17, Array((two(year % 100) + rest).utf8))
        }
        return element(0x18, Array((String(format: "%04d", year) + rest).utf8))
    }

    /// One element at `offset`: its tag, where its content starts and how
    /// long it is; `nil` past the end or for a length this reader refuses.
    static func read(_ bytes: [UInt8], at offset: Int) -> (tag: UInt8, start: Int, length: Int)? {
        guard offset + 2 <= bytes.count else { return nil }
        let first = bytes[offset + 1]
        var start = offset + 2
        var length = Int(first)
        if first & 0x80 != 0 {
            let count = Int(first & 0x7F)
            guard count > 0, count <= 4, start + count <= bytes.count else { return nil }
            length = bytes[start..<start + count].reduce(0) { $0 << 8 | Int($1) }
            start += count
        }
        guard start + length <= bytes.count else { return nil }
        return (bytes[offset], start, length)
    }

    /// The certificate's notBefore and notAfter (RFC 5280 §4.1.2.5).
    static func validity(ofCertificate certificate: [UInt8]) -> (Date, Date)? {
        guard let outer = read(certificate, at: 0), outer.tag == 0x30,
              let tbs = read(certificate, at: outer.start), tbs.tag == 0x30 else { return nil }
        var at = tbs.start
        guard var field = read(certificate, at: at) else { return nil }
        if field.tag == 0xA0 {
            at = field.start + field.length
            guard let next = read(certificate, at: at) else { return nil }
            field = next
        }
        // serial, signature, issuer, then validity
        for _ in 0..<3 {
            at = field.start + field.length
            guard let next = read(certificate, at: at) else { return nil }
            field = next
        }
        guard field.tag == 0x30, let from = read(certificate, at: field.start),
              let until = read(certificate, at: from.start + from.length),
              let notBefore = date(certificate, from), let notAfter = date(certificate, until) else { return nil }
        return (notBefore, notAfter)
    }

    private static func date(_ bytes: [UInt8], _ field: (tag: UInt8, start: Int, length: Int)) -> Date? {
        let text = String(decoding: bytes[field.start..<field.start + field.length], as: UTF8.self)
        let digits = text.hasSuffix("Z") ? String(text.dropLast()) : text
        guard digits.allSatisfy(\.isNumber) else { return nil }
        let full: String
        switch (field.tag, digits.count) {
        case (0x17, 12):
            let year = Int(digits.prefix(2)) ?? 0
            full = (year >= 50 ? "19" : "20") + digits
        case (0x18, 14):
            full = digits
        default:
            return nil
        }
        let numbers = stride(from: 4, to: 14, by: 2).map { Int(full.dropFirst($0).prefix(2)) ?? 0 }
        var parts = DateComponents()
        parts.year = Int(full.prefix(4))
        (parts.month, parts.day, parts.hour, parts.minute, parts.second) =
            (numbers[0], numbers[1], numbers[2], numbers[3], numbers[4])
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar.date(from: parts)
    }
}
#endif
