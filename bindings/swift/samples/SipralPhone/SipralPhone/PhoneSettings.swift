// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Foundation
import Security

/// How SIP travels to the server.
enum SignallingChoice: String, CaseIterable, Codable, Identifiable {
    case udp, tcp, tls
    var id: String { rawValue }
    var label: String { rawValue.uppercased() }
}

/// Whether calls offer SRTP (RFC 4568 keys in the SDP).
enum SrtpChoice: String, CaseIterable, Codable, Identifiable {
    case off, offered, required
    var id: String { rawValue }
}

/// One account, everything but the password. Kept in `UserDefaults`; the
/// password is the `SecretStore`'s.
struct PhoneSettings: Codable, Equatable {
    /// The server's name or address, without port.
    var server = ""
    var port: UInt16 = 5060
    var transport: SignallingChoice = .udp
    /// The user part of the address of record, and the user the password
    /// answers for unless `authUser` says otherwise.
    var user = ""
    var authUser = ""
    /// The address of record's domain, when it is not the server's name.
    var domain = ""
    var displayName = ""
    var srtp: SrtpChoice = .off
    /// Off for a peer with no registrar: calls go straight to the server.
    var registers = true
    /// `host:port`, or empty for none.
    var stunServer = ""
    /// Whole SIP messages in the log (credentials and keys still removed).
    var wholeMessages = true

    var isComplete: Bool { !server.isEmpty && !user.isEmpty && port != 0 }
    var effectiveDomain: String { domain.isEmpty ? server : domain }
    var aor: String { "sip:\(user)@\(effectiveDomain)" }
    var registrar: String { "sip:\(effectiveDomain)" }
    var effectiveAuthUser: String { authUser.isEmpty ? user : authUser }

    /// What the dial pad typed, as a URI: a bare number or name is a user
    /// at the account's domain, anything with a scheme is taken as it is.
    func target(for typed: String) -> String {
        let trimmed = typed.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("sip:") || trimmed.hasPrefix("sips:") || trimmed.hasPrefix("tel:") {
            return trimmed
        }
        if trimmed.contains("@") {
            return "sip:\(trimmed)"
        }
        return "sip:\(trimmed)@\(effectiveDomain)"
    }
}

/// Where the password lives.
protocol SecretStore: AnyObject {
    func read(_ key: String) throws -> String?
    /// `nil` removes it.
    func write(_ value: String?, for key: String) throws
}

struct KeychainError: Error, CustomStringConvertible {
    let status: OSStatus
    var description: String { "keychain status \(status)" }
}

/// Generic passwords under one service, readable after the first unlock
/// (a push may wake the application while the phone is locked) and never
/// carried to another device by a backup.
final class KeychainSecretStore: SecretStore {
    private let service: String

    init(service: String) {
        self.service = service
    }

    private func query(_ key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
    }

    func read(_ key: String) throws -> String? {
        var request = query(key)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var found: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &found)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = found as? Data else { throw KeychainError(status: status) }
        return String(decoding: data, as: UTF8.self)
    }

    func write(_ value: String?, for key: String) throws {
        let removed = SecItemDelete(query(key) as CFDictionary)
        guard removed == errSecSuccess || removed == errSecItemNotFound else { throw KeychainError(status: removed) }
        guard let value, !value.isEmpty else { return }
        var item = query(key)
        item[kSecValueData as String] = Data(value.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let added = SecItemAdd(item as CFDictionary, nil)
        guard added == errSecSuccess else { throw KeychainError(status: added) }
    }
}

/// The account as saved: settings as JSON in `UserDefaults`, the password
/// in the `SecretStore` and nowhere else.
final class SettingsStore {
    static let settingsKey = "account"
    static let passwordKey = "account.password"
    static let tokenKey = "push.voip-token"

    private let defaults: UserDefaults
    private let secrets: SecretStore

    init(defaults: UserDefaults, secrets: SecretStore) {
        self.defaults = defaults
        self.secrets = secrets
    }

    func load() -> PhoneSettings {
        guard let data = defaults.data(forKey: Self.settingsKey),
              let settings = try? JSONDecoder().decode(PhoneSettings.self, from: data) else { return PhoneSettings() }
        return settings
    }

    func password() throws -> String? {
        try secrets.read(Self.passwordKey)
    }

    func save(_ settings: PhoneSettings, password: String?) throws {
        defaults.set(try JSONEncoder().encode(settings), forKey: Self.settingsKey)
        try secrets.write(password, for: Self.passwordKey)
    }

    /// The last VoIP token PushKit issued, so a launch a push woke can put
    /// it on the first REGISTER before PushKit says it again.
    var voipToken: [UInt8]? {
        get { defaults.data(forKey: Self.tokenKey).map { Array($0) } }
        set { defaults.set(newValue.map { Data($0) }, forKey: Self.tokenKey) }
    }
}
