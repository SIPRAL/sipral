// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import XCTest
@testable import SipralPhone

/// A secret store in memory, to see what reaches it and what does not.
final class MemorySecrets: SecretStore {
    var values: [String: String] = [:]

    func read(_ key: String) throws -> String? { values[key] }

    func write(_ value: String?, for key: String) throws {
        values[key] = value?.isEmpty == false ? value : nil
    }
}

/// The account as typed, as saved, and as dialled.
final class PhoneSettingsTests: XCTestCase {
    private var suite: String!
    private var defaults: UserDefaults!

    override func setUp() {
        suite = "org.sipral.phone.tests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suite)
    }

    private func sample() -> PhoneSettings {
        var settings = PhoneSettings()
        settings.server = "pbx.example.com"
        settings.port = 5080
        settings.transport = .tls
        settings.user = "152"
        return settings
    }

    func testTheDomainIsTheServersNameUnlessOneIsGiven() {
        var settings = sample()
        XCTAssertEqual(settings.aor, "sip:152@pbx.example.com")
        XCTAssertEqual(settings.registrar, "sip:pbx.example.com")
        XCTAssertEqual(settings.effectiveAuthUser, "152")
        settings.domain = "example.com"
        settings.authUser = "u152"
        XCTAssertEqual(settings.aor, "sip:152@example.com")
        XCTAssertEqual(settings.registrar, "sip:example.com")
        XCTAssertEqual(settings.effectiveAuthUser, "u152")
    }

    func testWhatIsDialledBecomesAUriAtTheAccountsDomain() {
        let settings = sample()
        XCTAssertEqual(settings.target(for: "170"), "sip:170@pbx.example.com")
        XCTAssertEqual(settings.target(for: " *43 "), "sip:*43@pbx.example.com")
        XCTAssertEqual(settings.target(for: "bob@example.org"), "sip:bob@example.org")
        XCTAssertEqual(settings.target(for: "sips:bob@example.org"), "sips:bob@example.org")
        XCTAssertEqual(settings.target(for: "tel:+40211234567"), "tel:+40211234567")
    }

    func testAnAccountWithoutServerOrUserIsIncomplete() {
        XCTAssertFalse(PhoneSettings().isComplete)
        var settings = sample()
        XCTAssertTrue(settings.isComplete)
        settings.port = 0
        XCTAssertFalse(settings.isComplete)
    }

    /// The password goes to the secret store and appears nowhere in the
    /// defaults; the rest comes back as it was saved.
    func testThePasswordIsKeptOnlyInTheSecretStore() throws {
        let secrets = MemorySecrets()
        let store = SettingsStore(defaults: defaults, secrets: secrets)
        let password = "correct-horse-battery-staple"
        try store.save(sample(), password: password)

        XCTAssertEqual(store.load(), sample())
        XCTAssertEqual(try store.password(), password)
        let saved = defaults.persistentDomain(forName: suite) ?? [:]
        let everything = try PropertyListSerialization.data(fromPropertyList: saved, format: .xml, options: 0)
        XCTAssertFalse(String(decoding: everything, as: UTF8.self).contains(password))
        for value in saved.values {
            if let data = value as? Data {
                XCTAssertFalse(String(decoding: data, as: UTF8.self).contains(password))
            }
        }

        try store.save(sample(), password: "")
        XCTAssertNil(try store.password(), "an emptied password stays behind")
    }

    func testNothingSavedLoadsAnEmptyAccount() {
        let store = SettingsStore(defaults: defaults, secrets: MemorySecrets())
        XCTAssertEqual(store.load(), PhoneSettings())
        XCTAssertNil(store.voipToken)
        store.voipToken = [0x01, 0xab]
        XCTAssertEqual(store.voipToken, [0x01, 0xab])
    }

    /// The real keychain, as the application's own process sees it.
    func testTheKeychainKeepsReplacesAndRemovesAPassword() throws {
        let keychain = KeychainSecretStore(service: suite)
        defer { try? keychain.write(nil, for: "p") }
        XCTAssertNil(try keychain.read("p"))
        try keychain.write("first", for: "p")
        XCTAssertEqual(try keychain.read("p"), "first")
        try keychain.write("second", for: "p")
        XCTAssertEqual(try keychain.read("p"), "second")
        try keychain.write(nil, for: "p")
        XCTAssertNil(try keychain.read("p"))
    }
}
