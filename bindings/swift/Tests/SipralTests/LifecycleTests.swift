// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(CryptoKit)
import Foundation
import XCTest
@testable import Sipral

/// A snapshot store in memory, standing in for the Keychain.
final class MemorySnapshotStore: SipralSnapshotStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: [UInt8]] = [:]

    var keys: [String] { lock.withLock { Array(values.keys) } }

    func read(_ key: String) throws -> [UInt8]? { lock.withLock { values[key] } }

    func write(_ value: [UInt8]?, for key: String) throws {
        lock.withLock { values[key] = value }
    }
}

/// What a mobile application calls as it goes to the background and comes
/// back, and the registration it carries into a later process
/// (`docs/15-mobile.md`, "C3").
final class LifecycleTests: XCTestCase {
    private func until(_ seconds: Double = 5, _ what: () throws -> Bool) async throws -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while try !what(), Date() < deadline {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        return try what()
    }

    private func registeredAccount(on stack: SipralStack, registrar: DatagramRegistrar) async throws -> Account {
        let account = try stack.addAccount(
            aor: "sip:alice@example.com", registrarAddress: registrar.address, registrar: "sip:example.com"
        )
        try account.register()
        let registered = try await until { try account.registrationState == .registered }
        XCTAssertTrue(registered, "the account never registered")
        return account
    }

    /// The binding stops being believed on the way into suspend, nothing is
    /// sent then, and the way back proves it with a REGISTER.
    func testSuspendingSendsNothingAndResumingRegistersAgain() async throws {
        let registrar = try DatagramRegistrar()
        defer { registrar.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try await registeredAccount(on: stack, registrar: registrar)
        let before = registrar.registers.count

        let suspended = try stack.suspending()
        XCTAssertEqual(suspended.unverified, 1)
        XCTAssertEqual(suspended.subscriptions, 0)
        XCTAssertEqual(suspended.calls, 0)
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertEqual(registrar.registers.count, before, "something was sent on the way into suspend")

        try stack.resumed()
        let proved = try await until { registrar.registers.count > before }
        XCTAssertTrue(proved, "no REGISTER after resuming")
        let again = try await until { try account.registrationState == .registered }
        XCTAssertTrue(again)
    }

    func testResumingWithoutSuspendingAndLosingTheNetworkAreSafe() throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        try stack.resumed()
        try stack.suspending()
        try stack.resumed()
        try stack.interfaceLost()
        try stack.nameResolutionLost()
    }

    /// The whole cold start after a push, across two processes: written
    /// down on the way into the background, the first process gone without
    /// unregistering, read back in a new stack that comes up `.restored`,
    /// and the push's refresh continuing the same binding.
    func testARegistrationWrittenDownComesBackRestoredAndThePushRefreshContinuesIt() async throws {
        let registrar = try DatagramRegistrar()
        defer { registrar.stop() }
        let store = MemorySnapshotStore()
        var wallClock: UInt64 = 1_790_000_000_000

        let first = try SipralStack(audio: .application)
        let lifecycle = SipralAppLifecycle(store: store, clock: { [wallClock] in wallClock })
        try lifecycle.launched(first)
        let account = try await registeredAccount(on: first, registrar: registrar)
        lifecycle.keep(account, key: "alice")
        let suspended = try XCTUnwrap(lifecycle.enteredBackground())
        XCTAssertEqual(suspended.unverified, 1)
        XCTAssertEqual(store.keys, ["sipral.registration.alice"])
        let callId = FakeRegistrarHeader.header("Call-ID", registrar.registers.last ?? "")
        let sent = registrar.registers.count
        first.close()

        wallClock += 90_000
        let second = try SipralStack(audio: .application)
        defer { second.close() }
        let woken = SipralAppLifecycle(store: store, clock: { [wallClock] in wallClock })
        try woken.launched(second)
        let restored = try second.addAccount(
            aor: "sip:alice@example.com", registrarAddress: registrar.address, registrar: "sip:example.com"
        )
        XCTAssertTrue(woken.restore(restored, key: "alice"))
        XCTAssertEqual(try restored.registrationState, .restored)
        XCTAssertTrue(restored.wantsRegistration)
        XCTAssertNil(try restored.timeToReadyMs(), "ready before any registrar answered")

        try restored.refreshBinding()
        let confirmed = try await until { try restored.registrationState == .registered }
        XCTAssertTrue(confirmed, "the refresh never confirmed the restored binding")
        let refresh = try XCTUnwrap(registrar.registers.dropFirst(sent).first, "no REGISTER from the new process")
        XCTAssertEqual(FakeRegistrarHeader.header("Call-ID", refresh), callId, "a second registration, not the same binding")
        XCTAssertNotNil(try restored.timeToReadyMs())
    }

    /// A snapshot written for another address of record is refused, and
    /// removed so it is not tried again; nothing written is no restore.
    func testAnotherAccountsSnapshotIsRefusedAndForgotten() async throws {
        let registrar = try DatagramRegistrar()
        defer { registrar.stop() }
        let store = MemorySnapshotStore()
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let lifecycle = SipralAppLifecycle(store: store)
        lifecycle.stack = stack
        let account = try await registeredAccount(on: stack, registrar: registrar)
        lifecycle.keep(account, key: "alice")
        XCTAssertNotNil(lifecycle.enteredBackground())
        lifecycle.enteredForeground()

        let bob = try stack.addAccount(
            aor: "sip:bob@example.com", registrarAddress: registrar.address, registrar: "sip:example.com"
        )
        let failures = Written()
        lifecycle.storageFailed = { failures.add("\($0)") }
        XCTAssertFalse(lifecycle.restore(bob, key: "alice"))
        XCTAssertEqual(failures.all.count, 1)
        XCTAssertEqual(store.keys, [], "a refused snapshot was kept")
        XCTAssertFalse(lifecycle.restore(bob, key: "nobody"))
    }

    /// An account with nothing worth keeping removes what an earlier
    /// background had written, and freezing it says why.
    func testAnAccountThatNeverRegisteredWritesNothingDown() throws {
        let store = MemorySnapshotStore()
        try store.write([0, 0, 0, 0, 0, 0, 0, 1, 42], for: "sipral.registration.bob")
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:bob@example.com", registrarAddress: "127.0.0.1:9", registrar: "sip:example.com")
        XCTAssertThrowsError(try account.freeze()) {
            XCTAssertEqual(($0 as? SipralError)?.status, .wrongState)
        }
        let lifecycle = SipralAppLifecycle(store: store)
        lifecycle.stack = stack
        lifecycle.keep(account, key: "bob")
        XCTAssertNotNil(lifecycle.enteredBackground())
        XCTAssertEqual(store.keys, [])
    }

    func testBytesThatAreNotASnapshotAreRefusedAndTheAccountIsLeftAlone() throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:bob@example.com", registrarAddress: "127.0.0.1:9", registrar: "sip:example.com")
        XCTAssertThrowsError(try account.thaw([1, 2, 3], asleepMs: 0)) {
            XCTAssertEqual(($0 as? SipralError)?.status, .invalidArgument)
        }
        XCTAssertFalse(account.wantsRegistration)
    }

    func testTheRecordKeepsWhenItWasWritten() {
        let record = SipralAppLifecycle.record(writtenAt: 0x0102_0304_0506_0708, snapshot: [9, 10])
        XCTAssertEqual(record, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        let read = SipralAppLifecycle.record(from: record)
        XCTAssertEqual(read?.writtenAt, 0x0102_0304_0506_0708)
        XCTAssertEqual(read?.snapshot, [9, 10])
        XCTAssertNil(SipralAppLifecycle.record(from: [1, 2, 3, 4, 5, 6, 7, 8]))
    }

    /// With a call up the process is not suspended and nothing is written.
    func testNothingIsSuspendedWithACallUp() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let aliceAccount = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        let bobEvents = Recorder(bob.events())
        let call = try alice.placeCall(account: aliceAccount, target: "sip:bob@\(bob.bindAddress)")
        defer { call.close() }
        let arrived = await bobEvents.first(within: 5) { $0.kind == .incomingCall }
        XCTAssertNotNil(arrived)
        let store = MemorySnapshotStore()
        let lifecycle = SipralAppLifecycle(store: store)
        lifecycle.stack = alice
        XCTAssertNil(lifecycle.enteredBackground(), "suspended with a call ringing")
        try call.hangup()
        let ended = try await until { call.ended }
        XCTAssertTrue(ended)
        XCTAssertNotNil(lifecycle.enteredBackground(), "not suspended once the call had ended")
    }
}
#endif
