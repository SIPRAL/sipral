// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
#if canImport(OSLog)
import OSLog
#endif
import XCTest
@testable import Sipral

/// The log, the state snapshot and the RTP port range, carried through
/// `SipralStack` -- the Swift counterpart of
/// `bindings/python/tests/test_logging.py`.
final class LoggingTests: XCTestCase {
    /// A call the stack refuses: a stack with no RTP range has no port to
    /// reserve.
    private func refuse(_ stack: SipralStack) -> SipralStatus? {
        do {
            _ = try Sipral.stackRtpPortReserve(stack: stack.handle)
            return .ok
        } catch {
            return (error as? SipralError)?.status
        }
    }

    /// Every line a handler heard, from whichever thread delivered it.
    private final class Heard: @unchecked Sendable {
        private let lock = NSLock()
        private var lines: [(SipralLogLevel, String, String, UInt64)] = []

        func add(_ line: (SipralLogLevel, String, String, UInt64)) {
            lock.lock(); defer { lock.unlock() }
            lines.append(line)
        }

        var all: [(SipralLogLevel, String, String, UInt64)] {
            lock.lock(); defer { lock.unlock() }
            return lines
        }
    }

    /// A null callback is how C turns the log and a screening policy off,
    /// and the generated wrappers took neither a null callback nor a null
    /// pointer beside it, so this did not compile.
    func testTheGeneratedWrappersTakeANullListener() throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        // the stack's own poll thread may hold it for a moment: wait that out
        func retrying(_ body: () throws -> Void) throws {
            for _ in 0..<500 {
                do {
                    try body()
                    return
                } catch let refused as SipralError where refused.status == .busy {
                    Thread.sleep(forTimeInterval: 0.001)
                }
            }
            try body()
        }
        try retrying {
            try Sipral.stackLog(stack: stack.handle, level: SipralLogLevel.off.rawValue, callback: nil, userData: nil)
        }
        try retrying { try Sipral.stackScreen(stack: stack.handle, callback: nil, userData: nil) }
    }

    func testARefusedCallIsLoggedWithNobodyInIt() throws {
        let features = try Sipral.capabilities().features
        XCTAssertNotEqual(features & Sipral.featureLogging, 0)
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let heard = Heard()
        try stack.setLog(level: .debug) { level, target, message, suppressed in
            heard.add((level, target, message, suppressed))
        }

        XCTAssertEqual(refuse(stack), .wrongState)
        let line = try XCTUnwrap(heard.all.first, "the refusal was never logged")
        XCTAssertEqual(line.0, .debug)
        XCTAssertEqual(line.1, "api")
        XCTAssertTrue(line.2.hasPrefix("refused, WrongState"), line.2)
        XCTAssertEqual(line.3, 0)
        XCTAssertFalse(line.2.contains("127.0.0.1"), line.2)

        try stack.setLog(level: .off, handler: nil)
        let count = heard.all.count
        XCTAssertEqual(refuse(stack), .wrongState)
        XCTAssertEqual(heard.all.count, count, "a log turned off says nothing")
    }

    func testTheStateNamesTheAccountAndNotThePerson() throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        _ = try stack.addAccount(aor: "sip:alice@example.invalid", registrarAddress: "127.0.0.1:5999")
        let text = try stack.state()
        for expected in ["accounts: 1", "transports: 1", "counters: "] {
            XCTAssertTrue(text.contains(expected), "\(expected) missing from:\n\(text)")
        }
        XCTAssertFalse(text.contains("alice"), text)
        XCTAssertFalse(text.contains("127.0.0.1"), text)
    }

    func testACallIsCarriedOnEvenPortsFromEachStacksRange() async throws {
        let alice = try SipralStack(audio: .application, rtpPortMin: 47200, rtpPortMax: 47219)
        let bob = try SipralStack(audio: .application, rtpPortMin: 47300, rtpPortMax: 47319)
        defer { alice.close(); bob.close() }
        let account = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        let bobEvents = Recorder(bob.events())

        let aliceCall = try alice.placeCall(account: account, target: "sip:bob@\(bob.bindAddress)")
        defer { aliceCall.close() }
        let rang = await bobEvents.first(within: 5) { $0.kind == .incomingCall }
        let bobCall = try bob.answerCall(try XCTUnwrap(rang, "the call never reached Bob"))
        defer { bobCall.close() }

        let deadline = DispatchTime.now() + 5
        while (aliceCall.media == nil || bobCall.media == nil) && DispatchTime.now() < deadline {
            usleep(20_000)
        }
        XCTAssertNotNil(aliceCall.media)
        XCTAssertNotNil(bobCall.media)
        for (call, low, high) in [(aliceCall, 47200, 47219), (bobCall, 47300, 47319)] {
            let port = try XCTUnwrap(call.mediaAddress.split(separator: ":").last.flatMap { Int($0) })
            XCTAssertTrue(port >= low && port < high && port % 2 == 0, "media on \(port)")
        }
    }

    #if canImport(OSLog)
    /// `logTo(subsystem:level:)`: a registrar's refusal -- a warning, which
    /// the unified logging system keeps where it drops debug lines -- reaches
    /// it under the category of its target, read back from this process's own
    /// log store.
    func testALineReachesTheUnifiedLogUnderItsTarget() throws {
        let subsystem = "org.sipral.test.\(UUID().uuidString)"
        let registrar = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { registrar.close() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let since = Date().addingTimeInterval(-1)
        try stack.logTo(subsystem: subsystem, level: .info)
        let account = try stack.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: registrar.localAddress, registrar: "sip:sipral.invalid"
        )
        try account.register()
        let refused = DispatchTime.now() + 5
        var answered = false
        while !answered && DispatchTime.now() < refused {
            if let (data, source) = registrar.receive() {
                let request = String(decoding: data, as: UTF8.self)
                if request.hasPrefix("REGISTER ") {
                    _ = registrar.send(forbidden(to: request), to: source)
                    answered = true
                }
            } else {
                usleep(10_000)
            }
        }
        XCTAssertTrue(answered, "no REGISTER reached the registrar")

        let store = try OSLogStore(scope: .currentProcessIdentifier)
        let matching = NSPredicate(format: "subsystem == %@", subsystem)
        var found: OSLogEntryLog?
        let deadline = Date().addingTimeInterval(5)
        while found == nil && Date() < deadline {
            found = try store.getEntries(at: store.position(date: since), matching: matching)
                .compactMap { $0 as? OSLogEntryLog }
                .first { $0.category == "registration" && $0.level == .notice }
            if found == nil { usleep(100_000) }
        }
        let entry = try XCTUnwrap(found, "no warning reached the unified log under \(subsystem)")
        XCTAssertFalse(entry.composedMessage.contains("<private>"), entry.composedMessage)
        XCTAssertFalse(entry.composedMessage.contains("alice"), entry.composedMessage)
        XCTAssertEqual(SipralLogLevel.warn.osLogType, .default)
        XCTAssertEqual(SipralLogLevel.error.osLogType, .error)
        XCTAssertEqual(SipralLogLevel.trace.osLogType, .debug)
    }

    /// A registrar's `403 Forbidden` to `request`.
    private func forbidden(to request: String) -> [UInt8] {
        let lines = request.components(separatedBy: "\r\n")
        let copied = ["Via", "From", "To", "Call-ID", "CSeq"].compactMap { name in
            lines.first { $0.lowercased().hasPrefix("\(name.lowercased()):") }
        }
        let head = ["SIP/2.0 403 Forbidden"] + copied.map { $0.lowercased().hasPrefix("to:") ? "\($0);tag=registrar" : $0 }
        return Array((head + ["Content-Length: 0", "", ""]).joined(separator: "\r\n").utf8)
    }
    #endif

    func testARequestNobodyAnswersIsCountedAsSentAgain() throws {
        let silent = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { silent.close() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        XCTAssertEqual(try stack.counters().requestsRetransmitted, 0)
        let account = try stack.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: silent.localAddress, registrar: "sip:sipral.invalid"
        )
        try account.register()
        let deadline = DispatchTime.now() + 5
        while try stack.counters().requestsRetransmitted == 0 && DispatchTime.now() < deadline {
            usleep(100_000)
        }
        let counters = try stack.counters()
        XCTAssertGreaterThan(counters.requestsRetransmitted, 0)
        XCTAssertGreaterThan(counters.registrationsAttempted, 0)
        XCTAssertEqual(counters.requestsRefusedAtLimit, 0)
    }

    func testARangeWithNoPairLeftSaysSo() throws {
        let stack = try SipralStack(audio: .application, rtpPortMin: 47400, rtpPortMax: 47401)
        defer { stack.close() }
        let first = try stack.openMediaSocket(host: "127.0.0.1")
        defer { first.close() }
        XCTAssertTrue(first.localAddress.hasSuffix(":47400"), first.localAddress)
        XCTAssertThrowsError(try stack.openMediaSocket(host: "127.0.0.1")) { error in
            XCTAssertEqual((error as? SipralError)?.status, .exhausted)
        }
    }
}
