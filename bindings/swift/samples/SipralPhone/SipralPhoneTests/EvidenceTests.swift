// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import XCTest
@testable import SipralPhone

/// The log file and the one file "Share log" hands over.
final class EvidenceTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private static let timed = try! NSRegularExpression(
        pattern: #"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z (app|stack) "#
    )

    private func isTimed(_ line: String) -> Bool {
        Self.timed.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) != nil
    }

    func testEveryLineIsTimedAndTheApplicationsAreKeptForTheScreen() throws {
        let log = EvidenceLog(directory: directory.appendingPathComponent("Logs"))
        log.note("launch")
        log.stack(level: "debug", target: "sipral_ua", message: "REGISTER sent")
        log.flush()
        let text = try String(contentsOf: log.current, encoding: .utf8)
        let lines = text.split(separator: "\n").map(String.init)
        XCTAssertEqual(lines.count, 2)
        XCTAssertTrue(lines.allSatisfy(isTimed), text)
        XCTAssertTrue(lines[1].hasSuffix("stack debug sipral_ua REGISTER sent"), lines[1])
        XCTAssertEqual(log.recent.count, 1)
        XCTAssertTrue(log.recent[0].hasSuffix("app launch"))
    }

    /// A whole SIP message spans lines, and every one of them is timed.
    func testEveryLineOfAWholeMessageIsTimed() throws {
        let log = EvidenceLog(directory: directory.appendingPathComponent("Logs"))
        log.stack(level: "trace", target: "sip", message: "sent to 192.0.2.1:5060, 40 bytes:\r\nOPTIONS sip:a@b SIP/2.0\r\nCSeq: 1 OPTIONS\r\n")
        log.flush()
        let lines = try String(contentsOf: log.current, encoding: .utf8).split(separator: "\n").map(String.init)
        XCTAssertEqual(lines.count, 4)
        XCTAssertTrue(lines.allSatisfy(isTimed), lines.joined(separator: "\n"))
        XCTAssertTrue(lines[1].hasSuffix("stack trace sip | OPTIONS sip:a@b SIP/2.0"), lines[1])
    }

    /// Past the limit the file becomes the previous one; two are kept, and
    /// a new log on the same directory carries on in the current one.
    func testTheLogTurnsOverIntoOnePreviousFile() throws {
        let logs = directory.appendingPathComponent("Logs")
        let log = EvidenceLog(directory: logs, maxBytes: 400)
        for index in 0..<20 {
            log.note("line \(index)")
        }
        log.flush()
        XCTAssertEqual(log.files.map(\.lastPathComponent), [EvidenceLog.previousName, EvidenceLog.fileName])
        let current = try String(contentsOf: log.current, encoding: .utf8)
        XCTAssertTrue(current.contains("app line 19"))
        let size = try Data(contentsOf: log.current).count
        XCTAssertLessThanOrEqual(size, 400)

        let again = EvidenceLog(directory: logs, maxBytes: 400)
        again.note("after a relaunch")
        again.flush()
        XCTAssertTrue(try String(contentsOf: again.current, encoding: .utf8).contains("after a relaunch"))
    }

    /// One file: every section, the log as written, and the password gone
    /// from all of it, wherever a line had carried it.
    func testTheBundleHoldsEverySectionAndNoPassword() throws {
        let password = "s3cret-Pa55"
        let log = EvidenceLog(directory: directory.appendingPathComponent("Logs"))
        log.note("account saved")
        log.stack(level: "trace", target: "sipral_ua", message: "a line that should never hold \(password)")
        log.flush()
        let date = Date(timeIntervalSince1970: 1_790_000_000)
        let url = try EvidenceBundle.write(
            into: directory.appendingPathComponent("Evidence"),
            at: date,
            about: [("account", "sip:152@pbx.example.com"), ("note", "typed \(password) by mistake")],
            logFiles: log.files,
            decisions: #"{"records_dropped":0,"records":[]}"#,
            state: "accounts: 1",
            secrets: [password, ""]
        )
        XCTAssertEqual(url.lastPathComponent, "sipral-phone-20260921-141320Z.txt")
        let text = try String(contentsOf: url, encoding: .utf8)
        XCTAssertFalse(text.contains(password))
        XCTAssertTrue(text.contains("[removed]"))
        for section in ["== about ==", "== log (application and stack, oldest first) ==",
                        "== decisions (sipral_stack_diagnostics_json) ==", "== state (sipral_stack_state_text) =="] {
            XCTAssertTrue(text.contains(section), "missing \(section)")
        }
        XCTAssertTrue(text.contains(#"{"records_dropped":0,"records":[]}"#))
        XCTAssertTrue(text.hasPrefix("Sipral Phone evidence, written 2026-09-21T14:13:20.000Z"))
        let logLines = text.components(separatedBy: "== log (application and stack, oldest first) ==\n")[1]
            .components(separatedBy: "\n\n== decisions")[0]
            .split(separator: "\n").map(String.init)
        XCTAssertEqual(logLines.count, 2)
        XCTAssertTrue(logLines.allSatisfy(isTimed))
    }
}
