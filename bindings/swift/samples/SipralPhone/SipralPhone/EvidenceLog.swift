// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Foundation

/// Every line the application and the stack write, each with its time, in
/// one file that survives the process: a launch a push woke shares what the
/// run before it saw. At `maxBytes` the file becomes the previous one and a
/// new one starts, so two files at most are kept.
final class EvidenceLog: @unchecked Sendable {
    static let fileName = "sipral-phone.log"
    static let previousName = "sipral-phone.1.log"

    let directory: URL
    private let maxBytes: Int
    private let queue = DispatchQueue(label: "org.sipral.phone.log")
    private var handle: FileHandle?
    private var written = 0
    private var recentLines: [String] = []
    private let recentLimit: Int
    /// Told of every application line, on the log's own queue.
    var onNote: (@Sendable (String) -> Void)?

    init(directory: URL, maxBytes: Int = 4_000_000, recentLimit: Int = 300) {
        self.directory = directory
        self.maxBytes = maxBytes
        self.recentLimit = recentLimit
    }

    var current: URL { directory.appendingPathComponent(Self.fileName) }
    var previous: URL { directory.appendingPathComponent(Self.previousName) }

    /// The files to share, oldest first.
    var files: [URL] {
        [previous, current].filter { FileManager.default.fileExists(atPath: $0.path) }
    }

    /// The application's own lines, newest last.
    var recent: [String] { queue.sync { recentLines } }

    static func timestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    /// One line of the application's own.
    func note(_ text: String, at date: Date = Date()) {
        let line = "\(Self.timestamp(date)) app \(text)"
        queue.async {
            self.recentLines.append(line)
            if self.recentLines.count > self.recentLimit {
                self.recentLines.removeFirst(self.recentLines.count - self.recentLimit)
            }
            self.append(line)
            self.onNote?(line)
        }
    }

    /// One line of the stack's log, already redacted by the stack. A whole
    /// SIP message spans lines; each carries the time and `|` after the
    /// target, so every line of the file is timed and greppable alone.
    func stack(level: String, target: String, message: String, at date: Date = Date()) {
        let prefix = "\(Self.timestamp(date)) stack \(level) \(target)"
        let parts = message.replacingOccurrences(of: "\r\n", with: "\n").split(separator: "\n", omittingEmptySubsequences: false)
        let lines = parts.enumerated().map { index, part in
            index == 0 ? "\(prefix) \(part)" : "\(prefix) | \(part)"
        }
        queue.async { self.append(lines.joined(separator: "\n")) }
    }

    /// Waits for every line handed over so far to be written.
    func flush() {
        queue.sync { try? handle?.synchronize() }
    }

    private func append(_ line: String) {
        let bytes = Data((line + "\n").utf8)
        if handle == nil || written + bytes.count > maxBytes {
            rotateIfNeeded(adding: bytes.count)
        }
        handle?.write(bytes)
        written += bytes.count
    }

    private func rotateIfNeeded(adding count: Int) {
        let manager = FileManager.default
        if handle == nil {
            open()
        }
        if written + count > maxBytes, written > 0 {
            try? handle?.close()
            handle = nil
            try? manager.removeItem(at: previous)
            try? manager.moveItem(at: current, to: previous)
            open()
        }
    }

    /// The current file, created if missing, positioned at its end.
    private func open() {
        let manager = FileManager.default
        try? manager.createDirectory(at: directory, withIntermediateDirectories: true)
        if !manager.fileExists(atPath: current.path) {
            manager.createFile(atPath: current.path, contents: nil)
        }
        handle = try? FileHandle(forWritingTo: current)
        written = Int((try? handle?.seekToEnd()) ?? 0)
    }
}

/// The one file "Share log" hands over: what the phone and the stack were,
/// every logged line, the stack's decision record and its state, each
/// section headed and every line timed. Any secret given is taken out of
/// all of it, wherever it appears, before the file is written; the stack's
/// own lines have had credentials removed already.
enum EvidenceBundle {
    static func fileName(at date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return "sipral-phone-\(formatter.string(from: date))Z.txt"
    }

    static func write(
        into directory: URL,
        at date: Date = Date(),
        about: [(String, String)],
        logFiles: [URL],
        decisions: String?,
        state: String?,
        secrets: [String]
    ) throws -> URL {
        var text = "Sipral Phone evidence, written \(EvidenceLog.timestamp(date))\n"
        text += "\n== about ==\n"
        for (name, value) in about {
            text += "\(name): \(value)\n"
        }
        text += "\n== log (application and stack, oldest first) ==\n"
        for file in logFiles {
            text += (try? String(contentsOf: file, encoding: .utf8)) ?? "(\(file.lastPathComponent) unreadable)\n"
        }
        text += "\n== decisions (sipral_stack_diagnostics_json) ==\n"
        text += (decisions ?? "(no stack)") + "\n"
        text += "\n== state (sipral_stack_state_text) ==\n"
        text += (state ?? "(no stack)") + "\n"
        for secret in secrets where !secret.isEmpty {
            text = text.replacingOccurrences(of: secret, with: "[removed]")
        }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent(fileName(at: date))
        try Data(text.utf8).write(to: url, options: .atomic)
        return url
    }
}
