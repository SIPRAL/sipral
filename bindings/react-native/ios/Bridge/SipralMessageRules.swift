// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The message rules JavaScript sets (`setMessageRules`), applied by the
// stack's message hook to each message as it passes: JavaScript is too far
// away to answer the hook itself. A field is matched by its name in any case
// and in either form RFC 3261 §7.3.3 gives it, as the core's own Rewrite
// does; the body, and so Content-Length, is never touched.

import Foundation

/// One rule, as `MessageRule` in `src/types.ts` has it.
public struct SipralMessageRule: Equatable {
    /// Nil for both directions.
    public var outgoing: Bool?
    /// Nil for every method.
    public var method: String?
    public var set: [Field] = []
    public var add: [Field] = []
    public var remove: [String] = []

    public struct Field: Equatable {
        public var name: String
        public var value: String
    }

    /// The rules in `text`, as `setMessageRules` crosses them: one directive
    /// a line, `rule <outgoing|incoming|*> <method|*>` opening each rule,
    /// then `set name:value`, `add name:value` and `remove name` lines.
    public static func parse(_ text: String) throws -> [SipralMessageRule] {
        var rules: [SipralMessageRule] = []
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let directive = line.prefix { $0 != " " }
            let rest = String(line.dropFirst(directive.count + 1))
            if directive == "rule" {
                let parts = rest.split(separator: " ")
                guard parts.count == 2 else { throw refused("a rule line names a direction and a method") }
                var rule = SipralMessageRule()
                switch parts[0] {
                case "*": rule.outgoing = nil
                case "outgoing": rule.outgoing = true
                case "incoming": rule.outgoing = false
                default: throw refused("a rule's direction is outgoing or incoming, not \(parts[0])")
                }
                rule.method = parts[1] == "*" ? nil : String(parts[1])
                rules.append(rule)
                continue
            }
            guard !rules.isEmpty else { throw refused("a \(directive) line comes after a rule line") }
            switch directive {
            case "set", "add":
                guard let colon = rest.firstIndex(of: ":") else { throw refused("a \(directive) line is name:value") }
                let field = Field(name: String(rest[..<colon]), value: String(rest[rest.index(after: colon)...]))
                try check(field.name)
                if field.value.contains("\r") { throw refused("a field's value is one line") }
                if directive == "set" {
                    rules[rules.count - 1].set.append(field)
                } else {
                    rules[rules.count - 1].add.append(field)
                }
            case "remove":
                try check(rest)
                rules[rules.count - 1].remove.append(rest)
            default:
                throw refused("\(directive) is no rule directive")
            }
        }
        return rules
    }

    private static func check(_ name: String) throws {
        if name.isEmpty || name.contains(where: { ": \t\r\n".contains($0) }) {
            throw refused("a field name is a token, without a colon, a space or a line break")
        }
        if canonical(name) == "content-length" {
            throw refused("Content-Length is the library's")
        }
    }

    private static func refused(_ why: String) -> SipralRefusal {
        SipralRefusal("invalidArgument", why)
    }

    /// `message` with every rule that fits it applied, or nil when none
    /// changed it (or it cannot be taken apart, which the stack then reads
    /// as it came).
    public static func apply(_ rules: [SipralMessageRule], outgoing: Bool, to message: [UInt8]) -> [UInt8]? {
        let fitting = rules.filter { $0.outgoing == nil || $0.outgoing == outgoing }
        guard !fitting.isEmpty, var parsed = Parsed(message) else { return nil }
        var changed = false
        for rule in fitting where rule.method == nil || rule.method == parsed.method {
            for field in rule.remove {
                changed = parsed.remove(field) || changed
            }
            for field in rule.set {
                parsed.set(field.name, field.value)
                changed = true
            }
            for field in rule.add {
                parsed.lines.append("\(field.name): \(field.value)")
                changed = true
            }
        }
        return changed ? parsed.bytes : nil
    }

    /// The full name of a field, lower case, whichever form it was written in.
    static func canonical(_ name: String) -> String {
        let lower = name.trimmingCharacters(in: .whitespaces).lowercased()
        return compact[lower] ?? lower
    }

    private static let compact: [String: String] = [
        "a": "accept-contact", "u": "allow-events", "i": "call-id", "m": "contact",
        "e": "content-encoding", "l": "content-length", "c": "content-type", "o": "event",
        "f": "from", "y": "identity", "r": "refer-to", "b": "referred-by", "j": "reject-contact",
        "d": "request-disposition", "x": "session-expires", "s": "subject", "k": "supported",
        "t": "to", "v": "via",
    ]

    /// A message taken apart: its start line, each field as written (a
    /// folded one with its continuation lines), and its body untouched.
    private struct Parsed {
        var start: String
        var lines: [String]
        var body: ArraySlice<UInt8>

        init?(_ message: [UInt8]) {
            let end = message.indices.dropLast(3).first {
                message[$0] == 13 && message[$0 + 1] == 10 && message[$0 + 2] == 13 && message[$0 + 3] == 10
            }
            guard let end, let head = String(bytes: message[..<end], encoding: .utf8) else { return nil }
            var all = head.components(separatedBy: "\r\n")
            start = all.removeFirst()
            lines = []
            for line in all {
                if let first = line.first, first == " " || first == "\t", !lines.isEmpty {
                    lines[lines.count - 1] += "\r\n" + line
                } else {
                    lines.append(line)
                }
            }
            body = message[(end + 4)...]
        }

        /// A request's method, or a response's by its CSeq.
        var method: String? {
            if start.hasPrefix("SIP/") {
                let cseq = lines.first { Self.name(of: $0) == "cseq" }.flatMap(Self.value(of:))
                return cseq?.split(separator: " ").last.map(String.init)
            }
            return start.split(separator: " ").first.map(String.init)
        }

        mutating func remove(_ field: String) -> Bool {
            let wanted = SipralMessageRule.canonical(field)
            let before = lines.count
            lines.removeAll { Self.name(of: $0) == wanted }
            return lines.count != before
        }

        mutating func set(_ field: String, _ value: String) {
            let wanted = SipralMessageRule.canonical(field)
            guard let first = lines.firstIndex(where: { Self.name(of: $0) == wanted }) else {
                lines.append("\(field): \(value)")
                return
            }
            lines[first] = "\(field): \(value)"
            var index = lines.count - 1
            while index > first {
                if Self.name(of: lines[index]) == wanted {
                    lines.remove(at: index)
                }
                index -= 1
            }
        }

        var bytes: [UInt8] {
            Array(([start] + lines).joined(separator: "\r\n").utf8) + Array("\r\n\r\n".utf8) + body
        }

        private static func name(of line: String) -> String? {
            line.firstIndex(of: ":").map { SipralMessageRule.canonical(String(line[..<$0])) }
        }

        private static func value(of line: String) -> String? {
            line.firstIndex(of: ":").map { line[line.index(after: $0)...].trimmingCharacters(in: .whitespaces) }
        }
    }
}
