// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation

/// A NAT64 prefix (RFC 6052): where an IPv6-only network puts an IPv4
/// address inside an IPv6 one, so that its translator reaches the IPv4
/// Internet.
public struct Nat64Prefix: Equatable, Sendable, CustomStringConvertible {
    /// The prefix's sixteen octets, zero past `length`.
    public let octets: [UInt8]
    /// 32, 40, 48, 56, 64 or 96 bits.
    public let length: Int

    /// The prefix lengths RFC 6052 §2.2 defines.
    public static let lengths = [32, 40, 48, 56, 64, 96]

    /// The well-known prefix, `64:ff9b::/96` (RFC 6052 §2.1).
    public static let wellKnown = Nat64Prefix(octets: [0, 0x64, 0xff, 0x9b] + [UInt8](repeating: 0, count: 12), length: 96)!

    /// `nil` unless `length` is one RFC 6052 defines and `octets` holds
    /// sixteen of them; what lies past `length` is cleared.
    public init?(octets: [UInt8], length: Int) {
        guard octets.count == 16, Self.lengths.contains(length) else { return nil }
        self.octets = octets.enumerated().map { $0.offset < length / 8 ? $0.element : 0 }
        self.length = length
    }

    /// `2001:db8::/32`, or `nil` for anything else.
    public init?(_ text: String) {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let length = Int(parts[1]), let octets = Self.octets(of: String(parts[0])) else {
            return nil
        }
        self.init(octets: octets, length: length)
    }

    /// The four octets of the IPv4 address sit here, past the prefix and
    /// around bits 64-71, which stay zero (RFC 6052 §2.2).
    var positions: [Int] {
        var found: [Int] = []
        var index = length / 8
        while found.count < 4 {
            if index != 8 { found.append(index) }
            index += 1
        }
        return found
    }

    /// `ipv4` (four octets) inside this prefix.
    public func synthesize(_ ipv4: [UInt8]) -> [UInt8] {
        var address = octets
        for (octet, position) in zip(ipv4, positions) {
            address[position] = octet
        }
        return address
    }

    /// The IPv4 address `ipv6` (sixteen octets) carries, if it lies inside
    /// this prefix with bits 64-71 zero.
    public func extract(_ ipv6: [UInt8]) -> [UInt8]? {
        guard ipv6.count == 16, Array(ipv6[0..<length / 8]) == Array(octets[0..<length / 8]) else { return nil }
        if length < 96, ipv6[8] != 0 { return nil }
        return positions.map { ipv6[$0] }
    }

    /// `ipv4` (dotted) inside this prefix, as IPv6 text.
    public func synthesize(_ ipv4: String) -> String? {
        var v4 = in_addr()
        guard inet_pton(AF_INET, ipv4, &v4) == 1 else { return nil }
        return Self.text(of: synthesize(withUnsafeBytes(of: &v4) { Array($0) }))
    }

    /// The dotted IPv4 address `ipv6` (text) carries, if it is inside this
    /// prefix.
    public func extract(_ ipv6: String) -> String? {
        guard let octets = Self.octets(of: ipv6), let v4 = extract(octets) else { return nil }
        return v4.map(String.init).joined(separator: ".")
    }

    public var description: String {
        "\(Self.text(of: octets))/\(length)"
    }

    /// The prefixes a DNS64 server's answer for `ipv4only.arpa` reveals
    /// (RFC 7050 §3): in each address, the one length at which
    /// `192.0.0.170` sits, else `192.0.0.171`; an address holding it at
    /// more than one length, or at none, reveals nothing. In the order
    /// answered, each once.
    public static func revealed(by answers: [[UInt8]]) -> [Nat64Prefix] {
        var found: [Nat64Prefix] = []
        for address in answers where address.count == 16 {
            for known: [UInt8] in [[192, 0, 0, 170], [192, 0, 0, 171]] {
                let lengths = Self.lengths.filter {
                    Nat64Prefix(octets: address, length: $0)?.extract(address) == known
                }
                if lengths.count == 1, let prefix = Nat64Prefix(octets: address, length: lengths[0]) {
                    if !found.contains(prefix) { found.append(prefix) }
                    break
                }
            }
        }
        return found
    }

    static func octets(of ipv6: String) -> [UInt8]? {
        let bare = ipv6.hasPrefix("[") && ipv6.hasSuffix("]") ? String(ipv6.dropFirst().dropLast()) : ipv6
        var v6 = in6_addr()
        guard inet_pton(AF_INET6, bare, &v6) == 1 else { return nil }
        return withUnsafeBytes(of: &v6) { Array($0) }
    }

    static func text(of octets: [UInt8]) -> String {
        var v6 = in6_addr()
        withUnsafeMutableBytes(of: &v6) { $0.copyBytes(from: octets) }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        inet_ntop(AF_INET6, &v6, &buffer, socklen_t(INET6_ADDRSTRLEN))
        return String(cString: buffer)
    }
}

/// The NAT64 the current network offers, if any, and the IPv4 address this
/// machine goes by behind it.
///
/// On a network with IPv6 only, an IPv4 server is reached at its address
/// inside the network's NAT64 prefix. The library and the rest of this
/// layer keep seeing IPv4: the sockets translate on the way out and back,
/// and this machine names itself `hostAddress`, as a 464XLAT client does
/// (RFC 6877). A server sees a client behind a NAT, as it would behind any
/// other.
public enum Nat64 {
    /// What this machine calls itself behind the translator: from
    /// `192.0.0.0/29`, kept for this (RFC 7335), the one Android's 464XLAT
    /// client takes.
    public static let hostAddress = "192.0.0.4"

    /// How long a discovery is kept, found or not, before it is asked again.
    static let keptFor: TimeInterval = 60

    private static let lock = NSLock()
    nonisolated(unsafe) private static var known: [Nat64Prefix] = []
    nonisolated(unsafe) private static var askedAt: Date?

    /// The prefixes found last, without asking. Empty on a network with
    /// IPv4, or before anything asked.
    public static var prefixes: [Nat64Prefix] {
        lock.lock()
        defer { lock.unlock() }
        return known
    }

    /// The network's prefixes, asked of its DNS64 server (RFC 7050) when the
    /// last answer is older than `keptFor`. Blocks for the lookup.
    @discardableResult
    public static func discover() -> [Nat64Prefix] {
        lock.lock()
        if let askedAt, Date().timeIntervalSince(askedAt) < keptFor {
            defer { lock.unlock() }
            return known
        }
        lock.unlock()
        let found = Nat64Prefix.revealed(by: wellKnownNameAnswers())
        lock.lock()
        defer { lock.unlock() }
        known = found
        askedAt = Date()
        return found
    }

    /// Ask again at the next `discover`: the network changed.
    public static func forget() {
        lock.lock()
        defer { lock.unlock() }
        askedAt = nil
    }

    /// Use `prefixes` as if discovered, for `keptFor`.
    static func assume(_ prefixes: [Nat64Prefix]) {
        lock.lock()
        defer { lock.unlock() }
        known = prefixes
        askedAt = Date()
    }

    /// `ipv4` inside the first prefix found, if any.
    static func synthesized(_ ipv4: String) -> String? {
        prefixes.first?.synthesize(ipv4)
    }

    /// The IPv4 address `ipv6` stands for, if it is inside a prefix found.
    static func extracted(_ ipv6: [UInt8]) -> [UInt8]? {
        prefixes.lazy.compactMap { $0.extract(ipv6) }.first
    }

    /// The IPv6 addresses `getaddrinfo` gives for `ipv4only.arpa`, which has
    /// none but what a DNS64 server makes of its IPv4 ones.
    private static func wellKnownNameAnswers() -> [[UInt8]] {
        var hints = addrinfo()
        hints.ai_family = AF_INET6
        #if canImport(Darwin)
        hints.ai_socktype = SOCK_DGRAM
        #else
        hints.ai_socktype = Int32(SOCK_DGRAM.rawValue)
        #endif
        var found: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo("ipv4only.arpa", nil, &hints, &found) == 0, let first = found else { return [] }
        defer { freeaddrinfo(first) }
        var answers: [[UInt8]] = []
        var entry: UnsafeMutablePointer<addrinfo>? = first
        while let current = entry {
            if let address = current.pointee.ai_addr, address.pointee.sa_family == sa_family_t(AF_INET6) {
                let octets = address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { pointer in
                    var v6 = pointer.pointee.sin6_addr
                    return withUnsafeBytes(of: &v6) { Array($0) }
                }
                if !answers.contains(octets) { answers.append(octets) }
            }
            entry = current.pointee.ai_next
        }
        return answers
    }
}
