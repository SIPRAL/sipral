// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#else
#error("UDPSocket needs a POSIX sockets implementation")
#endif

/// The one POSIX socket every stack and every call's media opens.
///
/// The library owns no sockets; this is the application side, on POSIX
/// rather than Network.framework so it also builds on Linux.
public final class UDPSocket: @unchecked Sendable {
    let fd: Int32
    /// `host:port`, as every address crosses `sipral.h`.
    public let localAddress: String
    /// `AF_INET6` for a socket bound to an IPv6 address, or to every address
    /// of both families (`0.0.0.0` or `Nat64.hostAddress`); else `AF_INET`.
    let family: Int32

    /// A socket at `host:port`. `0.0.0.0` and `Nat64.hostAddress` bind every
    /// address of both families where the system allows it, so the socket
    /// also reaches an IPv4 server from a network with IPv6 only, through
    /// its NAT64; it still reports and is given IPv4 addresses.
    public init(host: String, port: UInt16) throws {
        let wildcard = host == "0.0.0.0" || host == Nat64.hostAddress
        if wildcard, let (fd, bound) = Self.ipv6(at: in6addr_any, port: port) {
            self.fd = fd
            self.family = AF_INET6
            self.localAddress = "\(host):\(bound)"
            return
        }
        if let octets = Nat64Prefix.octets(of: host) {
            var at = in6_addr()
            withUnsafeMutableBytes(of: &at) { $0.copyBytes(from: octets) }
            guard let (fd, bound) = Self.ipv6(at: at, port: port) else {
                throw SipralBindingError.socket("bind() failed for \(host), errno \(errno)")
            }
            self.fd = fd
            self.family = AF_INET6
            self.localAddress = "[\(Nat64Prefix.text(of: octets))]:\(bound)"
            return
        }
        let fd = socket(AF_INET, Self.datagram, 0)
        guard fd >= 0 else {
            throw SipralBindingError.socket("socket() failed, errno \(errno)")
        }

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host == Nat64.hostAddress ? "0.0.0.0" : host, &address.sin_addr) == 1 else {
            UDPSocket.closeDescriptor(fd)
            throw SipralBindingError.socket("inet_pton failed for \(host)")
        }

        let bound = withUnsafePointer(to: &address) { pointer -> Int32 in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
                bind(fd, raw, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else {
            UDPSocket.closeDescriptor(fd)
            throw SipralBindingError.socket("bind() failed, errno \(errno)")
        }

        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        var actual = sockaddr_in()
        var actualLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &actual) { pointer -> Int32 in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
                getsockname(fd, raw, &actualLen)
            }
        }
        guard named == 0 else {
            UDPSocket.closeDescriptor(fd)
            throw SipralBindingError.socket("getsockname() failed, errno \(errno)")
        }

        self.fd = fd
        self.family = AF_INET
        self.localAddress = "\(host):\(UInt16(bigEndian: actual.sin_port))"
    }

    #if canImport(Darwin)
    private static let datagram = SOCK_DGRAM
    #else
    private static let datagram = Int32(SOCK_DGRAM.rawValue)
    #endif

    /// A non-blocking IPv6 socket at `at:port` that also carries IPv4 (all
    /// of it for `in6addr_any`), and the port it got; `nil` where the system
    /// has no IPv6, or will not bind it.
    private static func ipv6(at: in6_addr, port: UInt16) -> (Int32, UInt16)? {
        let fd = socket(AF_INET6, datagram, 0)
        guard fd >= 0 else { return nil }
        var only: Int32 = 0
        var address = sockaddr_in6()
        address.sin6_family = sa_family_t(AF_INET6)
        address.sin6_port = port.bigEndian
        address.sin6_addr = at
        let bound = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only, socklen_t(MemoryLayout<Int32>.size)) == 0
            && withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) == 0
                }
            }
        var actual = sockaddr_in6()
        var length = socklen_t(MemoryLayout<sockaddr_in6>.size)
        let named = bound && withUnsafeMutablePointer(to: &actual) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) == 0 }
        }
        guard named else {
            closeDescriptor(fd)
            return nil
        }
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        return (fd, UInt16(bigEndian: actual.sin6_port))
    }

    /// Whether a read has failed for a reason other than there being nothing
    /// to read. Such a socket is never read from successfully again: on iOS,
    /// one the system took back while the application was suspended (a
    /// defunct socket) still polls readable and fails every read, so a loop
    /// that only polls and reads it spins.
    public private(set) var failed = false

    /// Read errors that say nothing about the socket itself: nothing waiting,
    /// a signal, and what an ICMP error or a busy interface reports for one
    /// datagram.
    private static let passing: Set<Int32> = [
        EAGAIN, EWOULDBLOCK, EINTR, ECONNREFUSED, EHOSTUNREACH, ENETUNREACH, EHOSTDOWN, EMSGSIZE, ENOBUFS,
    ]

    /// Say the socket is beyond use when `poll` reports its descriptor
    /// invalid (`POLLNVAL`), which it does at once on every call.
    func markFailed() {
        failed = true
    }

    /// One datagram, non-blocking. `nil` when nothing is waiting, or when the
    /// read failed (`failed`).
    public func receive(capacity: Int = 65536) -> (data: [UInt8], from: String)? {
        var buffer = [UInt8](repeating: 0, count: capacity)
        var fromAddress = sockaddr_storage()
        var fromLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
        var error: Int32 = 0
        let received = buffer.withUnsafeMutableBytes { raw -> Int in
            withUnsafeMutablePointer(to: &fromAddress) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    let count = recvfrom(fd, raw.baseAddress, capacity, 0, sockaddrPtr, &fromLen)
                    error = errno
                    return count
                }
            }
        }
        if received < 0, !Self.passing.contains(error) {
            failed = true
        }
        guard received > 0 else { return nil }
        return (Array(buffer[0..<received]), Self.text(of: fromAddress))
    }

    /// `host:port` for an address `recvfrom` filled in. An IPv4 address an
    /// IPv6 socket received from, mapped (`::ffff:a.b.c.d`) or through a
    /// NAT64 found (`Nat64`), is given as IPv4; other IPv6 as `[v6]:port`.
    static func text(of storage: sockaddr_storage) -> String {
        let family = storage.ss_family
        return withUnsafePointer(to: storage) { pointer in
            if family == sa_family_t(AF_INET6) {
                return pointer.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { v6 in
                    var address = v6.pointee.sin6_addr
                    let octets = withUnsafeBytes(of: &address) { Array($0) }
                    let port = UInt16(bigEndian: v6.pointee.sin6_port)
                    let mapped = octets[0..<10].allSatisfy { $0 == 0 } && octets[10] == 0xff && octets[11] == 0xff
                    if let v4 = mapped ? Array(octets[12..<16]) : Nat64.extracted(octets) {
                        return "\(v4.map(String.init).joined(separator: ".")):\(port)"
                    }
                    return "[\(Nat64Prefix.text(of: octets))]:\(port)"
                }
            }
            return pointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { v4 in
                "\(Self.text(of: v4.pointee.sin_addr)):\(UInt16(bigEndian: v4.pointee.sin_port))"
            }
        }
    }

    /// Errors that say an IPv4 destination has no route from here, as on a
    /// network with IPv6 only.
    private static let noRoute: Set<Int32> = [ENETUNREACH, EHOSTUNREACH, EADDRNOTAVAIL]

    /// One datagram to `host:port`. On a socket of both families an IPv4
    /// destination with no route goes to its address inside the NAT64
    /// prefix found, if any.
    @discardableResult
    public func send(_ payload: [UInt8], toHost host: String, port: UInt16) -> Bool {
        let bare = host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
        var v4 = in_addr()
        let isV4 = inet_pton(AF_INET, bare, &v4) == 1
        if family == AF_INET {
            guard isV4 else { return false }
            var address = sockaddr_in()
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = port.bigEndian
            address.sin_addr = v4
            return sendto(&address, payload) == payload.count
        }
        let target = isV4 ? "::ffff:\(bare)" : bare
        guard let octets = Nat64Prefix.octets(of: target) else { return false }
        if sendTo6(octets, port: port, payload) == payload.count { return true }
        let error = errno
        guard isV4, let translated = Self.translated(bare, after: error) else { return false }
        return sendTo6(translated, port: port, payload) == payload.count
    }

    /// Where a datagram to the IPv4 `host` goes after a send to it failed
    /// with `error`: inside the NAT64 prefix found, when the error says IPv4
    /// has no route from here.
    static func translated(_ host: String, after error: Int32) -> [UInt8]? {
        guard noRoute.contains(error), let synthesized = Nat64.synthesized(host) else { return nil }
        return Nat64Prefix.octets(of: synthesized)
    }

    private func sendTo6(_ octets: [UInt8], port: UInt16, _ payload: [UInt8]) -> Int {
        var address = sockaddr_in6()
        address.sin6_family = sa_family_t(AF_INET6)
        address.sin6_port = port.bigEndian
        withUnsafeMutableBytes(of: &address.sin6_addr) { $0.copyBytes(from: octets) }
        return sendto(&address, payload)
    }

    private func sendto<Address>(_ address: inout Address, _ payload: [UInt8]) -> Int {
        payload.withUnsafeBytes { raw -> Int in
            withUnsafePointer(to: &address) { pointer -> Int in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    #if canImport(Darwin)
                    Darwin.sendto(fd, raw.baseAddress, payload.count, 0, sockaddrPtr, socklen_t(MemoryLayout<Address>.size))
                    #else
                    Glibc.sendto(fd, raw.baseAddress, payload.count, 0, sockaddrPtr, socklen_t(MemoryLayout<Address>.size))
                    #endif
                }
            }
        }
    }

    @discardableResult
    public func send(_ payload: [UInt8], to address: String) -> Bool {
        let (host, port) = Self.parse(address)
        return send(payload, toHost: host, port: port)
    }

    public static func parse(_ address: String) -> (host: String, port: UInt16) {
        guard let colon = address.lastIndex(of: ":") else { return (address, 0) }
        let host = String(address[address.startIndex..<colon])
        let port = UInt16(address[address.index(after: colon)...]) ?? 0
        return (host, port)
    }

    private static func text(of address: in_addr) -> String {
        var address = address
        var buffer = [Int8](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &address, &buffer, socklen_t(INET_ADDRSTRLEN))
        return String(cString: buffer)
    }

    public func close() {
        UDPSocket.closeDescriptor(fd)
    }

    private static func closeDescriptor(_ fd: Int32) {
        #if canImport(Darwin)
        Darwin.close(fd)
        #else
        Glibc.close(fd)
        #endif
    }
}

/// A failure in this layer itself (mostly sockets), not a `SipralError`.
public enum SipralBindingError: Error, CustomStringConvertible, Sendable {
    case socket(String)

    public var description: String {
        switch self {
        case .socket(let message): return "SipralBindingError.socket: \(message)"
        }
    }
}
