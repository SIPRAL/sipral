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

    public init(host: String, port: UInt16) throws {
        #if canImport(Darwin)
        let socketType = SOCK_DGRAM
        #else
        let socketType = Int32(SOCK_DGRAM.rawValue)
        #endif
        let fd = socket(AF_INET, socketType, 0)
        guard fd >= 0 else {
            throw SipralBindingError.socket("socket() failed, errno \(errno)")
        }

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host, &address.sin_addr) == 1 else {
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
        self.localAddress = "\(host):\(UInt16(bigEndian: actual.sin_port))"
    }

    /// One datagram, non-blocking. `nil` when nothing is waiting.
    public func receive(capacity: Int = 65536) -> (data: [UInt8], from: String)? {
        var buffer = [UInt8](repeating: 0, count: capacity)
        var fromAddress = sockaddr_in()
        var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let received = buffer.withUnsafeMutableBytes { raw -> Int in
            withUnsafeMutablePointer(to: &fromAddress) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    recvfrom(fd, raw.baseAddress, capacity, 0, sockaddrPtr, &fromLen)
                }
            }
        }
        guard received > 0 else { return nil }
        let host = Self.text(of: fromAddress.sin_addr)
        let port = UInt16(bigEndian: fromAddress.sin_port)
        return (Array(buffer[0..<received]), "\(host):\(port)")
    }

    @discardableResult
    public func send(_ payload: [UInt8], toHost host: String, port: UInt16) -> Bool {
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host, &address.sin_addr) == 1 else { return false }
        let sent = payload.withUnsafeBytes { raw -> Int in
            withUnsafePointer(to: &address) { pointer -> Int in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    sendto(fd, raw.baseAddress, payload.count, 0, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        return sent == payload.count
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
