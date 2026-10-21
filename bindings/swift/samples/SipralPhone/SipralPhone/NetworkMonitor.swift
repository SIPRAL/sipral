// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Darwin
import Network
import Sipral

/// Feeds `SipralStack.networkChanged(to:)` from `NWPathMonitor`. The
/// address is the one the system sends from toward the server (found by
/// connecting a UDP socket, which sends nothing), so Wi-Fi, cellular and a
/// VPN are each told apart by what actually carries the traffic.
final class NetworkMonitor: @unchecked Sendable {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "org.sipral.phone.network")
    /// What the stack was last told, or created on. Only on `queue`.
    private var told: SipralStack.Network?

    /// The network toward `server` (`ip:port`) on `path`.
    static func network(toward server: String, path: NWPath) -> SipralStack.Network {
        guard path.status == .satisfied else { return SipralStack.Network(link: .down) }
        let address = localAddress(toward: server)
        return SipralStack.Network(
            link: link(of: path), address: address, interface: address.flatMap(interface(holding:))
        )
    }

    /// Starts watching and answers the network the stack is created on;
    /// `changed` is called on the monitor's queue whenever a path describes
    /// a different one.
    func start(toward server: String, _ changed: @escaping @Sendable (SipralStack.Network) -> Void) -> SipralStack.Network {
        let first = DispatchSemaphore(value: 0)
        monitor.pathUpdateHandler = { [self] path in
            let now = Self.network(toward: server, path: path)
            guard let before = told else {
                told = now
                first.signal()
                return
            }
            guard now != before else { return }
            told = now
            changed(now)
        }
        monitor.start(queue: queue)
        // NWPathMonitor answers at once; the wait only bounds a system
        // that does not, and then the stack starts on the route alone.
        if first.wait(timeout: .now() + 1) == .timedOut {
            let address = Self.localAddress(toward: server)
            let guess = SipralStack.Network(
                link: address == nil ? .down : .wifi, address: address, interface: address.flatMap(Self.interface(holding:))
            )
            queue.sync { if told == nil { told = guess } }
        }
        return queue.sync { told ?? SipralStack.Network(link: .down) }
    }

    func stop() {
        monitor.cancel()
    }

    static func link(of path: NWPath) -> SipralLink {
        guard path.status == .satisfied else { return .down }
        if path.usesInterfaceType(.wifi) { return .wifi }
        if path.usesInterfaceType(.cellular) { return .cellular }
        if path.usesInterfaceType(.wiredEthernet) { return .wired }
        return .tunnel
    }

    /// The local IPv4 address the system sends from toward `remote`, or
    /// `nil` when nothing routes there.
    static func localAddress(toward remote: String) -> String? {
        let (host, port) = UDPSocket.parse(remote)
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = (port == 0 ? 5060 : port).bigEndian
        guard inet_pton(AF_INET, host, &address.sin_addr) == 1 else { return nil }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else { return nil }
        var local = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        guard named == 0 else { return nil }
        var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &local.sin_addr, &text, socklen_t(INET_ADDRSTRLEN))
        return String(decoding: text.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    /// The interface holding `address` (`en0` Wi-Fi, `pdp_ip0` cellular, a
    /// `utun` for a VPN).
    static func interface(holding address: String) -> String? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return nil }
        defer { freeifaddrs(list) }
        var cursor = list
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard let raw = entry.pointee.ifa_addr, raw.pointee.sa_family == UInt8(AF_INET) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(raw, socklen_t(raw.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0
            else { continue }
            if String(decoding: host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self) == address {
                return String(cString: entry.pointee.ifa_name)
            }
        }
        return nil
    }

    /// The server's IPv4 address: `name` itself when it is one, else the
    /// first the system's resolver answers.
    static func resolve(_ name: String) -> String? {
        var v4 = in_addr()
        if inet_pton(AF_INET, name, &v4) == 1 { return name }
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_DGRAM
        var found: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(name, nil, &hints, &found) == 0, let first = found else { return nil }
        defer { freeaddrinfo(found) }
        guard let raw = first.pointee.ai_addr else { return nil }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(raw, first.pointee.ai_addrlen, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0
        else { return nil }
        return String(decoding: host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
