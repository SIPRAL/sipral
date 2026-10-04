// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Darwin
import Network
import Sipral

/// Where this Mac is on the network, and a word whenever that changes: the
/// sample's own half of `SipralStack.networkChanged(to:)`, which only the
/// platform can tell.
///
/// The address is the one the system would send from toward the registrar
/// -- asked by connecting a UDP socket there, which sends nothing -- so a
/// server behind a VPN is reached from the tunnel's address and one on the
/// LAN from the LAN's. `NWPathMonitor` says when to ask again.
final class NetworkWatcher: @unchecked Sendable {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "org.sipral.sample.network")

    /// The network the monitor's first update described, which is where the
    /// stack already is: `start` hands it back rather than calling it a
    /// change. Touched only on `queue`.
    private var first = true

    /// The network as it stands toward `remote`, before anything changes:
    /// what the stack is created on, so that its first `networkChanged`
    /// compares like with like.
    static func current(toward remote: String) -> SipralStack.Network {
        let address = localAddress(toward: remote)
        return SipralStack.Network(link: .wired, address: address, interface: address.flatMap(interface(holding:)))
    }

    /// Calls `changed` on a queue of the watcher's own with the network it
    /// sees toward `remote` (`host:port`), every time the path changes after
    /// the monitor's first look.
    func start(toward remote: String, _ changed: @escaping @Sendable (SipralStack.Network) -> Void) {
        monitor.pathUpdateHandler = { [self] path in
            guard !first else {
                first = false
                return
            }
            changed(Self.network(of: path, toward: remote))
        }
        monitor.start(queue: queue)
    }

    func stop() {
        monitor.cancel()
    }

    private static func network(of path: NWPath, toward remote: String) -> SipralStack.Network {
        guard path.status == .satisfied else { return SipralStack.Network(link: .down) }
        let link: SipralLink
        if path.usesInterfaceType(.wifi) {
            link = .wifi
        } else if path.usesInterfaceType(.cellular) {
            link = .cellular
        } else if path.usesInterfaceType(.wiredEthernet) {
            link = .wired
        } else {
            link = .tunnel
        }
        let address = localAddress(toward: remote)
        return SipralStack.Network(link: link, address: address, interface: address.flatMap(interface(holding:)))
    }

    /// The local IPv4 address the system sends from toward `remote`, or `nil`
    /// when there is no route.
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

    /// The name of the interface `address` is on: what tells two networks
    /// that hand out the same address apart.
    private static func interface(holding address: String) -> String? {
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
}
