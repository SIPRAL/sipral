// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import CSipral
import Dispatch
#if canImport(dnssd)
import dnssd
#endif

/// What a resolver said to one lookup: a `SipralDnsAnswer`, and with
/// `.records` the records of the kind asked for, each its time-to-live in
/// seconds and then its data as a zone file writes it -- `300 192.0.2.40`,
/// `300 10 60 5060 sip1.example.com` (`sipral_account_looked_up`).
public struct DnsLookupAnswer: Sendable, Equatable {
    public let answer: SipralDnsAnswer
    public let records: [String]

    public init(answer: SipralDnsAnswer, records: [String] = []) {
        self.answer = answer
        self.records = records
    }

    /// The name has no record of that kind, or does not exist.
    public static let nothing = DnsLookupAnswer(answer: .nothing)
    /// The resolver could not answer.
    public static let failed = DnsLookupAnswer(answer: .failed)
}

/// Answers `SipralEventKind.lookupWanted` for the accounts a stack added with
/// `serverUri`: the name and the kind of record asked, and what the DNS said.
/// Called on a thread of its own, one per lookup, and may block.
public typealias SipralResolver = @Sendable (_ name: String, _ record: SipralDnsRecordType) -> DnsLookupAnswer

/// The resolver a `SipralStack` uses when it is given none.
///
/// On Apple platforms SRV and NAPTR are asked of the system's DNS service
/// (`DNSServiceQueryRecord`, the resolver every app on the device shares,
/// VPN and per-interface DNS settings included), each within five seconds;
/// addresses are asked of `getaddrinfo`, which reads the hosts file as well,
/// with a time-to-live of `addressTtl`, the platform's lookup not saying what
/// the zone's was. Elsewhere only addresses are asked, and every SRV or NAPTR
/// query is answered `.nothing`, which RFC 3263's procedure takes as a
/// domain that publishes none.
public enum SipralDns {
    /// The time-to-live given an address the platform's lookup found, in
    /// seconds: how soon a moved server is looked up again.
    public static let addressTtl: UInt32 = 60

    /// How long a query to the DNS service may take.
    static let patienceMs: Int32 = 5000

    public static let platform: SipralResolver = { name, record in
        switch record {
        case .a: return addresses(of: name, family: AF_INET)
        case .aaaa: return addresses(of: name, family: AF_INET6)
        case .srv, .naptr:
            #if canImport(dnssd)
            return query(name, record)
            #else
            return .nothing
            #endif
        default: return .nothing
        }
    }

    /// The addresses of one family `getaddrinfo` finds for `name`.
    static func addresses(of name: String, family: Int32) -> DnsLookupAnswer {
        var hints = addrinfo()
        hints.ai_family = family
        #if canImport(Darwin)
        hints.ai_socktype = SOCK_DGRAM
        #else
        hints.ai_socktype = Int32(SOCK_DGRAM.rawValue)
        #endif
        var found: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(name, nil, &hints, &found)
        guard status == 0, let first = found else {
            return status == EAI_NONAME || status == EAI_NODATA_OR_NONAME ? .nothing : .failed
        }
        defer { freeaddrinfo(first) }
        var seen: [String] = []
        var entry: UnsafeMutablePointer<addrinfo>? = first
        while let current = entry {
            if let text = numeric(current.pointee.ai_addr, current.pointee.ai_addrlen), !seen.contains(text) {
                seen.append(text)
            }
            entry = current.pointee.ai_next
        }
        guard !seen.isEmpty else { return .nothing }
        return DnsLookupAnswer(answer: .records, records: seen.map { "\(addressTtl) \($0)" })
    }

    /// `EAI_NODATA` where the platform still has it, `EAI_NONAME` elsewhere.
    private static var EAI_NODATA_OR_NONAME: Int32 {
        #if canImport(Darwin)
        return EAI_NODATA
        #else
        return EAI_NONAME
        #endif
    }

    private static func numeric(_ address: UnsafeMutablePointer<sockaddr>?, _ length: socklen_t) -> String? {
        guard let address else { return nil }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(address, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else {
            return nil
        }
        let text = String(cString: host)
        return text.split(separator: "%").first.map(String.init) ?? text
    }

    /// One SRV or NAPTR record's data, as `DNSServiceQueryRecord` hands it
    /// over (RFC 2782, RFC 3403: the names in it uncompressed), written as a
    /// zone file writes it after `ttl`: priority, weight, port and target;
    /// order, preference, flags, service and replacement, the regular
    /// expression left out since RFC 3263 follows none. `nil` for data that
    /// is not one.
    public static func zoneText(of record: SipralDnsRecordType, data: [UInt8], ttl: UInt32) -> String? {
        var at = 0
        func number() -> Int? {
            guard at + 2 <= data.count else { return nil }
            defer { at += 2 }
            return Int(data[at]) << 8 | Int(data[at + 1])
        }
        func characters() -> String? {
            guard at < data.count else { return nil }
            let length = Int(data[at])
            guard at + 1 + length <= data.count else { return nil }
            defer { at += 1 + length }
            return String(decoding: data[(at + 1)..<(at + 1 + length)], as: UTF8.self)
        }
        func name() -> String? {
            var labels: [String] = []
            while at < data.count {
                let length = Int(data[at])
                at += 1
                if length == 0 { return labels.isEmpty ? "." : labels.joined(separator: ".") }
                guard length < 64, at + length <= data.count else { return nil }
                labels.append(String(decoding: data[at..<(at + length)], as: UTF8.self))
                at += length
            }
            return nil
        }
        switch record {
        case .srv:
            guard let priority = number(), let weight = number(), let port = number(), let target = name() else {
                return nil
            }
            return "\(ttl) \(priority) \(weight) \(port) \(target)"
        case .naptr:
            guard let order = number(), let preference = number(), let flags = characters(),
                  let service = characters(), characters() != nil, let replacement = name() else {
                return nil
            }
            return "\(ttl) \(order) \(preference) \(flags.isEmpty ? "\"\"" : flags) \(service) \(replacement)"
        default:
            return nil
        }
    }

    #if canImport(dnssd)
    /// What one query to the DNS service collected, filled in by its reply
    /// callback on the thread `query` runs.
    private final class Collected {
        let record: SipralDnsRecordType
        var records: [String] = []
        var answer: SipralDnsAnswer?
        init(record: SipralDnsRecordType) { self.record = record }
    }

    /// `DNSServiceQueryRecord` for `name`, read until the last answer came
    /// or `patienceMs` ran out.
    static func query(_ name: String, _ record: SipralDnsRecordType) -> DnsLookupAnswer {
        let type = record == .srv ? kDNSServiceType_SRV : kDNSServiceType_NAPTR
        let collected = Collected(record: record)
        var service: DNSServiceRef?
        let context = Unmanaged.passRetained(collected)
        defer { context.release() }
        let flags = DNSServiceFlags(kDNSServiceFlagsReturnIntermediates | kDNSServiceFlagsTimeout)
        let started = DNSServiceQueryRecord(
            &service, flags, 0, name, UInt16(type), UInt16(kDNSServiceClass_IN),
            { _, flags, _, error, _, _, _, length, data, ttl, context in
                guard let context else { return }
                let collected = Unmanaged<Collected>.fromOpaque(context).takeUnretainedValue()
                switch Int(error) {
                case kDNSServiceErr_NoError:
                    if flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0, let data, length > 0 {
                        let bytes = Array(UnsafeRawBufferPointer(start: data, count: Int(length)))
                        if let text = SipralDns.zoneText(of: collected.record, data: bytes, ttl: ttl) {
                            collected.records.append(text)
                        }
                    }
                    if flags & DNSServiceFlags(kDNSServiceFlagsMoreComing) == 0 {
                        collected.answer = collected.records.isEmpty ? .nothing : .records
                    }
                case kDNSServiceErr_NoSuchRecord, kDNSServiceErr_NoSuchName:
                    collected.answer = collected.records.isEmpty ? .nothing : .records
                default:
                    collected.answer = collected.records.isEmpty ? .failed : .records
                }
            },
            context.toOpaque()
        )
        guard started == kDNSServiceErr_NoError, let service else { return .failed }
        defer { DNSServiceRefDeallocate(service) }
        let descriptor = DNSServiceRefSockFD(service)
        let deadline = DispatchTime.now() + .milliseconds(Int(patienceMs))
        while collected.answer == nil {
            let left = Int64(deadline.uptimeNanoseconds) - Int64(DispatchTime.now().uptimeNanoseconds)
            guard left > 0 else { break }
            var readable = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            guard poll(&readable, 1, Int32(min(left / 1_000_000, Int64(patienceMs)))) > 0 else { continue }
            guard DNSServiceProcessResult(service) == kDNSServiceErr_NoError else { break }
        }
        guard let answer = collected.answer else {
            return collected.records.isEmpty ? .failed : DnsLookupAnswer(answer: .records, records: collected.records)
        }
        return DnsLookupAnswer(answer: answer, records: answer == .records ? collected.records : [])
    }
    #endif
}

extension SipralStack {
    /// `sipral_advertised_address`: the `host:port` to advertise for a
    /// socket bound at `bound` whose traffic goes to `peer`. A wildcard bind
    /// (`0.0.0.0:5060`) gives the address of the route toward `peer`; a
    /// loopback bind toward a peer that is not throws `.unreachableAddress`,
    /// and no route at all `.transportDown`. Both are addresses, not names.
    public static func advertisedAddress(bound: String, peer: String) throws -> String {
        var buffer = [CChar](repeating: 0, count: 128)
        let needed = try Sipral.advertisedAddress(bound: bound, peer: peer, buffer: &buffer)
        let bytes = buffer.prefix(max(0, needed - 1)).map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// The address of this machine's route toward `peer` (`host:port`), the
    /// one a socket bound on every interface is reached at from there;
    /// `127.0.0.1` when there is no peer, it is a name rather than an
    /// address, or no route reaches it -- the address that works for a peer
    /// on this machine and that the library refuses to advertise to any
    /// other.
    public static func routeHost(toward peer: String?) -> String {
        guard let peer, isAddress(peer) else { return "127.0.0.1" }
        let wildcard = peer.hasPrefix("[") ? "[::]:0" : "0.0.0.0:0"
        guard let advertised = try? advertisedAddress(bound: wildcard, peer: peer) else { return "127.0.0.1" }
        return UDPSocket.parse(advertised).host
    }

    /// Whether `text` is `host:port` with an IP address for its host.
    static func isAddress(_ text: String) -> Bool {
        let (host, port) = UDPSocket.parse(text)
        guard port != 0 || text.hasSuffix(":0") else { return false }
        let bare = host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
        var v4 = in_addr()
        var v6 = in6_addr()
        return inet_pton(AF_INET, bare, &v4) == 1 || inet_pton(AF_INET6, bare, &v6) == 1
    }
}
