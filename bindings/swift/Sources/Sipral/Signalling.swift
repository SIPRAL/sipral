// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import CSipral
import Dispatch
#if canImport(Network)
import Foundation
import Network
import Security
#endif

/// Which authorities a TLS connection to the SIP server trusts -- the three
/// answers `docs/22-tls.md` gives for every platform: `.platform` (the
/// system's own store, what a public server's certificate is checked
/// against), `.privateAuthority` (a private CA, DER-encoded, beside the
/// system's) and `.onlyAuthority` (that authority and no other: pinning it).
/// The name is checked by the SSL policy against the server name the stack
/// was given; none of them turns a check off. TLS is Network.framework's,
/// on Apple platforms only.
public enum TLSTrust: Sendable {
    case platform
    case privateAuthority([UInt8])
    case onlyAuthority([UInt8])
}

/// How fast one address may ring a stack: `burst` INVITEs at once, then one
/// more every `everyMs` (`sipral_stack_invite_limit`). `.standard` is what
/// every stack starts with -- ten, then one every two seconds, past which a
/// call is answered 480 -- and `.voiceAgent` the preset for a headless
/// service taking a trunk's calls, a hundred and twenty-eight at once and
/// then twenty a second (`docs/08-ffi.md`, "How fast one address may ring
/// this stack").
public struct InviteLimit: Sendable, Equatable {
    public let burst: UInt32
    public let everyMs: UInt64

    public init(burst: UInt32, everyMs: UInt64) {
        self.burst = burst
        self.everyMs = everyMs
    }

    /// Ten at once, then one every two seconds.
    public static let standard = InviteLimit(burst: Sipral.inviteLimitBurst, everyMs: Sipral.inviteLimitEveryMs)

    /// A hundred and twenty-eight at once, then one every fifty milliseconds.
    public static let voiceAgent = InviteLimit(
        burst: Sipral.inviteLimitVoiceAgentBurst, everyMs: Sipral.inviteLimitVoiceAgentEveryMs
    )
}

/// A transport this stack signals on stopped carrying traffic
/// (`sipral_transport_failed_event_t`): which one, what it spoke, what went
/// wrong and, when TLS refused the connection, why, with the TLS library's
/// own `detail`.
public struct TransportFailedEventData: Sendable {
    public let transport: UInt32
    public let protocolRaw: UInt32
    public let error: SipralTransportError?
    public let tls: SipralTlsFailure?
    public let detail: String?
}

/// A connection that could not be made, and what the stack is to call it.
struct SignallingRefusal: Error, Sendable {
    let error: SipralTransportError
    let tls: SipralTlsFailure
    let detail: String

    /// One line of at most `SIPRAL_TRANSPORT_DETAIL_BYTES` bytes of UTF-8.
    static func sentence(_ text: String) -> String {
        var line = String(text.map { $0.isNewline || ($0.asciiValue.map { $0 < 0x20 || $0 == 0x7F } ?? false) ? " " : $0 })
        while line.utf8.count > Sipral.transportDetailBytes {
            line.removeLast()
        }
        return line
    }
}

/// The one connection a `SipralStack` signals on over TCP or TLS.
///
/// On Apple platforms a Network.framework `NWConnection`, over TLS with the
/// certificate checked against `serverName` under `TLSTrust`; elsewhere a
/// plain TCP socket, TLS being refused there before any connection is
/// made, since there is no platform TLS to bring. `open` blocks until the
/// connection is ready or refused; `bytes` gets everything read, in order,
/// on the connection's own queue; `lost` once, for a connection that was
/// open and went away -- `nil` for an orderly close.
final class SignallingConnection: @unchecked Sendable {
    private let lock = SignallingLock()
    private var finished = false
    private var bytes: (@Sendable ([UInt8]) -> Void)?
    private var lost: (@Sendable (SignallingRefusal?) -> Void)?
    private(set) var local = ""
    private(set) var remote = ""
    #if canImport(Network)
    private let connection: NWConnection
    private let queue: DispatchQueue
    /// What the certificate check said when it refused, kept for the reason
    /// the refused handshake is reported with.
    private let verdict = SignallingVerdict()
    #else
    private var fd: Int32 = -1
    #endif

    /// Connect from `bindHost` to `server`, over TLS when `transport` says
    /// so; throws the refusal.
    init(
        server: String, bindHost: String, transport: SipralTransport, serverName: String, trust: TLSTrust,
        patienceMs: Int
    ) throws {
        let (host, port) = UDPSocket.parse(server)
        #if canImport(Network)
        queue = DispatchQueue(label: "org.sipral.signalling.\(server)")
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.connectionTimeout = max(1, patienceMs / 1000)
        let parameters: NWParameters
        if transport == .tls {
            let tls = NWProtocolTLS.Options()
            let security = tls.securityProtocolOptions
            sec_protocol_options_set_tls_server_name(security, serverName)
            let anchors: [SecCertificate]
            let only: Bool
            switch trust {
            case .platform:
                anchors = []
                only = false
            case .privateAuthority(let der):
                anchors = [SecCertificateCreateWithData(nil, Data(der) as CFData)].compactMap { $0 }
                only = false
            case .onlyAuthority(let der):
                anchors = [SecCertificateCreateWithData(nil, Data(der) as CFData)].compactMap { $0 }
                only = true
            }
            let verdict = self.verdict
            sec_protocol_options_set_verify_block(security, { _, trust, complete in
                let evaluated = sec_trust_copy_ref(trust).takeRetainedValue()
                SecTrustSetPolicies(evaluated, SecPolicyCreateSSL(true, serverName as CFString))
                if !anchors.isEmpty {
                    SecTrustSetAnchorCertificates(evaluated, anchors as CFArray)
                    SecTrustSetAnchorCertificatesOnly(evaluated, only)
                }
                var failure: CFError?
                let trusted = SecTrustEvaluateWithError(evaluated, &failure)
                if !trusted {
                    verdict.keep(Self.refusal(failure))
                }
                complete(trusted)
            }, DispatchQueue(label: "org.sipral.signalling.trust"))
            connection = NWConnection(
                host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port) ?? 5061,
                using: NWParameters(tls: tls, tcp: tcp)
            )
            parameters = connection.parameters
        } else {
            connection = NWConnection(
                host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port) ?? 5060,
                using: NWParameters(tls: nil, tcp: tcp)
            )
            parameters = connection.parameters
        }
        parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(bindHost), port: 0)
        let settled = DispatchSemaphore(value: 0)
        let outcome = SignallingOutcome()
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                if outcome.settle(nil) {
                    settled.signal()
                } else {
                    return
                }
            case .waiting(let error), .failed(let error):
                var refusal = self.verdict.kept ?? Self.refusal(error)
                if refusal.error == .connectionReset && refusal.tls == .none && !outcome.isSettled {
                    // a reset answering the SYN, before the connection was
                    // ever ready, is a port nothing listens on: refused,
                    // which is what BSD sockets call it
                    refusal = SignallingRefusal(error: .connectionRefused, tls: .none, detail: refusal.detail)
                }
                if outcome.settle(refusal) {
                    settled.signal()
                } else {
                    self.finish(refusal)
                }
            case .cancelled:
                if !outcome.settle(SignallingRefusal(error: .other, tls: .none, detail: "the connection was cancelled")) {
                    self.finish(nil)
                } else {
                    settled.signal()
                }
            default:
                break
            }
        }
        connection.start(queue: queue)
        if settled.wait(timeout: .now() + .milliseconds(patienceMs + 1000)) == .timedOut {
            _ = outcome.settle(SignallingRefusal(
                error: .timedOut, tls: .none, detail: "no connection to \(server) in \(patienceMs / 1000) seconds"
            ))
        }
        if let refusal = outcome.refusal {
            lock.withLock { finished = true }
            connection.cancel()
            throw refusal
        }
        let path = { [connection, queue] in queue.sync { connection.currentPath?.localEndpoint } }
        guard let named = Self.localAddress(within: patienceMs, reading: path) else {
            lock.withLock { finished = true }
            connection.cancel()
            throw SignallingRefusal(
                error: .other, tls: .none, detail: "the connection to \(server) never named its local address"
            )
        }
        local = named
        if case .hostPort(let remoteHost, let remotePort) = connection.endpoint {
            remote = "\(Self.text(remoteHost)):\(remotePort.rawValue)"
        }
        #else
        guard transport == .tcp else {
            throw SipralError(status: .notSupported, message: "SIP over TLS needs Network.framework, which this platform has not")
        }
        let descriptor = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard descriptor >= 0 else {
            throw SignallingRefusal(error: .other, tls: .none, detail: "no socket")
        }
        var source = sockaddr_in()
        source.sin_family = sa_family_t(AF_INET)
        inet_pton(AF_INET, bindHost, &source.sin_addr)
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host, &address.sin_addr) == 1 else {
            _ = SignallingC.close(descriptor)
            throw SignallingRefusal(error: .other, tls: .none, detail: "\(host) is not an IPv4 address")
        }
        let bound = withUnsafePointer(to: &source) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        let connected = bound == 0 ? withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                SignallingC.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        } : -1
        guard connected == 0 else {
            let code = errno
            _ = SignallingC.close(descriptor)
            let error: SipralTransportError = switch code {
            case ECONNREFUSED: .connectionRefused
            case ETIMEDOUT: .timedOut
            case ENETUNREACH, EHOSTUNREACH: .unreachable
            default: .other
            }
            throw SignallingRefusal(error: error, tls: .none, detail: String(cString: strerror(code)))
        }
        var on: Int32 = 1
        setsockopt(descriptor, Int32(IPPROTO_TCP), TCP_NODELAY, &on, socklen_t(MemoryLayout<Int32>.size))
        fd = descriptor
        local = Self.address(descriptor, local: true)
        remote = Self.address(descriptor, local: false)
        #endif
    }

    /// Start delivering what arrives, and how the connection ends.
    func start(bytes: @escaping @Sendable ([UInt8]) -> Void, lost: @escaping @Sendable (SignallingRefusal?) -> Void) {
        lock.withLock {
            self.bytes = bytes
            self.lost = lost
        }
        #if canImport(Network)
        receive()
        #else
        let descriptor = fd
        DispatchQueue.global(qos: .userInitiated).async { [self] in readLoop(descriptor) }
        #endif
    }

    /// Write one message, whole and after everything written before it; a
    /// connection that fails here is lost.
    func send(_ payload: [UInt8]) {
        #if canImport(Network)
        connection.send(content: payload, completion: .contentProcessed { [weak self] error in
            if let error {
                self?.finish(Self.refusal(error))
            }
        })
        #else
        var offset = 0
        while offset < payload.count {
            let written = payload.withUnsafeBytes { raw in
                #if canImport(Darwin)
                Darwin.send(fd, raw.baseAddress! + offset, payload.count - offset, 0)
                #else
                Glibc.send(fd, raw.baseAddress! + offset, payload.count - offset, Int32(MSG_NOSIGNAL))
                #endif
            }
            if written <= 0 {
                finish(SignallingRefusal(error: .connectionReset, tls: .none, detail: String(cString: strerror(errno))))
                return
            }
            offset += written
        }
        #endif
    }

    /// Close it, saying nothing.
    func close() {
        let already = lock.withLock { () -> Bool in
            defer { finished = true }
            return finished
        }
        guard !already else { return }
        #if canImport(Network)
        connection.cancel()
        #else
        shutdown(fd, Int32(SHUT_RDWR))
        _ = SignallingC.close(fd)
        #endif
    }

    private func finish(_ refusal: SignallingRefusal?) {
        let (already, lost) = lock.withLock { () -> (Bool, (@Sendable (SignallingRefusal?) -> Void)?) in
            defer { finished = true }
            return (finished, self.lost)
        }
        guard !already else { return }
        #if canImport(Network)
        connection.cancel()
        #else
        _ = SignallingC.close(fd)
        #endif
        lost?(refusal)
    }

    #if canImport(Network)
    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, complete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                let deliver = self.lock.withLock { self.bytes }
                deliver?([UInt8](data))
            }
            if let error {
                self.finish(Self.refusal(error))
                return
            }
            if complete {
                self.finish(nil)
                return
            }
            self.receive()
        }
    }

    /// What Security said about a certificate it refused: expired, a name
    /// mismatch, or untrusted.
    private static func refusal(_ failure: CFError?) -> SignallingRefusal {
        let code = failure.map { CFErrorGetCode($0) } ?? 0
        let detail = sentence(failure.map { CFErrorCopyDescription($0) as String } ?? "the certificate was refused")
        let tls: SipralTlsFailure = switch Int32(truncatingIfNeeded: code) {
        case errSecCertificateExpired, errSecCertificateNotValidYet: .expired
        case errSecHostNameMismatch: .nameMismatch
        default: .untrusted
        }
        return SignallingRefusal(error: .connectionReset, tls: tls, detail: detail)
    }

    /// What Network.framework said: a TLS failure the certificate check did
    /// not explain is a handshake refused; a POSIX error is what the socket
    /// said.
    private static func refusal(_ error: NWError) -> SignallingRefusal {
        let detail = sentence(error.debugDescription)
        switch error {
        case .tls:
            return SignallingRefusal(error: .connectionReset, tls: .handshakeRefused, detail: detail)
        case .posix(let code):
            let kind: SipralTransportError = switch code {
            case .ECONNREFUSED: .connectionRefused
            case .ETIMEDOUT: .timedOut
            case .ENETUNREACH, .EHOSTUNREACH, .ENETDOWN, .EHOSTDOWN: .unreachable
            case .ECONNRESET, .EPIPE, .ECONNABORTED: .connectionReset
            default: .other
            }
            return SignallingRefusal(error: kind, tls: .none, detail: detail)
        default:
            return SignallingRefusal(error: .other, tls: .none, detail: detail)
        }
    }

    private static func sentence(_ text: String) -> String { SignallingRefusal.sentence(text) }

    /// The local end of a connection that is ready, as `host:port`, or
    /// `nil` when `read` never named one within `patienceMs`. A connection
    /// can be ready while its path does not name the local end yet -- on a
    /// loaded machine the address arrives a moment later -- and that end is
    /// what the stack is created on and a transport is bound by, so the wait
    /// is for the address, not only for the state.
    static func localAddress(within patienceMs: Int, reading read: () -> NWEndpoint?) -> String? {
        let deadline = DispatchTime.now() + .milliseconds(patienceMs)
        while true {
            if case .hostPort(let host, let port)? = read() {
                return "\(text(host)):\(port.rawValue)"
            }
            guard DispatchTime.now() < deadline else { return nil }
            usleep(1000)
        }
    }

    private static func text(_ host: NWEndpoint.Host) -> String {
        switch host {
        case .ipv4(let address): return "\(address)".components(separatedBy: "%")[0]
        case .ipv6(let address): return "\(address)".components(separatedBy: "%")[0]
        case .name(let name, _): return name
        @unknown default: return "\(host)"
        }
    }
    #else
    private func readLoop(_ descriptor: Int32) {
        var buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let read = buffer.withUnsafeMutableBytes { recv(descriptor, $0.baseAddress, $0.count, 0) }
            if read == 0 {
                finish(nil)
                return
            }
            if read < 0 {
                finish(SignallingRefusal(error: .connectionReset, tls: .none, detail: String(cString: strerror(errno))))
                return
            }
            let deliver = lock.withLock { bytes }
            deliver?(Array(buffer.prefix(read)))
        }
    }

    private static func address(_ descriptor: Int32, local: Bool) -> String {
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                local ? getsockname(descriptor, $0, &length) : getpeername(descriptor, $0, &length)
            }
        }
        var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &address.sin_addr, &text, socklen_t(text.count))
        return "\(String(cString: text)):\(UInt16(bigEndian: address.sin_port))"
    }
    #endif
}

#if canImport(Network)
/// The certificate check's refusal, written on Security's queue and read on
/// the connection's.
private final class SignallingVerdict: @unchecked Sendable {
    private let lock = SignallingLock()
    private var refusal: SignallingRefusal?

    func keep(_ refusal: SignallingRefusal) {
        lock.withLock { self.refusal = refusal }
    }

    var kept: SignallingRefusal? { lock.withLock { refusal } }
}
#endif

/// The first answer a connection gets, kept once: ready, or refused.
private final class SignallingOutcome: @unchecked Sendable {
    private let lock = SignallingLock()
    private var settled = false
    private(set) var refusal: SignallingRefusal?

    /// Whether an answer came already.
    var isSettled: Bool { lock.withLock { settled } }

    /// Whether this was the first answer.
    func settle(_ refusal: SignallingRefusal?) -> Bool {
        lock.withLock {
            guard !settled else { return false }
            settled = true
            self.refusal = refusal
            return true
        }
    }
}

/// A mutex, without Foundation on the Linux build.
private final class SignallingLock: @unchecked Sendable {
    private var mutex = pthread_mutex_t()
    init() { pthread_mutex_init(&mutex, nil) }
    deinit { pthread_mutex_destroy(&mutex) }
    func withLock<T>(_ body: () -> T) -> T {
        pthread_mutex_lock(&mutex)
        defer { pthread_mutex_unlock(&mutex) }
        return body()
    }
}

#if !canImport(Network)
/// The C library's own `close` and `connect`, which the methods of the same
/// name above would otherwise shadow.
private enum SignallingC {
    static func close(_ descriptor: Int32) -> Int32 {
        #if canImport(Glibc)
        Glibc.close(descriptor)
        #else
        Darwin.close(descriptor)
        #endif
    }

    static func connect(_ descriptor: Int32, _ address: UnsafePointer<sockaddr>, _ length: socklen_t) -> Int32 {
        #if canImport(Glibc)
        Glibc.connect(descriptor, address, length)
        #else
        Darwin.connect(descriptor, address, length)
        #endif
    }
}
#endif
