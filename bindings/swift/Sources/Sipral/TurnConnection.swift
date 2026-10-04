// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Dispatch
#if canImport(Network)
import Foundation
import Network
import Security
#endif

/// One media socket's TCP or TLS connection to the TURN server
/// (`SIPRAL_EVENT_KIND_TURN_STREAM`, RFC 8656 §3.1).
///
/// On Apple platforms it is a Network.framework `NWConnection`, over TLS
/// when the server was named with `SipralTransport.tls`: the handshake and
/// the certificate check are the platform's own, the name checked is
/// `TurnServer.serverName`, and the roots trusted are the system's or,
/// when `TurnServer.trustedCertificates` names some, those and nothing else.
/// Elsewhere -- the lab agent's Linux build -- it is a plain TCP socket,
/// and TLS is refused: there is no platform TLS to bring there.
///
/// Every callback arrives on the connection's own queue: `ready` once, with
/// whether it opened; `bytes` for everything read, in order; `closed` once,
/// for a connection that was open and went away. `send` may be called from
/// any thread and keeps the order it was called in.
final class TurnConnection: @unchecked Sendable {
    let local: String
    private let queue: DispatchQueue
    private let lock = NSLockish()
    private var finished = false
    private let ready: @Sendable (Bool) -> Void
    private let bytes: @Sendable ([UInt8]) -> Void
    private let closed: @Sendable () -> Void
    #if canImport(Network)
    private let connection: NWConnection
    private var opened = false
    #else
    private var fd: Int32 = -1
    #endif

    init(
        local: String, server: String, turn: TurnServer,
        ready: @escaping @Sendable (Bool) -> Void,
        bytes: @escaping @Sendable ([UInt8]) -> Void,
        closed: @escaping @Sendable () -> Void
    ) {
        self.local = local
        self.queue = DispatchQueue(label: "org.sipral.turn.\(local)")
        self.ready = ready
        self.bytes = bytes
        self.closed = closed
        let (host, port) = UDPSocket.parse(server)
        #if canImport(Network)
        let parameters: NWParameters
        if turn.transport == .tls {
            let tls = NWProtocolTLS.Options()
            let security = tls.securityProtocolOptions
            let name = turn.serverName ?? host
            sec_protocol_options_set_tls_server_name(security, name)
            let anchors = turn.trustedCertificates.compactMap {
                SecCertificateCreateWithData(nil, Data($0) as CFData)
            }
            if !anchors.isEmpty {
                // the roots given and nothing else, and the name as the
                // application gave it: a private CA or a self-signed server
                // is trusted exactly as far as it was asked to be
                sec_protocol_options_set_verify_block(security, { _, trust, complete in
                    let evaluated = sec_trust_copy_ref(trust).takeRetainedValue()
                    SecTrustSetPolicies(evaluated, SecPolicyCreateSSL(true, name as CFString))
                    SecTrustSetAnchorCertificates(evaluated, anchors as CFArray)
                    SecTrustSetAnchorCertificatesOnly(evaluated, true)
                    complete(SecTrustEvaluateWithError(evaluated, nil))
                }, queue)
            }
            parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        } else {
            let tcp = NWProtocolTCP.Options()
            tcp.noDelay = true
            parameters = NWParameters(tls: nil, tcp: tcp)
        }
        connection = NWConnection(
            host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port) ?? 3478, using: parameters
        )
        connection.stateUpdateHandler = { [weak self] state in self?.changed(state) }
        connection.start(queue: queue)
        #else
        let wantsTls = turn.transport == .tls
        queue.async { [self] in
            guard !wantsTls, let opened = Self.connect(host: host, port: port) else {
                finish(openedBefore: false)
                return
            }
            lock.withLock { fd = opened }
            self.ready(true)
            readLoop(opened)
        }
        #endif
    }

    /// Write `payload` on the connection, whole and after everything sent
    /// before it. A connection that fails here is closed, and `closed` said.
    func send(_ payload: [UInt8]) {
        #if canImport(Network)
        connection.send(content: payload, completion: .contentProcessed { [weak self] error in
            if error != nil { self?.fail() }
        })
        #else
        let descriptor = lock.withLock { fd }
        guard descriptor >= 0 else { return }
        var offset = 0
        while offset < payload.count {
            let written = payload.withUnsafeBytes { raw in
                #if canImport(Darwin)
                Darwin.send(descriptor, raw.baseAddress! + offset, payload.count - offset, 0)
                #else
                Glibc.send(descriptor, raw.baseAddress! + offset, payload.count - offset, Int32(MSG_NOSIGNAL))
                #endif
            }
            if written <= 0 {
                fail()
                return
            }
            offset += written
        }
        #endif
    }

    /// Close it, saying nothing: for a connection the stack asked to have
    /// closed, or found broken. What was sent before is written first --
    /// the Refresh that gives the relay back is usually the last of it.
    func close() {
        let already = lock.withLock { () -> Bool in
            defer { finished = true }
            return finished
        }
        guard !already else { return }
        #if canImport(Network)
        let connection = connection
        connection.send(
            content: nil, contentContext: .finalMessage, isComplete: true,
            completion: .contentProcessed { _ in connection.cancel() }
        )
        #else
        let descriptor = lock.withLock { () -> Int32 in
            defer { fd = -1 }
            return fd
        }
        if descriptor >= 0 {
            shutdown(descriptor, Int32(SHUT_RDWR))
            _ = Glibcish.close(descriptor)
        }
        #endif
    }

    private func fail() {
        #if canImport(Network)
        finish(openedBefore: lock.withLock { opened })
        #else
        finish(openedBefore: true)
        #endif
    }

    private func finish(openedBefore: Bool) {
        let already = lock.withLock { () -> Bool in
            defer { finished = true }
            return finished
        }
        guard !already else { return }
        #if canImport(Network)
        connection.cancel()
        #else
        let descriptor = lock.withLock { () -> Int32 in
            defer { fd = -1 }
            return fd
        }
        if descriptor >= 0 { _ = Glibcish.close(descriptor) }
        #endif
        if openedBefore { closed() } else { ready(false) }
    }

    #if canImport(Network)
    private func changed(_ state: NWConnection.State) {
        switch state {
        case .ready:
            lock.withLock { opened = true }
            ready(true)
            receive()

        case .waiting, .failed:
            // a refused port, a server that is not there, a handshake that
            // failed or a certificate nobody vouches for: Network.framework
            // would wait for a better path, and a relay that is not there
            // now is one the call goes without
            fail()
        case .cancelled:
            fail()
        default:
            break
        }
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, complete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.bytes([UInt8](data))
            }
            if complete || error != nil {
                self.fail()
                return
            }
            self.receive()
        }
    }
    #else
    private static func connect(host: String, port: UInt16) -> Int32? {
        let descriptor = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard descriptor >= 0 else { return nil }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host, &address.sin_addr) == 1 else {
            _ = Glibcish.close(descriptor)
            return nil
        }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Glibcish.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else {
            _ = Glibcish.close(descriptor)
            return nil
        }
        var on: Int32 = 1
        setsockopt(descriptor, Int32(IPPROTO_TCP), TCP_NODELAY, &on, socklen_t(MemoryLayout<Int32>.size))
        return descriptor
    }

    private func readLoop(_ descriptor: Int32) {
        var buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let read = buffer.withUnsafeMutableBytes { recv(descriptor, $0.baseAddress, $0.count, 0) }
            if read <= 0 {
                fail()
                return
            }
            bytes(Array(buffer.prefix(read)))
        }
    }
    #endif
}

/// `NSLock`'s one use here, without Foundation on the Linux build.
private final class NSLockish: @unchecked Sendable {
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
private enum Glibcish {
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
