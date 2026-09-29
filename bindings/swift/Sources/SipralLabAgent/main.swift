// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

// A headless voice agent: answers, listens, talks back, hangs up on "#".
//
// The Swift-layer equivalent of `bindings/python/examples/agent.py`, run the
// same way by `scripts/lab.sh`'s own `swift_agent`: registered at Asterisk as
// `labuser-agent-swift`, dialled by `[agent-call]`, and its log read back for
// "answered", the "#" it hangs up on, and packets both ways.
//
//   SIPRAL_AOR=sip:agent@example.invalid \
//   SIPRAL_REGISTRAR=sip:example.invalid \
//   SIPRAL_REGISTRAR_ADDRESS=203.0.113.10:5060 \
//   SIPRAL_AUTH_USER=agent SIPRAL_AUTH_PASSWORD=secret \
//   SipralLabAgent
//
// SIPRAL_SIGNALLING is udp (the default), tcp or tls: over either of the
// last two the agent keeps one connection to SIPRAL_REGISTRAR_ADDRESS and
// signals on it, and over TLS -- on Apple platforms, where Network.framework
// is -- checks the server's certificate against SIPRAL_TLS_SERVER_NAME (the
// address's host when unset) with SIPRAL_TLS_CA as the only authority it
// trusts (the system's when unset). A connection that fails is printed as
// "transport failed error=<...> tls=<...>" with Security's own words, and
// tried again. SIPRAL_INVITE_LIMIT=voice-agent takes a trunk's rush of calls
// the default rate floor would answer 480.

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Dispatch
import Foundation
import Sipral

// Unbuffered: this agent's log is read from `docker logs` while it is still
// running, the same reason `scripts/lab.sh`'s `python_agent` runs
// `python3 -u`. Block-buffered stdio would hold every line back until this
// process exited, which it never does on its own.
setbuf(stdout, nil)

/// Which of this host's addresses a datagram to `address` leaves from.
///
/// That address goes in the `Contact` and in every answer's SDP, so it has
/// to be one the far end can send to: a stack bound to `0.0.0.0` advertises
/// it, and a registrar or a phone handed `0.0.0.0` has nowhere to send
/// anything back. Connecting a datagram socket sends nothing; it only asks
/// the system which route it would take
/// (`bindings/python/examples/agent.py`'s `route_to`).
func routeTo(_ address: String) -> String {
    let (host, port) = UDPSocket.parse(address)
    #if canImport(Darwin)
    let socketType = SOCK_DGRAM
    #else
    let socketType = Int32(SOCK_DGRAM.rawValue)
    #endif
    let probe = socket(AF_INET, socketType, 0)
    defer {
        #if canImport(Darwin)
        Darwin.close(probe)
        #else
        Glibc.close(probe)
        #endif
    }
    var target = sockaddr_in()
    target.sin_family = sa_family_t(AF_INET)
    target.sin_port = port.bigEndian
    inet_pton(AF_INET, host, &target.sin_addr)
    _ = withUnsafePointer(to: &target) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
            connect(probe, raw, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    var local = sockaddr_in()
    var localLen = socklen_t(MemoryLayout<sockaddr_in>.size)
    _ = withUnsafeMutablePointer(to: &local) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
            getsockname(probe, raw, &localLen)
        }
    }
    var buffer = [Int8](repeating: 0, count: Int(INET_ADDRSTRLEN))
    inet_ntop(AF_INET, &local.sin_addr, &buffer, socklen_t(INET_ADDRSTRLEN))
    return String(cString: buffer)
}

func environmentValue(_ name: String) -> String? {
    guard let value = getenv(name) else { return nil }
    return String(cString: value)
}

/// The one function a real agent replaces. Default: an echo.
func respond(_ pcm: [Int16]) -> [Int16] { pcm }

/// `call.media` may still be `nil` the instant a call is answered; this
/// waits for it once, off `events`, the way
/// `bindings/python/examples/agent.py`'s `run_call` does. `events` is a
/// stream of this function's own, taken before the call was answered, so
/// the `mediaStarted` that sets `call.media` cannot slip past it.
func mediaFrames(of call: Call, watching events: AsyncStream<SipralEvent>) async -> AsyncStream<[Int16]> {
    if let media = call.media { return media.frames() }
    for await _ in events {
        if let media = call.media { return media.frames() }
    }
    return AsyncStream { $0.finish() }
}

private enum Termination: Sendable {
    case hangupRequested
    case remoteEnded
}

/// The streams one call is watched through, each taken before the answer
/// goes out: every one of them sees every event from then on, so three
/// readers of the same call split nothing between them.
struct CallStreams: Sendable {
    let forMedia: AsyncStream<SipralEvent>
    let forEnd: AsyncStream<SipralEvent>
    let digits: AsyncStream<Character>

    init(_ call: Call) {
        forMedia = call.events()
        forEnd = call.events()
        digits = call.dtmf()
    }
}

/// The last statistics read while the call was up. Once the far end's BYE
/// is answered the stack ends the call's media on its own poll thread, and a
/// statistics call after that answers that the media has ended rather than
/// with numbers -- so the call is read every 200 ms while it lasts, and the
/// numbers printed at the end are the last ones that came back.
final class LastStatistics: @unchecked Sendable {
    private let queue = DispatchQueue(label: "org.sipral.lab-agent.statistics")
    private var sent: UInt64 = 0
    private var received: UInt64 = 0

    func read(_ media: Media?) {
        guard let media, let stats = try? media.statistics() else { return }
        queue.sync {
            sent = stats.packets_sent
            received = stats.packets_received
        }
    }

    var counts: (sent: UInt64, received: UInt64) {
        queue.sync { (sent, received) }
    }
}

func runCall(_ call: Call, _ streams: CallStreams) async {
    print("answered \(String(call.handle, radix: 16))")

    let last = LastStatistics()
    let statisticsTask = Task {
        while !Task.isCancelled {
            last.read(call.media)
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
    }

    let talkTask = Task {
        for await frame in await mediaFrames(of: call, watching: streams.forMedia) {
            call.media?.sendAudio(respond(frame))
        }
    }

    let termination = await withTaskGroup(of: Termination.self) { group -> Termination in
        group.addTask {
            for await digit in streams.digits {
                print("dtmf \(digit)")
                if digit == "#" { return .hangupRequested }
            }
            return .remoteEnded
        }
        group.addTask {
            // Finishes right after the call's `callEnded`.
            for await _ in streams.forEnd {}
            return .remoteEnded
        }
        let first = await group.next() ?? .remoteEnded
        group.cancelAll()
        return first
    }
    talkTask.cancel()

    if termination == .hangupRequested {
        // The call is still up, so this last reading is the final count.
        last.read(call.media)
        // Read fresh from the stack, not from an event: an answered call
        // stays ringing until its ACK arrives, so "confirmed" here is this
        // end's word that the caller acknowledged the 200 OK.
        if let state = try? call.state {
            print("state \(String(call.handle, radix: 16)): \(state)")
        }
        try? call.hangup()
    }
    statisticsTask.cancel()
    call.close()

    let counts = last.counts
    print("ended \(String(call.handle, radix: 16)): packets_sent=\(counts.sent) packets_received=\(counts.received)")
}

/// Whether `call` has ended within `milliseconds`, read off `events`, a
/// stream of the call's own that finishes when the call ends. Both of the
/// group's children give up when the group cancels them, so it returns as
/// soon as either does. A child that awaited an unstructured task's `value`
/// would not: cancelling the child does not cancel that task, and a group
/// waits for every child before it returns -- which left the lab agent,
/// once it had dwelt, waiting for a far end that never hangs up before it
/// would hang up itself.
func endedWithin(_ call: Call, _ events: AsyncStream<SipralEvent>, milliseconds: UInt64) async -> Bool {
    if call.ended { return true }
    return await withTaskGroup(of: Bool.self) { group -> Bool in
        group.addTask {
            for await _ in events where call.ended {
                return true
            }
            return call.ended
        }
        group.addTask {
            try? await Task.sleep(nanoseconds: milliseconds * 1_000_000)
            return call.ended
        }
        let first = await group.next() ?? false
        group.cancelAll()
        return first || call.ended
    }
}

/// Talk for the life of one call this end placed against a peer with
/// nothing of its own that would ever hang up first (the lab's own
/// two-NAT pair, `scripts/lab.sh`'s `ice_turn_flow`, where the far end is
/// the harness's own `iceanswer` role rather than a server): `patienceMs`
/// is how long this end waits for media at all, so a call under
/// `SipralIce.required` with every path blocked is given up on rather than
/// waited on forever, and `dwellMs` is how long it talks before hanging up
/// on its own once media has started. `false` when it ended before media
/// ever started, which `runDirectCall` needs to tell apart from an
/// ordinary hangup.
func runCallDirect(_ call: Call, patienceMs: UInt64, dwellMs: UInt64) async -> Bool {
    print("answered \(String(call.handle, radix: 16))")
    // A stream of its own for each reader, the same rule `CallStreams` above
    // follows and `Call.events()`'s own doc comment gives: one `AsyncStream`
    // value fed to two separate `for await` loops is not two readers, it is
    // one reader two loops race for, and the loser waits on a stream nothing
    // is ever going to deliver to again.
    let forMedia = call.events()
    let forEnd = call.events()

    let gotMedia: Bool = if call.media != nil {
        true
    } else {
        await withTaskGroup(of: Bool.self) { group -> Bool in
            group.addTask {
                for await _ in forMedia where call.media != nil {
                    return true
                }
                return call.media != nil
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: patienceMs * 1_000_000)
                return false
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first || call.media != nil
        }
    }
    guard gotMedia, let media = call.media else {
        print("ended \(String(call.handle, radix: 16)): no media within \(patienceMs)ms -- no path was ever chosen")
        try? call.hangup()
        call.close()
        return false
    }

    let last = LastStatistics()
    let statisticsTask = Task {
        while !Task.isCancelled {
            last.read(call.media)
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
    }
    let talkTask = Task {
        for await frame in media.frames() {
            call.media?.sendAudio(respond(frame))
        }
    }
    // the dwell, cut short by the far end hanging up first; then this end's
    // own hangup, which waits on nothing the far end has to do
    if !(await endedWithin(call, forEnd, milliseconds: dwellMs)) {
        // one last read while the call is still certainly up, for the
        // freshest number this path can give
        last.read(call.media)
        try? call.hangup()
        // the relayed call's farewell -- the TURN Refresh that gives its
        // allocation back, not only the RTCP BYE -- is queued once the far
        // end's 200 to this end's own BYE is read, so this waits for
        // `call.ended` rather than closing right behind hangup(); on a
        // stream of its own, since the one above finished when its reader
        // was cancelled
        _ = await endedWithin(call, call.events(), milliseconds: 5_000)
    }
    talkTask.cancel()
    statisticsTask.cancel()
    // the same short wait bindings/python/examples/agent.py's own
    // hang_up_after_dwell gives, so a relayed call's farewell has had its
    // own turn before the stack tears the socket down
    try? await Task.sleep(nanoseconds: 200_000_000)

    call.close()
    let counts = last.counts
    print("ended \(String(call.handle, radix: 16)): packets_sent=\(counts.sent) packets_received=\(counts.received)")
    return true
}

/// Dial a peer straight at its address, no registrar between them --
/// `scripts/lab.sh`'s own `ice_turn_flow`, where the far end is the
/// harness's own `iceanswer` role rather than a server.
/// SIPRAL_PEER_HOST/SIPRAL_PEER_PORT name it, and the account this end
/// adds is one whose `registrarAddress` is just the routing destination
/// for: `registrar` is left `nil`, so nothing is ever registered.
///
/// SIPRAL_STUN_SERVER turns on STUN the same way `SipralStack`'s own
/// initializer already offers any application; SIPRAL_TURN_SERVER/
/// SIPRAL_TURN_USER/SIPRAL_TURN_PASSWORD ride on it. SIPRAL_TURN_TRANSPORT
/// is `udp`, `tcp` or `tls` (RFC 8656 §3.1); over TLS the server's
/// certificate is checked against SIPRAL_TURN_NAME and trusted if it chains
/// to a certificate in the PEM file SIPRAL_TURN_CA names, the system's
/// roots otherwise. TLS needs Network.framework, which only Apple's
/// platforms have: on Linux the stack opens the connection with a plain
/// socket, over TCP, and a relay asked for over TLS fails. SIPRAL_ICE=required
/// asks `SipralIce.required` of the stack, which is what makes a call that
/// cannot find a path fail outright rather than fall back to the address
/// this end bound to -- the one thing that would let a run through a
/// blocked NAT pair pass by accident.
func runDirectCall() async -> Bool {
    guard let peerHost = environmentValue("SIPRAL_PEER_HOST") else {
        print("SIPRAL_PEER_HOST is required")
        return false
    }
    let peerPort = environmentValue("SIPRAL_PEER_PORT") ?? "5060"
    let peerUser = environmentValue("SIPRAL_PEER_USER") ?? "callee"
    let peer = "\(peerHost):\(peerPort)"
    let host = routeTo(peer)

    let stunServer = environmentValue("SIPRAL_STUN_SERVER")
    let turnServer = environmentValue("SIPRAL_TURN_SERVER")
    let over = environmentValue("SIPRAL_TURN_TRANSPORT") ?? "udp"
    let transport: SipralTransport
    switch over {
    case "udp": transport = .udp
    case "tcp": transport = .tcp
    case "tls": transport = .tls
    default:
        print("SIPRAL_TURN_TRANSPORT is udp, tcp or tls, not \(over)")
        return false
    }
    let trusted = environmentValue("SIPRAL_TURN_CA").map(certificatesIn) ?? []
    let turn = turnServer.map {
        TurnServer(
            address: $0,
            username: environmentValue("SIPRAL_TURN_USER") ?? "",
            password: environmentValue("SIPRAL_TURN_PASSWORD") ?? "",
            transport: transport,
            serverName: environmentValue("SIPRAL_TURN_NAME"),
            trustedCertificates: trusted
        )
    }
    let ice: SipralIce? = environmentValue("SIPRAL_ICE") == "required" ? .required : nil

    let stack: SipralStack
    let account: Account
    let call: Call
    do {
        stack = try SipralStack(audio: .application, bindHost: host, ice: ice, stunServer: stunServer, turn: turn)
        account = try stack.addAccount(aor: "sip:caller@\(stack.bindAddress)", registrarAddress: peer)
        print("dialling sip:\(peerUser)@\(peer) from \(stack.bindAddress)")
        call = try stack.placeCall(account: account, target: "sip:\(peerUser)@\(peer)", mediaHost: host, destination: peer, ice: ice)
    } catch {
        print("call failed: \(error)")
        return false
    }
    let patienceMs = UInt64(environmentValue("SIPRAL_PATIENCE_MS") ?? "20000") ?? 20000
    let dwellMs = UInt64(environmentValue("SIPRAL_DWELL_MS") ?? "2000") ?? 2000
    let ok = await runCallDirect(call, patienceMs: patienceMs, dwellMs: dwellMs)
    if ok, let turnServer, transport != .udp {
        print("relay over \(over.uppercased()) to \(turnServer): the call ran through it")
    }
    return ok
}

/// "nameMismatch" as the other agents print it, "name_mismatch".
func snake(_ name: String) -> String {
    name.reduce(into: "") { out, character in
        if character.isUppercase {
            out += "_" + character.lowercased()
        } else {
            out.append(character)
        }
    }
}

/// The DER of every certificate in the PEM file at `path`, which is what
/// `TurnServer.trustedCertificates` takes: how the lab's coturn, whose
/// certificate is made for the run, is trusted over TLS.
func certificatesIn(_ path: String) -> [[UInt8]] {
    guard let pem = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
    var found: [[UInt8]] = []
    var body = ""
    var inside = false
    for line in pem.split(whereSeparator: \.isNewline) {
        if line.hasPrefix("-----BEGIN CERTIFICATE-----") {
            inside = true
            body = ""
        } else if line.hasPrefix("-----END CERTIFICATE-----") {
            inside = false
            if let der = Data(base64Encoded: body) {
                found.append([UInt8](der))
            }
        } else if inside {
            body += line.trimmingCharacters(in: .whitespaces)
        }
    }
    return found
}

// The lab's own NAT-pair flow (`ice_turn_flow`) runs this mode instead of
// the registrar-and-listen one below: SIPRAL_PEER_HOST is what tells the
// two apart, since a real registrar address never doubles as one -- the
// same tell `bindings/python/examples/agent.py`'s own `main` reads.
if environmentValue("SIPRAL_PEER_HOST") != nil {
    let ok = await runDirectCall()
    exit(ok ? 0 : 1)
}

let registrarAddress = environmentValue("SIPRAL_REGISTRAR_ADDRESS") ?? "127.0.0.1:5060"
let bindHost = routeTo(registrarAddress)
let signalling: SipralTransport
switch environmentValue("SIPRAL_SIGNALLING") ?? "udp" {
case "udp": signalling = .udp
case "tcp": signalling = .tcp
case "tls": signalling = .tls
case let other:
    print("SIPRAL_SIGNALLING is udp, tcp or tls, not \(other)")
    exit(1)
}
let authority = environmentValue("SIPRAL_TLS_CA").flatMap { certificatesIn($0).first }
let stack = try SipralStack(
    audio: .application, bindHost: bindHost,
    signalling: signalling,
    signallingServer: signalling == .udp ? nil : registrarAddress,
    tlsServerName: environmentValue("SIPRAL_TLS_SERVER_NAME"),
    tlsTrust: authority.map { .onlyAuthority($0) } ?? .platform,
    inviteLimit: environmentValue("SIPRAL_INVITE_LIMIT") == "voice-agent" ? .voiceAgent : nil
)
let account = try stack.addAccount(
    aor: environmentValue("SIPRAL_AOR") ?? "sip:agent@example.invalid",
    registrarAddress: registrarAddress,
    registrar: environmentValue("SIPRAL_REGISTRAR"),
    authUser: environmentValue("SIPRAL_AUTH_USER"),
    authPassword: environmentValue("SIPRAL_AUTH_PASSWORD")
)
// Taken before the REGISTER goes out, so that nothing it raises -- the
// first INVITE included, however soon it follows -- lands before a reader.
let stackEvents = stack.events()
if environmentValue("SIPRAL_REGISTRAR") != nil {
    try account.register()
}
print("listening on \(stack.bindAddress)")

await withTaskGroup(of: Void.self) { group in
    for await event in stackEvents {
        if let failed = event.transportFailedData {
            let error = failed.error.map { "\($0)" } ?? "\(failed.protocolRaw)"
            let tls = failed.tls.map { "\($0)" } ?? "none"
            print("transport failed error=\(snake(error)) tls=\(snake(tls)): \(failed.detail ?? "")")
        }
        if event.kind == .incomingCall {
            guard let call = try? stack.takeIncomingCall(event, mediaHost: bindHost) else { continue }
            let streams = CallStreams(call)
            do {
                try call.answer()
            } catch {
                print("answer failed \(String(call.handle, radix: 16)): \(error)")
                call.close()
                continue
            }
            group.addTask { await runCall(call, streams) }
        }
    }
}
