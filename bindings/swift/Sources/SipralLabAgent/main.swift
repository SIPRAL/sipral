// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// A headless voice agent: answers, listens, talks back, hangs up on "#".
//
// Run by `scripts/lab.sh` (`swift_agent`), which reads its log back.
//
//   SIPRAL_AOR=sip:agent@example.invalid \
//   SIPRAL_REGISTRAR=sip:example.invalid \
//   SIPRAL_REGISTRAR_ADDRESS=203.0.113.10:5060 \
//   SIPRAL_AUTH_USER=agent SIPRAL_AUTH_PASSWORD=secret \
//   SipralLabAgent
//
// SIPRAL_SIGNALLING is udp (default), tcp or tls. TLS (Apple only) checks
// against SIPRAL_TLS_SERVER_NAME (default: the address's host) with
// SIPRAL_TLS_CA as the only authority (default: the system's).
// SIPRAL_INVITE_LIMIT=voice-agent lifts the default rate limit.
// SIPRAL_TEXT=echo echoes real-time text.

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Dispatch
import Foundation
import Sipral

// Unbuffered: the log is read from `docker logs` while the agent runs.
setbuf(stdout, nil)

/// Which of this host's addresses a datagram to `address` leaves from.
///
/// It goes in the `Contact` and SDP, so it must be reachable, unlike
/// `0.0.0.0`. Connecting a datagram socket sends nothing; it only picks the
/// route.
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

/// `call.media` may still be `nil` right after answering, so this waits
/// for `mediaStarted` on `events`, taken before the answer so it cannot be
/// missed.
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

/// One stream per reader, all taken before the answer goes out.
struct CallStreams: Sendable {
    let forMedia: AsyncStream<SipralEvent>
    let forEnd: AsyncStream<SipralEvent>
    let digits: AsyncStream<Character>
    let text: AsyncStream<TextEventData>

    init(_ call: Call) {
        forMedia = call.events()
        forEnd = call.events()
        digits = call.dtmf()
        text = call.text()
    }
}

/// With SIPRAL_TEXT=echo, what the caller types in real-time text (RFC
/// 4103) is printed and typed back to it.
let echoesText = environmentValue("SIPRAL_TEXT") == "echo"

/// Statistics are sampled every 200 ms, since after the far end's BYE the
/// media is gone and no longer answers.
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
    let textTask = Task {
        for await typed in streams.text {
            print("text \(typed.text.debugDescription)")
            try? call.media?.sendText(typed.text)
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
    textTask.cancel()

    if termination == .hangupRequested {
        // The call is still up, so this last reading is the final count.
        last.read(call.media)
        // Read fresh: "confirmed" means the caller's ACK arrived.
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

/// Whether `call` ended within `milliseconds`. Both children honour
/// cancellation, so it returns as soon as either finishes; awaiting an
/// unstructured task instead would block the group until the far end hung
/// up, which in the lab it never does first.
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

/// Talk on a placed call whose peer never hangs up first (the lab's
/// `ice_turn_flow`). `patienceMs` bounds the wait for media, so a blocked
/// ICE call gives up; `dwellMs` is the talk time. `false` when it ended
/// before media started.
func runCallDirect(_ call: Call, patienceMs: UInt64, dwellMs: UInt64) async -> Bool {
    print("answered \(String(call.handle, radix: 16))")
    // One stream per reader: two loops over one `AsyncStream` race for its
    // items, and the loser may wait forever.
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
    // dwell, unless the far end hangs up first
    if !(await endedWithin(call, forEnd, milliseconds: dwellMs)) {
        // last reading while certainly up
        last.read(call.media)
        try? call.hangup()
        // The TURN release is queued only after the 200 to our BYE, so wait
        // for `call.ended` (on a fresh stream: the one above is finished).
        _ = await endedWithin(call, call.events(), milliseconds: 5_000)
    }
    talkTask.cancel()
    statisticsTask.cancel()
    // let the relay's farewell leave before the socket closes
    try? await Task.sleep(nanoseconds: 200_000_000)

    call.close()
    let counts = last.counts
    print("ended \(String(call.handle, radix: 16)): packets_sent=\(counts.sent) packets_received=\(counts.received)")
    return true
}

/// Dial SIPRAL_PEER_HOST:SIPRAL_PEER_PORT directly, with no registrar (the
/// lab's `ice_turn_flow`).
///
/// SIPRAL_STUN_SERVER and SIPRAL_TURN_* configure NAT traversal;
/// SIPRAL_TURN_TRANSPORT is `udp`, `tcp` or `tls` (RFC 8656 §3.1), TLS
/// checked against SIPRAL_TURN_NAME and SIPRAL_TURN_CA (Apple only; on
/// Linux a TLS relay fails). SIPRAL_ICE=required makes a call with no path
/// fail instead of falling back to the bound address, which would let a
/// blocked-NAT run pass by accident.
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

/// The DER of every certificate in a PEM file, for
/// `TurnServer.trustedCertificates`.
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

// SIPRAL_PEER_HOST selects the direct-call mode.
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
// Taken before the REGISTER, so no event (even a quick INVITE) is missed.
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
            guard let call = try? stack.takeIncomingCall(event, mediaHost: bindHost, text: echoesText) else { continue }
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
