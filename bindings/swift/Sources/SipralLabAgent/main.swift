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

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
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
/// waits for it once, off `call.events`, the way
/// `bindings/python/examples/agent.py`'s `run_call` does.
func mediaFrames(of call: Call) async -> AsyncStream<[Int16]> {
    if let media = call.media { return media.frames }
    for await _ in call.events {
        if let media = call.media { return media.frames }
    }
    return AsyncStream { $0.finish() }
}

private enum Termination: Sendable {
    case hangupRequested
    case remoteEnded
}

func runCall(_ call: Call) async {
    print("answered \(String(call.handle, radix: 16))")

    let talkTask = Task {
        for await frame in await mediaFrames(of: call) {
            call.media?.sendAudio(respond(frame))
        }
    }

    let termination = await withTaskGroup(of: Termination.self) { group -> Termination in
        group.addTask {
            for await digit in call.dtmf {
                print("dtmf \(digit)")
                if digit == "#" { return .hangupRequested }
            }
            return .remoteEnded
        }
        group.addTask {
            for await _ in call.events {
                if call.ended { return .remoteEnded }
            }
            return .remoteEnded
        }
        let first = await group.next() ?? .remoteEnded
        group.cancelAll()
        return first
    }
    talkTask.cancel()

    var sent: UInt64 = 0
    var received: UInt64 = 0
    func captureStats(_ media: Media?) {
        guard let media, let stats = try? media.statistics() else { return }
        sent = stats.packets_sent
        received = stats.packets_received
    }

    if termination == .hangupRequested {
        // Read while the call is still up: once the BYE is answered the
        // stack ends the call's media on its own poll thread, and a
        // statistics call after that answers that the media has ended
        // rather than with numbers.
        captureStats(call.media)
        // Read fresh from the stack, not from an event: an answered call
        // stays ringing until its ACK arrives, so "confirmed" here is this
        // end's word that the caller acknowledged the 200 OK.
        if let state = try? call.state {
            print("state \(String(call.handle, radix: 16)): \(state)")
        }
        try? call.hangup()
    } else {
        captureStats(call.media)
    }
    call.close()

    print("ended \(String(call.handle, radix: 16)): packets_sent=\(sent) packets_received=\(received)")
}

let registrarAddress = environmentValue("SIPRAL_REGISTRAR_ADDRESS") ?? "127.0.0.1:5060"
let bindHost = routeTo(registrarAddress)
let stack = try SipralStack(bindHost: bindHost)
let account = try stack.addAccount(
    aor: environmentValue("SIPRAL_AOR") ?? "sip:agent@example.invalid",
    registrarAddress: registrarAddress,
    registrar: environmentValue("SIPRAL_REGISTRAR"),
    authUser: environmentValue("SIPRAL_AUTH_USER"),
    authPassword: environmentValue("SIPRAL_AUTH_PASSWORD")
)
if environmentValue("SIPRAL_REGISTRAR") != nil {
    try account.register()
}
print("listening on \(stack.bindAddress)")

await withTaskGroup(of: Void.self) { group in
    for await event in stack.events {
        if event.kind == .incomingCall {
            guard let call = try? stack.answerCall(event, mediaHost: bindHost) else { continue }
            group.addTask { await runCall(call) }
        }
    }
}
