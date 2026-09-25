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
import Dispatch
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
// Taken before the REGISTER goes out, so that nothing it raises -- the
// first INVITE included, however soon it follows -- lands before a reader.
let stackEvents = stack.events()
if environmentValue("SIPRAL_REGISTRAR") != nil {
    try account.register()
}
print("listening on \(stack.bindAddress)")

await withTaskGroup(of: Void.self) { group in
    for await event in stackEvents {
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
