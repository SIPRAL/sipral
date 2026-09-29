// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Printed from the declarations in crates/sipral-ffi by tools/abi-gen.
// Do not edit: `cargo run -p sipral-abi-gen` writes it again, and
// `scripts/check.sh` fails when what is committed is not what came out.

import CSipral

/// What names one thing the library holds.
public typealias SipralHandle = sipral_handle_t

/// What a call across the boundary answered.
///
/// Numbers already spent on features this build does not have:
/// - 9: video
public enum SipralStatus: Int32, Sendable {
    /// It worked.
    case ok = 0
    /// Something handed in was not usable.
    case invalidArgument = 1
    /// A panic was caught before it reached C.
    case panic = 2
    /// A word three of the four languages will not take plain.
    case `default` = 3
}

/// On or off, where C has no bool worth relying on.
public enum SipralToggle: UInt32, Sendable {
    case off = 0
    case on = 1
}

/// What a call across the boundary answered, when it did not answer
/// `ok`. The message is the calling thread's last error, read before
/// anything else on this thread could replace it.
public struct SipralError: Error, CustomStringConvertible, Sendable {
    /// The code C would have switched on.
    public let status: SipralStatus
    /// The sentence that goes with it.
    public let message: String

    public var description: String {
        message.isEmpty ? "\(status)" : "\(status): \(message)"
    }
}

public extension sipral_counters_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_stack_config_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_media_packet_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_event_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_screen_event_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_processor_event_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

/// One header field: a name and a value.
///
/// Built here and handed to C in a list. `withUnsafeArray` copies every
/// piece of text in every element into one buffer, points an array of
/// sipral_header_t into it and hands that array on for as long as one closure
/// runs, with the list's own count. An empty piece of text crosses as a
/// null pointer with a length of zero, and an empty list as a null
/// pointer with a count of zero.
public struct SipralHeader: Sendable {
    public var name: String
    public var value: String

    public init(name: String, value: String) {
        self.name = name
        self.value = value
    }

    /// A list of them as the array of sipral_header_t C reads, for as long as
    /// `body` runs and no longer: every pointer in it points into a buffer
    /// that is gone when `body` returns.
    static func withUnsafeArray<Answer>(_ list: [SipralHeader], _ body: (UnsafeBufferPointer<sipral_header_t>) throws -> Answer) rethrows -> Answer {
        var run: [CChar] = []
        var lengths: [Int] = []
        for element in list {
            let nameBytes = element.name.utf8.map { CChar(bitPattern: $0) }
            run.append(contentsOf: nameBytes)
            lengths.append(nameBytes.count)
            let valueBytes = element.value.utf8.map { CChar(bitPattern: $0) }
            run.append(contentsOf: valueBytes)
            lengths.append(valueBytes.count)
        }
        return try run.withUnsafeBufferPointer { bytes -> Answer in
            var array: [sipral_header_t] = []
            var at = 0
            var part = 0
            for _ in list {
                var record = sipral_header_t()
                record.name = lengths[part] == 0 ? nil : bytes.baseAddress.map { $0 + at }
                record.name_len = lengths[part]
                at += lengths[part]
                part += 1
                record.value = lengths[part] == 0 ? nil : bytes.baseAddress.map { $0 + at }
                record.value_len = lengths[part]
                at += lengths[part]
                part += 1
                array.append(record)
            }
            if array.isEmpty {
                return try body(UnsafeBufferPointer(start: nil, count: 0))
            }
            return try array.withUnsafeBufferPointer(body)
        }
    }
}

/// Everything the library does, with the C conventions read off it.
///
/// Swift gives a namespace `enum` like this one no load hook: there is
/// no module initializer and nothing else the runtime guarantees to run
/// before first use, the way a static constructor does for the .NET
/// binding or an `init` block does for the Kotlin one. What Swift does
/// guarantee is narrower, and it is enough: a static stored property's
/// initializer runs at most once, and finishes before the first read of
/// it returns, on whichever thread reaches it first — the same promise
/// `dispatch_once` made in Objective-C. `abiMismatch` below is one such
/// property, and every call in this `enum` reads it, through
/// `ensureAbi`, before it does anything else. So the check runs the
/// first time this module is asked to do anything at all, on whichever
/// thread makes that first call — not at import, which Swift gives no
/// hook for, but before that first call reaches C, which is the promise
/// this makes instead.
///
/// Skipping it is not something a caller can do: there is no call here
/// that reaches C without going through `ensureAbi` first. The `size`
/// every struct here carries settles how long a struct is, not what is
/// in it: a header and a library that disagree about the order or the
/// meaning of members can still agree about the length, and then every
/// size rule passes while the library reads a pointer out of whatever
/// was put in its place. No entry point can catch that on its own,
/// because whether a pointer is readable is the caller's promise, not
/// something the library can check. This is what finds the
/// disagreement before anything is read, and a mismatch is what it
/// throws — a SipralError, from whichever call the application happens
/// to make first, not a warning that is easy to miss.
public enum Sipral {
    /// The handle that names nothing.
    public static let handleNone: SipralHandle = 0

    /// The bit a hardware customer is told to check for.
    public static let featureOpus: UInt32 = 64

    /// The longest message that crosses.
    public static let messageBytes: Int = 65535

    /// How long a refused request waits before it is tried again.
    public static let retryEveryMs: UInt64 = 2000

    /// Nothing built against another major works against this one.
    public static let abiVersionMajor: UInt32 = 0

    /// Raised by anything the header gains.
    public static let abiVersionMinor: UInt32 = 8

    /// The calling thread's last error, or an empty string when it
    /// has none. Read the way C reads it: ask for the length, then
    /// for the bytes.
    ///
    /// Not behind `ensureAbi`. This is what a mismatch's own message
    /// is read with, while `abiMismatch` is still being computed, and
    /// going through the check to reach it would be this property
    /// reading itself before it has a value.
    static func rawLastErrorMessage() -> String {
        var needed = 0
        _ = sipral_last_error_message(nil, 0, &needed)
        guard needed > 1 else { return "" }
        var buffer = [CChar](repeating: 0, count: needed)
        let status = buffer.withUnsafeMutableBufferPointer {
            sipral_last_error_message($0.baseAddress, $0.count, nil)
        }
        guard status == SIPRAL_STATUS_OK else { return "" }
        return String(cString: buffer)
    }

    /// The calling thread's last error, or an empty string when it
    /// has none.
    public static func lastErrorMessage() throws -> String {
        try ensureAbi()
        return rawLastErrorMessage()
    }

    /// Whether the library this binding loaded can serve the ABI this
    /// file was printed against, checked once. A static stored
    /// property's initializer in Swift runs at most once and
    /// finishes before the first read of it returns, on whichever
    /// thread reaches it first, which is what makes this safe to
    /// read from every one of them without a lock of its own.
    static let abiMismatch: SipralError? = {
        let status = sipral_abi_check(abiVersionMajor, abiVersionMinor)
        guard status != SIPRAL_STATUS_OK else { return nil }
        return SipralError(
            status: SipralStatus(rawValue: status) ?? .panic,
            message: rawLastErrorMessage()
        )
    }()

    /// Throws what `abiMismatch` found, if it found one. Every call
    /// below reaches this before it reaches C, so a binding loaded
    /// over the wrong library fails here, in whichever call the
    /// application happens to make first, rather than in whichever
    /// one first happens to disagree about a struct's layout.
    static func ensureAbi() throws {
        if let mismatch = abiMismatch {
            throw mismatch
        }
    }

    /// Turn a status into a thrown error, and nothing into nothing.
    static func check(_ status: sipral_status_t) throws {
        guard status != SIPRAL_STATUS_OK else { return }
        throw SipralError(
            status: SipralStatus(rawValue: status) ?? .panic,
            message: rawLastErrorMessage()
        )
    }

    /// Whether this library can serve a binding generated against `major`.`minor`.
    public static func abiCheck(major: UInt32, minor: UInt32) throws {
        try ensureAbi()
        let status = sipral_abi_check(major, minor)
        try check(status)
    }

    /// The name of one SipralStatus, for a log line.
    public static func statusName(code: Int32) throws -> String? {
        try ensureAbi()
        guard let text = sipral_status_name(code) else { return nil }
        return String(cString: text)
    }

    /// Make one.
    public static func stackCreate(config: sipral_stack_config_t, configHeaders: [SipralHeader]) throws -> SipralHandle {
        try ensureAbi()
        var config = config
        var stack = SipralHandle()
        let status =
            SipralHeader.withUnsafeArray(configHeaders) { p0Headers -> sipral_status_t in
                config.headers = p0Headers.baseAddress
                config.headers_len = p0Headers.count
                return sipral_stack_create(&config, &stack)
            }
        try check(status)
        return stack
    }

    /// Read sipral_counters_t off it.
    public static func stackCounters(stack: SipralHandle) throws -> sipral_counters_t {
        try ensureAbi()
        var counters = sipral_counters_t.sized()
        let status = sipral_stack_counters(stack, &counters)
        try check(status)
        return counters
    }

    /// Hand it bytes to send.
    public static func stackSend(stack: SipralHandle, message: [UInt8]) throws {
        try ensureAbi()
        let status =
            message.withUnsafeBufferPointer { p1 in
                sipral_stack_send(stack, p1.baseAddress, p1.count)
            }
        try check(status)
    }

    /// Hand it header fields, an array of them with its length beside it.
    public static func stackLabel(stack: SipralHandle, headers: [SipralHeader]) throws {
        try ensureAbi()
        let status =
            SipralHeader.withUnsafeArray(headers) { p1 in
                sipral_stack_label(stack, p1.baseAddress, p1.count)
            }
        try check(status)
    }

    /// Hand it text, which crosses as UTF-8 and not as a String.
    public static func stackDescribe(stack: SipralHandle, note: String) throws {
        try ensureAbi()
        let status =
            Array(note.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    sipral_stack_describe(stack, p1.baseAddress, p1.count)
                }
            }
        try check(status)
    }

    /// Fill a buffer the caller brings.
    public static func stackName(stack: SipralHandle, name: inout [CChar]) throws -> Int {
        try ensureAbi()
        var len = Int()
        let status =
            name.withUnsafeMutableBufferPointer { p1 in
                sipral_stack_name(stack, p1.baseAddress, p1.count, &len)
            }
        try check(status)
        return len
    }

    /// Fill a buffer of numbers the caller brings.
    public static func stackCodecOrder(stack: SipralHandle, outCodecs: inout [UInt32]) throws -> Int {
        try ensureAbi()
        var count = Int()
        let status =
            outCodecs.withUnsafeMutableBufferPointer { p1 in
                sipral_stack_codec_order(stack, p1.baseAddress, p1.count, &count)
            }
        try check(status)
        return count
    }

    /// Fill a buffer of opaque bytes the caller brings.
    public static func stackFreeze(stack: SipralHandle, buffer: inout [UInt8]) throws -> Int {
        try ensureAbi()
        var len = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p1 in
                sipral_stack_freeze(stack, p1.baseAddress, p1.count, &len)
            }
        try check(status)
        return len
    }

    /// Fill a buffer of samples the caller brings.
    public static func callPlayback(stack: SipralHandle, samples: inout [Int16]) throws -> Int {
        try ensureAbi()
        var written = Int()
        let status =
            samples.withUnsafeMutableBufferPointer { p1 in
                sipral_call_playback(stack, p1.baseAddress, p1.count, &written)
            }
        try check(status)
        return written
    }

    /// Hand it samples, and get one datagram back in the struct.
    public static func callCapture(stack: SipralHandle, samples: [Int16], packet: inout sipral_media_packet_t) throws {
        try ensureAbi()
        let status =
            samples.withUnsafeBufferPointer { p1 in
                sipral_call_capture(stack, p1.baseAddress, p1.count, &packet)
            }
        try check(status)
    }

    /// Hand it one buffer of samples and fill another, in the same call,
    /// neither one named `capacity` — two buffers going in, one of them
    /// writable, which is not the same shape as one being filled.
    public static func callMix(stack: SipralHandle, mic: [Int16], local: inout [Int16]) throws {
        try ensureAbi()
        let status =
            mic.withUnsafeBufferPointer { p1 in
                local.withUnsafeMutableBufferPointer { p2 in
                    sipral_call_mix(stack, p1.baseAddress, p1.count, p2.baseAddress, p2.count)
                }
            }
        try check(status)
    }

    /// Hand it a datagram that arrived, in a buffer it may rewrite in
    /// place, and hear what became of it.
    public static func callMediaReceive(stack: SipralHandle, data: inout [UInt8]) throws -> UInt32 {
        try ensureAbi()
        var arrival = UInt32()
        let status =
            data.withUnsafeMutableBufferPointer { p1 in
                sipral_call_media_receive(stack, p1.baseAddress, p1.count, &arrival)
            }
        try check(status)
        return arrival
    }

    /// Install a policy on it, replace the one installed, or remove it.
    ///
    /// The callback and the pointer after it are one listener, the same
    /// pair a struct going in already means by them, and a null callback
    /// removes whatever was installed.
    public static func stackScreen(stack: SipralHandle, callback: sipral_screen_callback_t, userData: UnsafeMutableRawPointer) throws {
        try ensureAbi()
        let status = sipral_stack_screen(stack, callback, userData)
        try check(status)
    }

    /// Install a processor on it, replace the one installed, or remove it.
    ///
    /// The callback and the pointer after it are one listener, the same
    /// pair a struct going in already means by them, and a null callback
    /// removes whatever was installed.
    public static func stackProcess(stack: SipralHandle, callback: sipral_process_callback_t, userData: UnsafeMutableRawPointer) throws {
        try ensureAbi()
        let status = sipral_stack_process(stack, callback, userData)
        try check(status)
    }

    /// Take it apart.
    public static func stackDestroy(stack: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_stack_destroy(stack)
        try check(status)
    }

}
