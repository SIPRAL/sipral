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

/// Everything the library does, with the C conventions read off it.
public enum Sipral {
    /// The handle that names nothing.
    public static let handleNone: SipralHandle = 0

    /// The bit a hardware customer is told to check for.
    public static let featureOpus: UInt32 = 64

    /// The longest message that crosses.
    public static let messageBytes: Int = 65535

    /// The calling thread's last error, or an empty string when it
    /// has none. Read the way C reads it: ask for the length, then
    /// for the bytes.
    public static func lastErrorMessage() -> String {
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

    /// Turn a status into a thrown error, and nothing into nothing.
    static func check(_ status: sipral_status_t) throws {
        guard status != SIPRAL_STATUS_OK else { return }
        throw SipralError(
            status: SipralStatus(rawValue: status) ?? .panic,
            message: lastErrorMessage()
        )
    }

    /// The name of one SipralStatus, for a log line.
    public static func statusName(code: Int32) -> String? {
        guard let text = sipral_status_name(code) else { return nil }
        return String(cString: text)
    }

    /// Make one.
    public static func stackCreate(config: sipral_stack_config_t) throws -> SipralHandle {
        var config = config
        var stack = SipralHandle()
        let status = sipral_stack_create(&config, &stack)
        try check(status)
        return stack
    }

    /// Read sipral_counters_t off it.
    public static func stackCounters(stack: SipralHandle) throws -> sipral_counters_t {
        var counters = sipral_counters_t.sized()
        let status = sipral_stack_counters(stack, &counters)
        try check(status)
        return counters
    }

    /// Hand it bytes to send.
    public static func stackSend(stack: SipralHandle, message: [UInt8]) throws {
        let status =
            message.withUnsafeBufferPointer { p1 in
                sipral_stack_send(stack, p1.baseAddress, p1.count)
            }
        try check(status)
    }

    /// Hand it text, which crosses as UTF-8 and not as a String.
    public static func stackDescribe(stack: SipralHandle, note: String) throws {
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
        var count = Int()
        let status =
            outCodecs.withUnsafeMutableBufferPointer { p1 in
                sipral_stack_codec_order(stack, p1.baseAddress, p1.count, &count)
            }
        try check(status)
        return count
    }

    /// Fill a buffer of samples the caller brings.
    public static func callPlayback(stack: SipralHandle, samples: inout [Int16]) throws -> Int {
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
        let status =
            samples.withUnsafeBufferPointer { p1 in
                sipral_call_capture(stack, p1.baseAddress, p1.count, &packet)
            }
        try check(status)
    }

    /// Hand it a datagram that arrived, in a buffer it may rewrite in
    /// place, and hear what became of it.
    public static func callMediaReceive(stack: SipralHandle, data: inout [UInt8]) throws -> UInt32 {
        var arrival = UInt32()
        let status =
            data.withUnsafeMutableBufferPointer { p1 in
                sipral_call_media_receive(stack, p1.baseAddress, p1.count, &arrival)
            }
        try check(status)
        return arrival
    }

    /// Take it apart.
    public static func stackDestroy(stack: SipralHandle) throws {
        let status = sipral_stack_destroy(stack)
        try check(status)
    }

}
