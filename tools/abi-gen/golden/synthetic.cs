// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Printed from the declarations in crates/sipral-ffi by tools/abi-gen.
// Do not edit: `cargo run -p sipral-abi-gen` writes it again, and
// `scripts/check.sh` fails when what is committed is not what came out.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Sipral;

/// <summary>
/// What a call across the boundary answered.
/// Numbers already spent on features this build does not have:
/// - 9: video
/// </summary>
public enum SipralStatus : int
{
    /// <summary>
    /// It worked.
    /// </summary>
    Ok = 0,
    /// <summary>
    /// Something handed in was not usable.
    /// </summary>
    InvalidArgument = 1,
    /// <summary>
    /// A panic was caught before it reached C.
    /// </summary>
    Panic = 2,
    /// <summary>
    /// A word three of the four languages will not take plain.
    /// </summary>
    Default = 3,
}

/// <summary>
/// On or off, where C has no bool worth relying on.
/// </summary>
public enum SipralToggle : uint
{
    Off = 0,
    On = 1,
}

/// <summary>
/// What the library calls when something happens.
///
/// Hand it over as a function pointer: keep the delegate alive for as
/// long as the stack is, and pass Marshal.GetFunctionPointerForDelegate.
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void SipralEventCallback(IntPtr @event, IntPtr userData);

/// <summary>
/// What a stack has done since it was made.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralCounters
{
    public nuint Size;
    /// <summary>
    /// How many went out.
    /// </summary>
    public ulong RequestsSent;
    /// <summary>
    /// The fraction lost, which crosses JNI as its own bits.
    /// </summary>
    public float Loss;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralCounters Sized()
    {
        var value = default(SipralCounters);
        value.Size = (nuint)Marshal.SizeOf<SipralCounters>();
        return value;
    }
}

/// <summary>
/// One header field: a name and a value.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralHeader
{
    public IntPtr Name;
    public nuint NameLen;
    public IntPtr Value;
    public nuint ValueLen;
}

/// <summary>
/// What a stack is made with.
///
/// Holds buffers of the caller's and the library only reads it, so it
/// crosses behind a `const` pointer as a struct going in.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralStackConfig
{
    public nuint Size;
    /// <summary>
    /// Called for every event, from inside the poll.
    /// </summary>
    public IntPtr EventCallback;
    /// <summary>
    /// Handed back to the callback untouched.
    /// </summary>
    public IntPtr EventUserData;
    /// <summary>
    /// Where to listen, as UTF-8.
    /// </summary>
    public IntPtr BindAddress;
    public nuint BindAddressLen;
    public SipralToggle Echo;
    /// <summary>
    /// Header fields to send, `headers_len` of them.
    /// </summary>
    public IntPtr Headers;
    public nuint HeadersLen;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralStackConfig Sized()
    {
        var value = default(SipralStackConfig);
        value.Size = (nuint)Marshal.SizeOf<SipralStackConfig>();
        return value;
    }
}

/// <summary>
/// One datagram, in room the caller brought.
///
/// Holds writable buffers of the caller's, so it crosses behind a
/// mutable pointer as a struct going both ways.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralMediaPacket
{
    public nuint Size;
    /// <summary>
    /// Where to write the datagram.
    /// </summary>
    public IntPtr Data;
    public nuint Capacity;
    public nuint Len;
    /// <summary>
    /// Where to write the address it goes to, as UTF-8.
    /// </summary>
    public IntPtr Destination;
    public nuint DestinationCapacity;
    public nuint DestinationLen;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralMediaPacket Sized()
    {
        var value = default(SipralMediaPacket);
        value.Size = (nuint)Marshal.SizeOf<SipralMediaPacket>();
        return value;
    }
}

/// <summary>
/// What a registration event says.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralRegistrationEvent
{
    /// <summary>
    /// Where it got to.
    /// </summary>
    public uint State;
    public uint StatusCode;
}

/// <summary>
/// What a media event says.
///
/// Lifetime
///
/// Everything a pointer here names is the library's and lives until
/// the callback returns.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralMediaEvent
{
    public uint Codec;
    /// <summary>
    /// Why, as UTF-8, or null.
    /// </summary>
    public IntPtr Reason;
    public nuint ReasonLen;
    /// <summary>
    /// What the stream has done, or null when there is none.
    /// </summary>
    public IntPtr Statistics;
}

/// <summary>
/// The one arm SipralEvent.Kind names, and no other.
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public struct SipralEventPayload
{
    /// <summary>
    /// Read when the kind is a registration one.
    /// </summary>
    [FieldOffset(0)]
    public SipralRegistrationEvent Registration;
    /// <summary>
    /// Read when the kind is a media one.
    /// </summary>
    [FieldOffset(0)]
    public SipralMediaEvent Media;
}

/// <summary>
/// One thing that happened, as the callback is handed it.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralEvent
{
    public nuint Size;
    /// <summary>
    /// Which stack it came from.
    /// </summary>
    public ulong Stack;
    /// <summary>
    /// Which of them, from SipralStatus.
    /// </summary>
    public uint Kind;
    /// <summary>
    /// The message behind it, or null. It is the library's, and
    /// it lives as long as SipralStatus.Ok is being reported
    /// -- see sipral_stack_create for who owns what.
    /// </summary>
    public IntPtr Message;
    public nuint MessageLen;
    /// <summary>
    /// The arm the kind names.
    /// </summary>
    public SipralEventPayload Payload;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralEvent Sized()
    {
        var value = default(SipralEvent);
        value.Size = (nuint)Marshal.SizeOf<SipralEvent>();
        return value;
    }
}

/// <summary>
/// A list of SipralHeader as the array the library reads, for the length of
/// one call. Every piece of text in every element is copied into one
/// buffer, the records point into it, and both are pinned until Dispose,
/// which the wrapper that made this runs as the call returns or throws.
/// The count the library is given is the list's own, and an empty piece
/// of text crosses as a null pointer with a length of zero.
/// </summary>
internal sealed class SipralHeaderArray : IDisposable
{
    private GCHandle bytesPinned;
    private GCHandle recordsPinned;

    internal SipralHeaderArray((string Name, string Value)[]? list)
    {
        if (list is null || list.Length == 0)
        {
            return;
        }

        var parts = new byte[checked(list.Length * 2)][];
        for (var index = 0; index < list.Length; index++)
        {
            parts[index * 2 + 0] = Encoding.UTF8.GetBytes(list[index].Name);
            parts[index * 2 + 1] = Encoding.UTF8.GetBytes(list[index].Value);
        }

        var total = 0;
        foreach (var part in parts)
        {
            total = checked(total + part.Length);
        }

        var bytes = new byte[total];
        var records = new SipralHeader[list.Length];
        var at = 0;
        for (var index = 0; index < list.Length; index++)
        {
            Buffer.BlockCopy(parts[index * 2 + 0], 0, bytes, at, parts[index * 2 + 0].Length);
            records[index].NameLen = (nuint)parts[index * 2 + 0].Length;
            at += parts[index * 2 + 0].Length;
            Buffer.BlockCopy(parts[index * 2 + 1], 0, bytes, at, parts[index * 2 + 1].Length);
            records[index].ValueLen = (nuint)parts[index * 2 + 1].Length;
            at += parts[index * 2 + 1].Length;
        }

        bytesPinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            recordsPinned = GCHandle.Alloc(records, GCHandleType.Pinned);
        }
        catch
        {
            bytesPinned.Free();
            throw;
        }

        var start = bytesPinned.AddrOfPinnedObject();
        at = 0;
        for (var index = 0; index < records.Length; index++)
        {
            records[index].Name = records[index].NameLen == 0 ? IntPtr.Zero : start + at;
            at += (int)records[index].NameLen;
            records[index].Value = records[index].ValueLen == 0 ? IntPtr.Zero : start + at;
            at += (int)records[index].ValueLen;
        }

        Address = recordsPinned.AddrOfPinnedObject();
        Count = (nuint)records.Length;
    }

    /// <summary>Where the first record is, or zero for no list.</summary>
    internal IntPtr Address { get; }

    /// <summary>How many records there are, which is how long the list
    /// is.</summary>
    internal nuint Count { get; }

    /// <summary>Let go of the buffer and the records.</summary>
    public void Dispose()
    {
        if (recordsPinned.IsAllocated)
        {
            recordsPinned.Free();
        }

        if (bytesPinned.IsAllocated)
        {
            bytesPinned.Free();
        }
    }
}

/// <summary>What a call across the boundary answered, when it did not
/// answer Ok. The message is the calling thread's last error, read
/// before anything else on this thread could replace it.</summary>
public sealed class SipralException : Exception
{
    internal SipralException(SipralStatus status, string message)
        : base(message.Length == 0 ? status.ToString() : $"{status}: {message}")
    {
        Status = status;
    }

    /// <summary>The code C would have switched on.</summary>
    public SipralStatus Status { get; }
}

/// <summary>
/// The ABI as the runtime calls it. Every pointer is written as an
/// array or as in, ref or out, so nothing here needs an unsafe block
/// and the runtime pins what it passes. An array of records is the
/// one IntPtr: the wrapper pins the records and the text they point
/// at itself, for the length of the call.
/// </summary>
internal static class NativeMethods
{
    /// <summary>What the native library is called, before the
    /// platform puts its own prefix and suffix on it.</summary>
    internal const string Library = "sipral";

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_abi_check(uint major, uint minor);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_last_error_message(sbyte[] buffer, nuint capacity, out nuint needed);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern IntPtr sipral_status_name(int code);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_create(in SipralStackConfig config, out ulong stack);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_counters(ulong stack, ref SipralCounters outCounters);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_send(ulong stack, byte[] message, nuint messageLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_label(ulong stack, IntPtr headers, nuint headersLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_describe(ulong stack, sbyte[] note, nuint noteLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_name(ulong stack, sbyte[] name, nuint capacity, out nuint len);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_codec_order(ulong stack, uint[] outCodecs, nuint capacity, out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_playback(ulong stack, short[] samples, nuint capacity, out nuint written);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_capture(ulong stack, short[] samples, nuint sampleCount, ref SipralMediaPacket packet);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_media_receive(ulong stack, byte[] data, nuint len, out uint arrival);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_destroy(ulong stack);

}

/// <summary>Everything the library does, with the C conventions read
/// off it.</summary>
public static class Sipral
{
    /// <summary>
    /// Fails fast, before any of the rest of this class can be used,
    /// if the native library loaded under this assembly cannot serve
    /// the ABI it was generated against. A static constructor is
    /// guaranteed by the runtime to run before this type's first use,
    /// which is the closest a managed assembly has to "at load"
    /// without asking every caller to remember it themselves.
    ///
    /// The runtime wraps what a static constructor throws, so a
    /// mismatch does not arrive as a SipralException: the first use
    /// of this class throws TypeInitializationException, whose
    /// InnerException is the SipralException naming both versions,
    /// and every later use throws that TypeInitializationException
    /// again without running the check a second time.
    /// </summary>
    static Sipral()
    {
        AbiCheck(AbiVersionMajor, AbiVersionMinor);
    }

    /// <summary>
    /// The handle that names nothing.
    /// </summary>
    public const ulong HandleNone = 0;

    /// <summary>
    /// The bit a hardware customer is told to check for.
    /// </summary>
    public const uint FeatureOpus = 64;

    /// <summary>
    /// The longest message that crosses.
    /// </summary>
    public static readonly nuint MessageBytes = 65535;

    /// <summary>
    /// Nothing built against another major works against this one.
    /// </summary>
    public const uint AbiVersionMajor = 0;

    /// <summary>
    /// Raised by anything the header gains.
    /// </summary>
    public const uint AbiVersionMinor = 8;

    /// <summary>The calling thread's last error, or an empty string
    /// when it has none. Read the way C reads it: ask for the
    /// length, then for the bytes.</summary>
    public static string LastErrorMessage()
    {
        NativeMethods.sipral_last_error_message(Array.Empty<sbyte>(), 0, out var needed);
        if (needed <= 1)
        {
            return string.Empty;
        }

        var buffer = new sbyte[(int)needed];
        var status = NativeMethods.sipral_last_error_message(buffer, needed, out _);
        if (status != SipralStatus.Ok)
        {
            return string.Empty;
        }

        var bytes = new byte[buffer.Length];
        Buffer.BlockCopy(buffer, 0, bytes, 0, buffer.Length);
        var end = Array.IndexOf(bytes, (byte)0);
        return Encoding.UTF8.GetString(bytes, 0, end < 0 ? bytes.Length : end);
    }

    /// <summary>Turn a status into an exception, and nothing into
    /// nothing.</summary>
    internal static void Check(SipralStatus status)
    {
        if (status == SipralStatus.Ok)
        {
            return;
        }

        throw new SipralException(status, LastErrorMessage());
    }

    /// <summary>
    /// Whether this library can serve a binding generated against `major`.`minor`.
    /// </summary>
    public static void AbiCheck(uint major, uint minor)
    {
        Check(NativeMethods.sipral_abi_check(major, minor));
    }

    /// <summary>
    /// The name of one SipralStatus, for a log line.
    /// </summary>
    public static string? StatusName(int code) =>
        Marshal.PtrToStringUTF8(NativeMethods.sipral_status_name(code));

    /// <summary>
    /// Make one.
    /// </summary>
    public static ulong StackCreate(in SipralStackConfig config, (string Name, string Value)[]? configHeaders)
    {
        using var configHeadersArray = new SipralHeaderArray(configHeaders);
        var configValue = config;
        configValue.Headers = configHeadersArray.Address;
        configValue.HeadersLen = configHeadersArray.Count;
        Check(NativeMethods.sipral_stack_create(in configValue, out var stack));
        return stack;
    }

    /// <summary>
    /// Read SipralCounters off it.
    /// </summary>
    public static SipralCounters StackCounters(ulong stack)
    {
        var counters = SipralCounters.Sized();
        Check(NativeMethods.sipral_stack_counters(stack, ref counters));
        return counters;
    }

    /// <summary>
    /// Hand it bytes to send.
    /// </summary>
    public static void StackSend(ulong stack, byte[] message)
    {
        Check(NativeMethods.sipral_stack_send(stack, message, (nuint)message.Length));
    }

    /// <summary>
    /// Hand it header fields, an array of them with its length beside it.
    /// </summary>
    public static void StackLabel(ulong stack, (string Name, string Value)[] headers)
    {
        using var headersArray = new SipralHeaderArray(headers);
        Check(NativeMethods.sipral_stack_label(stack, headersArray.Address, headersArray.Count));
    }

    /// <summary>
    /// Hand it text, which crosses as UTF-8 and not as a String.
    /// </summary>
    public static void StackDescribe(ulong stack, string note)
    {
        var noteBytes = Encoding.UTF8.GetBytes(note);
        var noteSigned = new sbyte[noteBytes.Length];
        Buffer.BlockCopy(noteBytes, 0, noteSigned, 0, noteBytes.Length);
        Check(NativeMethods.sipral_stack_describe(stack, noteSigned, (nuint)noteSigned.Length));
    }

    /// <summary>
    /// Fill a buffer the caller brings.
    /// </summary>
    public static nuint StackName(ulong stack, sbyte[] name)
    {
        Check(NativeMethods.sipral_stack_name(stack, name, (nuint)name.Length, out var len));
        return len;
    }

    /// <summary>
    /// Fill a buffer of numbers the caller brings.
    /// </summary>
    public static nuint StackCodecOrder(ulong stack, uint[] outCodecs)
    {
        Check(NativeMethods.sipral_stack_codec_order(stack, outCodecs, (nuint)outCodecs.Length, out var count));
        return count;
    }

    /// <summary>
    /// Fill a buffer of samples the caller brings.
    /// </summary>
    public static nuint CallPlayback(ulong stack, short[] samples)
    {
        Check(NativeMethods.sipral_call_playback(stack, samples, (nuint)samples.Length, out var written));
        return written;
    }

    /// <summary>
    /// Hand it samples, and get one datagram back in the struct.
    /// </summary>
    public static void CallCapture(ulong stack, short[] samples, ref SipralMediaPacket packet)
    {
        Check(NativeMethods.sipral_call_capture(stack, samples, (nuint)samples.Length, ref packet));
    }

    /// <summary>
    /// Hand it a datagram that arrived, in a buffer it may rewrite in
    /// place, and hear what became of it.
    /// </summary>
    public static uint CallMediaReceive(ulong stack, byte[] data)
    {
        Check(NativeMethods.sipral_call_media_receive(stack, data, (nuint)data.Length, out var arrival));
        return arrival;
    }

    /// <summary>
    /// Take it apart.
    /// </summary>
    public static void StackDestroy(ulong stack)
    {
        Check(NativeMethods.sipral_stack_destroy(stack));
    }

}
