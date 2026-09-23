// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Text;
using System.Threading;
using Sipral.Interop;

namespace Sipral;

/// <summary>
/// Turns a <c>sipral_status_t</c> into <see cref="SipralException"/> —
/// the exception type itself is already printed by <c>tools/abi-gen</c>
/// into <c>SipralAbi.cs</c> (<c>SipralException : Exception</c>, with a
/// <see cref="SipralException.Status"/> the raw code), but the generator
/// stops at the type: it builds no message beyond whatever string its
/// own caller passes it. This is that caller — the .NET counterpart of
/// <c>bindings/python/sipral/errors.py</c> — reading the calling
/// thread's last-error string (<c>sipral_last_error_message</c>) the
/// same ask-then-fetch way, and retrying an ordinary
/// <see cref="SipralStatus.Busy"/> the same half-second the Python layer
/// does, for the same reason: <see cref="SipralStack"/> keeps one thread
/// polling continuously, so every other entry point an application calls
/// from its own thread is liable to collide with it for the length of
/// one poll.
/// </summary>
internal static class SipralErrors
{
    /// <summary>The name the header gives a status, e.g.
    /// "SIPRAL_STATUS_BUSY". Never fails: an unrecognised number still
    /// comes back readable.</summary>
    internal static string StatusName(SipralStatus status)
    {
        NativeLibraryLoader.EnsureRegistered();
        var ptr = NativeMethods.sipral_status_name((int)status);
        return ptr == IntPtr.Zero ? status.ToString() : System.Runtime.InteropServices.Marshal.PtrToStringUTF8(ptr) ?? status.ToString();
    }

    /// <summary>The thread-local last-error string, ask-then-fetch.</summary>
    private static string LastErrorMessage()
    {
        NativeLibraryLoader.EnsureRegistered();
        nuint capacity = 256;
        var buffer = new sbyte[capacity];
        var status = NativeMethods.sipral_last_error_message(buffer, capacity, out var len);
        if (status == SipralStatus.BufferTooSmall)
        {
            capacity = len;
            buffer = new sbyte[capacity];
            status = NativeMethods.sipral_last_error_message(buffer, capacity, out len);
        }
        if (status != SipralStatus.Ok)
        {
            return string.Empty;
        }
        var bytes = new byte[(int)len];
        Buffer.BlockCopy(buffer, 0, bytes, 0, (int)len);
        return Encoding.UTF8.GetString(bytes);
    }

    /// <summary>Raises <see cref="SipralException"/> unless
    /// <paramref name="status"/> is <see cref="SipralStatus.Ok"/>.
    /// Returns the status so a call site that also wants to branch on
    /// <see cref="SipralStatus.Busy"/> without an exception can do so
    /// directly.</summary>
    internal static SipralStatus Check(SipralStatus status, string where)
    {
        if (status != SipralStatus.Ok)
        {
            var statusName = StatusName(status);
            var detail = LastErrorMessage();
            var message = string.IsNullOrEmpty(detail)
                ? $"{where}: {statusName}"
                : $"{where}: {statusName}: {detail}";
            throw new SipralException(status, message);
        }
        return status;
    }

    /// <summary>Calls an entry point, waiting out an ordinary
    /// <see cref="SipralStatus.Busy"/> for up to half a second before
    /// letting it through to <see cref="Check"/> as whatever it still
    /// is. A signalling entry point's <c>now_ms</c> more than the ABI's
    /// clock slack behind this stack's last reading
    /// (<c>docs/08-ffi.md</c>, "Signalling makes a smaller version of the
    /// same allowance") gets the same retry: this layer always reads
    /// <c>now_ms</c> fresh on the calling thread right before the entry
    /// point runs, so what beat it there is the OS scheduler, not a stale
    /// value, and a retry reads a later one the stack's high-water mark
    /// can only have moved forward from, never a value it would refuse
    /// for the same reason twice in a row.</summary>
    internal static void Call(Func<SipralStatus> entryPoint, string where)
    {
        var deadline = Environment.TickCount64 + 500;
        var status = entryPoint();
        while (Environment.TickCount64 < deadline && (status == SipralStatus.Busy || IsClockStraggler(status)))
        {
            Thread.Sleep(1);
            status = entryPoint();
        }
        Check(status, where);
    }

    /// <summary>Whether <paramref name="status"/> is
    /// <see cref="SipralStatus.InvalidArgument"/> for exactly the reason
    /// <c>StackState::checked_instant</c> gives it — a <c>now_ms</c> that
    /// fell behind this stack's high-water mark by more than the slack —
    /// rather than any other bad argument, which this layer never retries
    /// since a fresh call would fail it the same way again. Reads the
    /// thread-local last-error message <see cref="Call"/> was about to
    /// read anyway on the way to raising it, so peeking here costs
    /// nothing a failing call was not already going to pay.</summary>
    private static bool IsClockStraggler(SipralStatus status) =>
        status == SipralStatus.InvalidArgument &&
        LastErrorMessage() is { } message &&
        message.StartsWith("now_ms is ", StringComparison.Ordinal) &&
        message.Contains("ms behind this stack's last reading", StringComparison.Ordinal);
}
