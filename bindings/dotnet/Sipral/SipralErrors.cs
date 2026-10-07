// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Text;
using System.Threading;
using Sipral.Interop;

namespace Sipral;

/// <summary>
/// Turns a <c>sipral_status_t</c> into <see cref="SipralException"/> with
/// the thread's last-error message. <see cref="SipralStatus.Busy"/> is
/// retried for half a second: the poll thread holds the stack for one poll
/// at a time, so calls from other threads collide with it.
/// </summary>
internal static class SipralErrors
{
    // e.g. "SIPRAL_STATUS_BUSY"; an unknown number still reads.
    internal static string StatusName(SipralStatus status)
    {
        NativeLibraryLoader.EnsureRegistered();
        var ptr = NativeMethods.sipral_status_name((int)status);
        return ptr == IntPtr.Zero ? status.ToString() : System.Runtime.InteropServices.Marshal.PtrToStringUTF8(ptr) ?? status.ToString();
    }

    private static string LastErrorMessage()
    {
        NativeLibraryLoader.EnsureRegistered();
        nuint capacity = 256;
        var buffer = new sbyte[capacity];
        var status = NativeMethods.sipral_last_error_message(buffer, capacity, out var needed);
        if (status == SipralStatus.BufferTooSmall)
        {
            capacity = needed;
            buffer = new sbyte[capacity];
            status = NativeMethods.sipral_last_error_message(buffer, capacity, out needed);
        }
        if (status != SipralStatus.Ok || needed == 0)
        {
            return string.Empty;
        }
        // `needed` counts the trailing NUL
        var length = (int)needed - 1;
        var bytes = new byte[length];
        Buffer.BlockCopy(buffer, 0, bytes, 0, length);
        return Encoding.UTF8.GetString(bytes);
    }

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

    // Retries Busy for up to half a second. ClockBehind gets the same
    // retry: now_ms is read fresh just before the call, so another thread
    // beat us only by scheduling, and a fresh reading will pass.
    internal static void Call(Func<SipralStatus> entryPoint, string where)
    {
        var deadline = Environment.TickCount64 + 500;
        var status = entryPoint();
        while (Environment.TickCount64 < deadline && (status == SipralStatus.Busy || status == SipralStatus.ClockBehind))
        {
            Thread.Sleep(1);
            status = entryPoint();
        }
        Check(status, where);
    }
}
