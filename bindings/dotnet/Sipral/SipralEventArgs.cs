// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Sipral;

/// <summary>
/// One event, decoded whole out of the library's own <c>sipral_event_t</c>
/// while it was still live.
///
/// Named <c>SipralEventArgs</c> rather than <c>SipralEvent</c> — the
/// idiomatic name the raw C struct already has in
/// <c>Sipral.SipralEvent</c>, printed by <c>tools/abi-gen</c> and not
/// this layer's to rename — and shaped as .NET names an object an
/// <see langword="event"/> hands a listener, since that is exactly what
/// this is used as on <see cref="SipralStack.EventReceived"/> and
/// <see cref="Call.EventReceived"/> as well as read off
/// <see cref="SipralStack.Events"/>, the <c>IAsyncEnumerable</c> reader.
///
/// <see cref="Kind"/> is always the raw <c>sipral_event_kind_t</c> — never
/// refused for a value this build's enum has no member for, since a kind
/// spent by a later task must still come through a binding compiled
/// against an older header (<c>docs/08-ffi.md</c>, "A binding that meets
/// a kind it does not know must ignore that event rather than refuse
/// it"). <see cref="KindName"/> is <c>sipral_event_kind_name</c>'s own
/// answer, which the library keeps current even when this binding's enum
/// has not been regenerated.
/// </summary>
public sealed class SipralEventArgs : EventArgs
{
    /// <summary>What this event is — the raw <c>sipral_event_kind_t</c>.</summary>
    public SipralEventKind Kind { get; }
    /// <summary><c>sipral_event_kind_name</c>'s own answer for <see cref="Kind"/>.</summary>
    public string KindName { get; }
    /// <summary>The stack this event is about.</summary>
    public ulong Stack { get; }
    /// <summary>The account this event is about, or 0.</summary>
    public ulong Account { get; }
    /// <summary>The call this event is about, or 0.</summary>
    public ulong Call { get; }
    /// <summary>The SIP message behind it, whole and unparsed, when there is one.</summary>
    public byte[]? Message { get; }

    /// <summary>Set for <see cref="SipralEventKind.RegistrationChanged"/>.</summary>
    public SipralRegistrationEventInfo? Registration { get; }
    /// <summary>Set for every call-shaped kind.</summary>
    public SipralCallEventInfo? CallInfo { get; }
    /// <summary>Set for every media-shaped kind.</summary>
    public SipralMediaEventInfo? Media { get; }
    /// <summary>Set for the three transfer kinds.</summary>
    public SipralTransferEventInfo? Transfer { get; }
    /// <summary>Set for <see cref="SipralEventKind.ResolveNeeded"/>.</summary>
    public SipralResolveEventInfo? Resolve { get; }
    /// <summary>Set for <see cref="SipralEventKind.NatMapping"/>.</summary>
    public SipralNatEventInfo? Nat { get; }
    /// <summary>Set for <see cref="SipralEventKind.NatRelay"/>.</summary>
    public SipralNatRelayEventInfo? Relay { get; }

    private SipralEventArgs(
        SipralEventKind kind, string kindName, ulong stack, ulong account, ulong call, byte[]? message,
        SipralRegistrationEventInfo? registration, SipralCallEventInfo? callInfo,
        SipralMediaEventInfo? media, SipralTransferEventInfo? transfer, SipralResolveEventInfo? resolve,
        SipralNatEventInfo? nat, SipralNatRelayEventInfo? relay)
    {
        Kind = kind;
        KindName = kindName;
        Stack = stack;
        Account = account;
        Call = call;
        Message = message;
        Registration = registration;
        CallInfo = callInfo;
        Media = media;
        Transfer = transfer;
        Resolve = resolve;
        Nat = nat;
        Relay = relay;
    }

    private static readonly SipralEventKind[] CallKinds =
    {
        SipralEventKind.IncomingCall, SipralEventKind.CallProgress, SipralEventKind.CallForked,
        SipralEventKind.CallConfirmed, SipralEventKind.SessionChanged, SipralEventKind.SessionOffered,
        SipralEventKind.SessionChangeFailed, SipralEventKind.CallReplaced, SipralEventKind.CallEnded,
        SipralEventKind.DtmfSent,
    };

    private static readonly SipralEventKind[] MediaKinds =
    {
        SipralEventKind.MediaStatistics, SipralEventKind.MediaStalled, SipralEventKind.MediaStarted,
        SipralEventKind.MediaChanged, SipralEventKind.MediaResumed, SipralEventKind.MediaFailed,
        SipralEventKind.RecordingStopped, SipralEventKind.DigitReceived, SipralEventKind.MediaSecured,
        SipralEventKind.MediaPathChosen,
    };

    /// <summary>
    /// Copies one <c>sipral_event_t*</c> out into a standalone
    /// <see cref="SipralEventArgs"/>. Called from inside the unmanaged
    /// callback and nowhere else: <paramref name="raw"/> points at memory
    /// the callback's caller owns and every field this reads is read
    /// before this method returns, exactly as
    /// <c>bindings/python/sipral/events.py</c>'s own <c>decode</c> reads
    /// its <c>cffi</c> pointer.
    /// </summary>
    internal static SipralEventArgs Decode(IntPtr raw)
    {
        var evt = Marshal.PtrToStructure<global::Sipral.SipralEvent>(raw);
        var kind = evt.Kind;
        var kindName = PtrToUtf8(NativeMethods.sipral_event_kind_name((uint)kind)) ?? kind.ToString();
        var message = ReadBytes(evt.Message, evt.MessageLen);

        SipralRegistrationEventInfo? registration = null;
        SipralCallEventInfo? callInfo = null;
        SipralMediaEventInfo? media = null;
        SipralTransferEventInfo? transfer = null;
        SipralResolveEventInfo? resolve = null;
        SipralNatEventInfo? nat = null;
        SipralNatRelayEventInfo? relay = null;

        if (kind == SipralEventKind.RegistrationChanged)
        {
            var r = evt.Payload.Registration;
            registration = new SipralRegistrationEventInfo(
                (SipralRegistrationState)r.State, (SipralRegistrationFailure)r.Failure, r.StatusCode,
                r.ExpiresMs, r.RefreshInMs, r.RetryInMs);
        }
        else if (Array.IndexOf(CallKinds, kind) >= 0)
        {
            var c = evt.Payload.Call;
            callInfo = new SipralCallEventInfo(
                (SipralCallState)c.State, (SipralCallEndReason)c.EndReason, c.StatusCode, c.Other,
                c.HeldHere != 0, c.HeldThere != 0,
                ReadBytes(c.LocalSdp, c.LocalSdpLen), ReadBytes(c.RemoteSdp, c.RemoteSdpLen), c.RetryInMs,
                ReadUtf8(c.FromUri, c.FromUriLen), ReadUtf8(c.FromDisplay, c.FromDisplayLen),
                ReadUtf8(c.ToUri, c.ToUriLen), ReadUtf8(c.CallId, c.CallIdLen), c.Digit);
        }
        else if (Array.IndexOf(MediaKinds, kind) >= 0)
        {
            var m = evt.Payload.Media;
            media = new SipralMediaEventInfo(
                (SipralCodec)m.Codec, (SipralDirection)m.Direction, m.SilentForMs, m.RecordedMs,
                (SipralMediaFault)m.Fault, ReadUtf8(m.Reason, m.ReasonLen), ReadStatistics(m.Statistics),
                m.Digit == 0 ? null : (char)m.Digit, m.EventCode, m.HeldMs,
                (SipralSrtpSuite)m.Suite, (SipralDigitSource)m.Source);
        }
        else if (kind == SipralEventKind.ResolveNeeded)
        {
            var res = evt.Payload.Resolve;
            resolve = new SipralResolveEventInfo(res.Dialog, ReadUtf8(res.Host, res.HostLen), res.Port,
                (SipralTransport)res.Protocol);
        }
        else if (kind is SipralEventKind.TransferRequested or SipralEventKind.TransferProgress
                 or SipralEventKind.TransferDone)
        {
            var t = evt.Payload.Transfer;
            transfer = new SipralTransferEventInfo(t.StatusCode, t.Attended != 0, ReadUtf8(t.Target, t.TargetLen));
        }
        else if (kind == SipralEventKind.NatMapping)
        {
            var n = evt.Payload.Nat;
            nat = new SipralNatEventInfo((SipralNatMapping)n.Mapping, n.Signalling != 0, n.Transport,
                n.Accounts, ReadUtf8(n.Local, n.LocalLen), ReadUtf8(n.Mapped, n.MappedLen),
                ReadUtf8(n.Previous, n.PreviousLen));
        }
        else if (kind == SipralEventKind.NatRelay)
        {
            var r = evt.Payload.Relay;
            relay = new SipralNatRelayEventInfo((SipralNatRelay)r.Outcome, r.Code,
                ReadUtf8(r.Local, r.LocalLen), ReadUtf8(r.Relayed, r.RelayedLen),
                ReadUtf8(r.Mapped, r.MappedLen), ReadUtf8(r.Reason, r.ReasonLen));
        }

        return new SipralEventArgs(kind, kindName, evt.Stack, evt.Account, evt.Call, message,
            registration, callInfo, media, transfer, resolve, nat, relay);
    }

    private static SipralStreamStatistics? ReadStatistics(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
        {
            return null;
        }
        var s = Marshal.PtrToStructure<SipralStreamStats>(ptr);
        return new SipralStreamStatistics(
            (SipralCodec)s.Codec, s.HasRoundTrip != 0 ? s.RoundTripUs : null, s.PacketsSent, s.OctetsSent,
            s.PacketsReceived, s.PacketsLost, s.PacketsLate, s.PacketsOverflowed, s.PacketsDuplicated,
            s.PacketsReordered, s.DelayUs, s.TargetDelayUs, s.JitterUs, s.LossRate, s.Score,
            s.Suffering != 0, s.SilentForMs);
    }

    private static byte[]? ReadBytes(IntPtr ptr, nuint len)
    {
        if (ptr == IntPtr.Zero || len == 0)
        {
            return null;
        }
        var buffer = new byte[(int)len];
        Marshal.Copy(ptr, buffer, 0, (int)len);
        return buffer;
    }

    private static string? ReadUtf8(IntPtr ptr, nuint len)
    {
        var bytes = ReadBytes(ptr, len);
        return bytes is null ? null : Encoding.UTF8.GetString(bytes);
    }

    private static string? PtrToUtf8(IntPtr ptr)
    {
        return ptr == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(ptr);
    }
}
