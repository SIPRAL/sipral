// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Sipral.Interop;
using static Sipral.Interop.NativeText;

namespace Sipral;

/// <summary>
/// One call handle, its events and, once media starts, its audio — the
/// .NET counterpart of <c>bindings/python/sipral/call.py</c>'s <c>Call</c>.
///
/// Built by <see cref="SipralStack.PlaceCall"/> for one this stack
/// placed, and by <see cref="SipralStack.AnswerCall"/> for one that came
/// in; either way it is registered with its stack before the caller ever
/// sees it, so <see cref="Deliver"/> always has somewhere to put an event
/// that names this call.
/// </summary>
public sealed class Call : IDisposable
{
    private readonly SipralStack _stack;
    private readonly CallSafeHandle _handle = new();
    private readonly Socket _mediaSocket;
    private readonly string _mediaAddress;
    private readonly Channel<SipralEventArgs> _events =
        Channel.CreateUnbounded<SipralEventArgs>(new UnboundedChannelOptions { SingleWriter = true });
    private readonly Channel<char> _dtmf =
        Channel.CreateUnbounded<char>(new UnboundedChannelOptions { SingleWriter = true });

    private int _disposed;

    internal ulong Handle => _handle.Value;

    /// <summary>Set once <see cref="SipralEventKind.MediaStarted"/>
    /// arrives; <see langword="null"/> before that.</summary>
    public CallMedia? Media { get; private set; }

    /// <summary>Set once <see cref="SipralEventKind.CallEnded"/> has been
    /// delivered.</summary>
    public bool Ended { get; private set; }

    /// <summary>Every event this call's handle names, decoded whole, in
    /// order.</summary>
    public IAsyncEnumerable<SipralEventArgs> Events => _events.Reader.ReadAllAsync();

    /// <summary>Just the digits: <see cref="SipralEventKind.DigitReceived"/>'s
    /// own character, so a voice agent that only cares about DTMF does
    /// not have to filter <see cref="Events"/> itself.</summary>
    public IAsyncEnumerable<char> Dtmf => _dtmf.Reader.ReadAllAsync();

    /// <summary>Fired synchronously, on the stack's poll thread, for
    /// every event this call's handle names — see
    /// <see cref="SipralStack.EventReceived"/> for the same shape and the
    /// same reason.</summary>
    public event EventHandler<SipralEventArgs>? EventReceived;

    internal Call(SipralStack stack, ulong handle, Socket mediaSocket, string mediaAddress)
    {
        _stack = stack;
        _handle.SetValue(handle);
        _mediaSocket = mediaSocket;
        _mediaAddress = mediaAddress;
    }

    /// <summary>Called by <see cref="SipralStack"/> on its own poll
    /// thread. Every side effect below — minting <see cref="Media"/>,
    /// marking <see cref="Ended"/> — happens before <paramref
    /// name="args"/> is handed to any reader, the same ordering
    /// <c>bindings/python/sipral/call.py</c>'s own <c>deliver</c>
    /// keeps and for the same reason: a consumer of <see cref="Events"/>
    /// that wakes because this call posted to <see cref="Media"/> must
    /// already see it set.</summary>
    internal void Deliver(SipralEventArgs args)
    {
        if (args.Kind == SipralEventKind.MediaStarted && Media is null)
        {
            // From here the socket is `CallMedia`'s own to read
            // (`docs/08-ffi.md`, "From the media handle on, the socket's
            // datagrams go to sipral_media_receive and nowhere else") —
            // `SipralStack` stops treating it as a pre-media-handle
            // STUN/TURN socket first, so the two never race to read the
            // same socket.
            _stack.ReleaseStunSocket(_mediaAddress);
            Media = new CallMedia(_stack, Handle, _mediaSocket);
        }
        if (args.Kind == SipralEventKind.CallEnded)
        {
            Ended = true;
        }

        // Same guard as `SipralStack.EventReceived`, and for the same
        // reason: this runs on the stack's own poll thread, one frame
        // above the native call that thread is inside, so a handler's
        // exception must stop here rather than unwind back across it and
        // take the whole process down with it.
        try
        {
            EventReceived?.Invoke(this, args);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.TraceError($"Sipral: Call.EventReceived handler threw: {ex}");
        }
        _events.Writer.TryWrite(args);

        if (args.Kind == SipralEventKind.DigitReceived && args.Media?.Digit is char digit)
        {
            _dtmf.Writer.TryWrite(digit);
        }
    }

    // -- state --------------------------------------------------------

    /// <summary><c>sipral_call_state</c>, read fresh — not cached from
    /// the last event, which a status query between events would
    /// otherwise miss.</summary>
    public SipralCallState State
    {
        get
        {
            uint state = 0;
            SipralErrors.Call(() => NativeMethods.sipral_call_state(_stack.Handle, Handle, out state), "sipral_call_state");
            return (SipralCallState)state;
        }
    }

    // -- actions --------------------------------------------------------

    /// <summary><c>sipral_call_answer_media</c>: accept, with this stack
    /// running the audio through the media socket this call already
    /// opened.</summary>
    public void Answer()
    {
        var address = ToSBytes(_mediaAddress);
        SipralErrors.Call(() => NativeMethods.sipral_call_answer_media(_stack.Handle, Handle, address, (nuint)address.Length, _stack.NowMs), "sipral_call_answer_media");
    }

    /// <summary><c>sipral_call_reject</c>: 486 Busy Here, 603 Decline, or
    /// whatever response code fits.</summary>
    public void Reject(uint code = 486)
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_reject(_stack.Handle, Handle, code, _stack.NowMs), "sipral_call_reject");
    }

    /// <summary><c>sipral_call_hangup</c>.</summary>
    public void Hangup()
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_hangup(_stack.Handle, Handle, _stack.NowMs), "sipral_call_hangup");
    }

    /// <summary><c>sipral_call_hold</c>.</summary>
    public void Hold()
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_hold(_stack.Handle, Handle, _stack.NowMs), "sipral_call_hold");
    }

    /// <summary><c>sipral_call_resume</c>.</summary>
    public void Resume()
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_resume(_stack.Handle, Handle, _stack.NowMs), "sipral_call_resume");
    }

    /// <summary><c>sipral_call_send_dtmf</c>.</summary>
    public void SendDtmf(string digits, SipralDtmf via = SipralDtmf.Rtp, uint durationMs = 100)
    {
        var encoded = ToSBytes(digits);
        SipralErrors.Call(() => NativeMethods.sipral_call_send_dtmf(_stack.Handle, Handle, encoded, (nuint)encoded.Length, (uint)via, durationMs, _stack.NowMs), "sipral_call_send_dtmf");
    }

    /// <summary>
    /// Waits for this call to reach <see cref="SipralCallState.Confirmed"/>
    /// or to end trying, whichever comes first — the ABI completes this
    /// asynchronously, through <see cref="SipralEventKind.CallConfirmed"/>
    /// and <see cref="SipralEventKind.CallEnded"/> on <see cref="Events"/>,
    /// so this is the <see cref="Task"/>-returning helper over it rather
    /// than a caller polling <see cref="State"/> in a loop.
    /// </summary>
    public async Task<bool> WaitForConfirmedAsync(CancellationToken cancellationToken = default)
    {
        await foreach (var args in Events.WithCancellation(cancellationToken))
        {
            if (args.Kind == SipralEventKind.CallConfirmed)
            {
                return true;
            }
            if (args.Kind == SipralEventKind.CallEnded)
            {
                return false;
            }
        }
        return false;
    }

    /// <summary>Waits until <see cref="Media"/> is set — the
    /// <see cref="SipralEventKind.MediaStarted"/> event has been
    /// delivered — or this call ends first.</summary>
    public async Task<CallMedia?> WaitForMediaAsync(CancellationToken cancellationToken = default)
    {
        if (Media is { } already)
        {
            return already;
        }
        await foreach (var args in Events.WithCancellation(cancellationToken))
        {
            if (Media is not null)
            {
                return Media;
            }
            if (args.Kind == SipralEventKind.CallEnded)
            {
                return null;
            }
        }
        return Media;
    }

    /// <summary>Hangs up if this call is still up, releases its media,
    /// forgets it. Idempotent, and safe to call from a
    /// <see langword="finally"/> regardless of how the call ended.</summary>
    public void Close()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        if (!Ended)
        {
            try
            {
                Hangup();
            }
            catch (SipralException)
            {
            }
        }
        if (Media is not null)
        {
            Media.Dispose();
        }
        else
        {
            // Never reached `SIPRAL_EVENT_KIND_MEDIA_STARTED`: refused,
            // failed before answer, or hung up while still ringing. A
            // socket `SipralStack.MapMediaSocket` named for it
            // (`nat: SipralNat.Stun`) is still the stack's to give back
            // (`sipral_stack_nat_unmap`) before the socket closes under it.
            _stack.ForgetMediaSocket(_mediaAddress);
            _mediaSocket.Dispose();
        }
        _stack.ForgetCall(Handle);
        _events.Writer.TryComplete();
        _dtmf.Writer.TryComplete();
        _handle.Dispose();
    }

    /// <summary>Same as <see cref="Close"/>.</summary>
    public void Dispose() => Close();
}
