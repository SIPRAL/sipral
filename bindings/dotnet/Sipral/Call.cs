// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Generic;
using System.Net;
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
    /// <summary>Replaced by <see cref="Readdress"/>; read from the audio
    /// engine's thread in device mode.</summary>
    private volatile Socket _mediaSocket;
    private volatile string _mediaAddress;
    private SipralSrtpSuite? _suite;
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
    /// and <see cref="SipralEventKind.InBandDigit"/>'s own character, so a
    /// voice agent that only cares about DTMF does not have to filter
    /// <see cref="Events"/> itself, nor care which way a key was
    /// sent.</summary>
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
            Media = new CallMedia(_stack, Handle, _mediaSocket, pumped: _stack.AudioMode == SipralAudio.Device);
        }
        if (args.Kind == SipralEventKind.MediaSecured && args.Media is { } secured)
        {
            _suite = secured.Suite;
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

        if (args.Kind is SipralEventKind.DigitReceived or SipralEventKind.InBandDigit
            && args.Media?.Digit is char digit)
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

    /// <summary><c>sipral_call_restart_ice</c>: offer the call again with
    /// new ICE credentials (RFC 8445 §9) and check every pair again once
    /// the far end answers, while the path it has carries the audio. The
    /// new path arrives as another
    /// <see cref="SipralEventKind.MediaPathChosen"/>.</summary>
    public void RestartIce()
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_restart_ice(_stack.Handle, Handle, _stack.NowMs), "sipral_call_restart_ice");
    }

    /// <summary>This call's media socket: where device mode's encoded packets
    /// leave from, and what <see cref="Readdress"/> replaces.</summary>
    internal Socket MediaSocket => _mediaSocket;

    /// <summary>This call's media socket as <c>host:port</c>: the address its
    /// audio was described at, and the name of its connection to a TURN
    /// server reached over TCP or TLS.</summary>
    public string MediaAddress => _mediaAddress;

    /// <summary>The SRTP transform a DTLS-SRTP handshake settled this call's
    /// media on, as the last <see cref="SipralEventKind.MediaSecured"/> said —
    /// from <see cref="SipralSrtpSuite.AesCm80"/> to RFC 7714's
    /// <see cref="SipralSrtpSuite.AeadAes256Gcm"/>, which two ends of this
    /// stack agree on — or <see langword="null"/> before the handshake and
    /// for a call not keyed by one. A call keyed by SDES agreed its suite in
    /// the SDP and raises no such event; <see cref="SipralMediaSnapshot"/>'s
    /// <c>Secured</c> says it is encrypted.</summary>
    public SipralSrtpSuite? SrtpSuite => _suite;

    /// <summary><c>sipral_call_hangup_for</c>: ends the call saying why, as a
    /// <c>Reason</c> (RFC 3326) on the BYE or the CANCEL —
    /// <paramref name="sipCause"/> a SIP status, <paramref name="q850Cause"/>
    /// a Q.850 cause (16 is normal clearing), either or both, with
    /// <paramref name="text"/> beside them. The refusal of an incoming call
    /// nothing answered carries only the Q.850 value (RFC 6432).</summary>
    public void HangupFor(uint sipCause = 0, uint q850Cause = 0, string? text = null)
    {
        var said = text is null ? null : ToSBytes(text);
        SipralErrors.Call(
            () => NativeMethods.sipral_call_hangup_for(
                _stack.Handle, Handle, sipCause, q850Cause, said!, (nuint)(said?.Length ?? 0), _stack.NowMs),
            "sipral_call_hangup_for");
    }

    /// <summary>Every entry of one identity list this call's INVITE carried:
    /// see <see cref="SipralStack.CallIdentity"/>.</summary>
    public IReadOnlyList<string> Identity(SipralIdentityText which) => _stack.CallIdentity(Handle, which);

    /// <summary>
    /// Moves this call's audio to a new network: what
    /// <see cref="SipralEventKind.CallAddressWanted"/> asks for once
    /// <see cref="SipralStack.MoveTo"/> changed the stack's address.
    ///
    /// A media socket is bound at <paramref name="mediaHost"/>:<paramref name="mediaPort"/>
    /// and the call offered at it (<c>sipral_call_media_readdress</c>): a
    /// re-INVITE with the call's last description, only <c>c=</c> and the
    /// <c>m=</c> port moved, and <paramref name="publicAddress"/>
    /// (<c>host:port</c>) in their place when the socket sits behind a NAT
    /// whose mapping the application knows. The new socket is the call's
    /// from here, whatever the far end answers —
    /// <see cref="SipralEventKind.SessionChanged"/> or
    /// <see cref="SipralEventKind.SessionChangeFailed"/> — and the old one is
    /// closed. <see cref="SipralStatus.WrongState"/> for a call running ICE,
    /// which <see cref="RestartIce"/> moves instead, or one with a change
    /// already on its way.
    /// </summary>
    public void Readdress(string mediaHost, int mediaPort = 0, string? publicAddress = null)
    {
        var socket = _stack.OpenMediaSocket(mediaHost, mediaPort);
        var address = SipralStack.FormatAddress((IPEndPoint)socket.LocalEndPoint!);
        var addressBytes = ToSBytes(address);
        var publicBytes = publicAddress is null ? null : ToSBytes(publicAddress);
        try
        {
            SipralErrors.Call(
                () => NativeMethods.sipral_call_media_readdress(
                    _stack.Handle, Handle, addressBytes, (nuint)addressBytes.Length,
                    publicBytes!, (nuint)(publicBytes?.Length ?? 0), _stack.NowMs),
                "sipral_call_media_readdress");
        }
        catch
        {
            var port = ((IPEndPoint)socket.LocalEndPoint!).Port;
            socket.Dispose();
            _stack.GiveBackPort(port);
            throw;
        }
        var old = _mediaSocket;
        _mediaSocket = socket;
        _mediaAddress = address;
        if (Media is { } media)
        {
            media.Rebind(socket);
        }
        else
        {
            old.Dispose();
        }
    }

    /// <summary><c>sipral_call_send_dtmf</c>. <see cref="SipralDtmf.Rtp"/>
    /// sends named events, or the tones in the audio on a call that
    /// negotiated none; <see cref="SipralDtmf.InBand"/> sends the tones on
    /// any call.</summary>
    public void SendDtmf(string digits, SipralDtmf via = SipralDtmf.Rtp, uint durationMs = 100)
    {
        var encoded = ToSBytes(digits);
        SipralErrors.Call(() => NativeMethods.sipral_call_send_dtmf(_stack.Handle, Handle, encoded, (nuint)encoded.Length, (uint)via, durationMs, _stack.NowMs), "sipral_call_send_dtmf");
    }

    /// <summary><c>sipral_call_dtmf_detection</c>: when this call listens
    /// for digits in the far end's audio. One heard there is a
    /// <see cref="SipralEventKind.InBandDigit"/>, and reaches
    /// <see cref="Dtmf"/> like any other.</summary>
    public void SetDtmfDetection(SipralDtmfDetection mode)
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_dtmf_detection(_stack.Handle, Handle, (uint)mode), "sipral_call_dtmf_detection");
    }

    /// <summary><c>sipral_call_detect_progress</c>: listen for the network's
    /// tones, decide who answered and listen for the machine's beep, as
    /// <paramref name="options"/> say (<see langword="null"/> for every
    /// default). Call it straight after <see cref="SipralStack.PlaceCall"/>,
    /// before the far end answers; each thing heard is a
    /// <see cref="SipralEventKind.ProgressDetected"/> with
    /// <see cref="SipralEventArgs.Progress"/> set.</summary>
    public void DetectProgress(SipralProgressOptions? options = null)
    {
        var o = options ?? new SipralProgressOptions();
        var config = new SipralProgressConfig
        {
            Size = (nuint)Marshal.SizeOf<SipralProgressConfig>(),
            Listen = (uint)SipralToggle.On,
            Region = (uint)o.Region,
            AnsweringMachine = (uint)(o.AnsweringMachine ? SipralToggle.On : SipralToggle.Off),
            Beep = (uint)(o.Beep ? SipralToggle.On : SipralToggle.Off),
            BeepWindowMs = o.BeepWindowMs,
            MaxInitialSilenceMs = o.MaxInitialSilenceMs,
            MaxGreetingMs = o.MaxGreetingMs,
            SilenceAfterGreetingMs = o.SilenceAfterGreetingMs,
            MaxWords = o.MaxWords,
            MinWordMs = o.MinWordMs,
            MinWordGapMs = o.MinWordGapMs,
            MaxDecisionMs = o.MaxDecisionMs,
            MinSpeechAboveFloorDb = o.MinSpeechAboveFloorDb,
            BeepMinMs = o.BeepMinMs,
            BeepMaxMs = o.BeepMaxMs,
            ToneCycles = o.ToneCycles,
        };
        SipralErrors.Call(() => NativeMethods.sipral_call_detect_progress(_stack.Handle, Handle, config), "sipral_call_detect_progress");
    }

    /// <summary><c>sipral_call_detect_progress</c> with listening off.</summary>
    public void StopProgress()
    {
        var config = new SipralProgressConfig
        {
            Size = (nuint)Marshal.SizeOf<SipralProgressConfig>(),
            Listen = (uint)SipralToggle.Off,
        };
        SipralErrors.Call(() => NativeMethods.sipral_call_detect_progress(_stack.Handle, Handle, config), "sipral_call_detect_progress");
    }

    /// <summary><c>sipral_call_consent_tone</c>: beep while this call is
    /// recorded, every value left at zero the library's default (1400 Hz,
    /// 18 dB below 0 dBm0, 200 ms every fifteen seconds);
    /// <paramref name="local"/> has this end hear it too.</summary>
    public void SetConsentTone(uint frequencyHz = 0, uint attenuationDb = 0, uint lengthMs = 0, uint intervalMs = 0, bool local = true)
    {
        Consent(SipralToggle.On, frequencyHz, attenuationDb, lengthMs, intervalMs, local);
    }

    /// <summary><c>sipral_call_consent_tone</c> with the tone off.</summary>
    public void ClearConsentTone() => Consent(SipralToggle.Off, 0, 0, 0, 0, true);

    private void Consent(SipralToggle enabled, uint frequencyHz, uint attenuationDb, uint lengthMs, uint intervalMs, bool local)
    {
        var tone = new SipralConsentTone
        {
            Size = (nuint)Marshal.SizeOf<SipralConsentTone>(),
            Enabled = (uint)enabled,
            FrequencyHz = frequencyHz,
            AttenuationDb = attenuationDb,
            LengthMs = lengthMs,
            IntervalMs = intervalMs,
            Local = (uint)(local ? SipralToggle.On : SipralToggle.Off),
        };
        SipralErrors.Call(() => NativeMethods.sipral_call_consent_tone(_stack.Handle, Handle, tone), "sipral_call_consent_tone");
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
