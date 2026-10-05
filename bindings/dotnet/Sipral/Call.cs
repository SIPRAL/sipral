// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
    private readonly Channel<string> _text =
        Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleWriter = true });
    /// <summary>The socket real-time text arrives on, when the call was
    /// placed or answered with <see cref="SipralCallOptions.Text"/>; handed
    /// to <see cref="CallMedia"/> once media starts.</summary>
    private readonly Socket? _textSocket;

    private int _disposed;

    /// <summary>The raw <c>sipral_handle_t</c>, for an entry point of
    /// <c>sipral.h</c> this class does not wrap, called through the
    /// application's own P/Invoke declaration. Valid while the
    /// call is.</summary>
    public ulong Handle => _handle.Value;

    /// <summary>Set once <see cref="SipralEventKind.MediaStarted"/>
    /// arrives; <see langword="null"/> before that.</summary>
    public CallMedia? Media { get; private set; }

    /// <summary>Set once <see cref="SipralEventKind.CallEnded"/> has been
    /// delivered.</summary>
    public bool Ended { get; private set; }

    /// <summary>What the call's media cost in the end: the record
    /// <see cref="SipralEventKind.MediaStatistics"/> carries, kept from the
    /// moment it arrives — right after <see cref="SipralEventKind.CallEnded"/>
    /// — and <see langword="null"/> before that or for a call whose media
    /// never started. <see cref="CallMedia.Statistics"/> answers with it too
    /// once the stream is gone.</summary>
    public SipralStreamStatistics? FinalStatistics { get; private set; }

    /// <summary>Every event this call's handle names, decoded whole, in
    /// order.</summary>
    public IAsyncEnumerable<SipralEventArgs> Events => _events.Reader.ReadAllAsync();

    /// <summary>Just the digits: <see cref="SipralEventKind.DigitReceived"/>'s
    /// and <see cref="SipralEventKind.InBandDigit"/>'s own character, so a
    /// voice agent that only cares about DTMF does not have to filter
    /// <see cref="Events"/> itself, nor care which way a key was
    /// sent.</summary>
    public IAsyncEnumerable<char> Dtmf => _dtmf.Reader.ReadAllAsync();

    /// <summary>Just the real-time text (RFC 4103): each
    /// <see cref="SipralEventKind.TextReceived"/>'s own text, in the order the
    /// far end typed it, with the control characters
    /// <see cref="SipralTextEventInfo"/> names left in.</summary>
    public IAsyncEnumerable<string> Text => _text.Reader.ReadAllAsync();

    /// <summary>The socket this call's real-time text arrives on, as
    /// <c>host:port</c>, when it was placed or answered with
    /// <see cref="SipralCallOptions.Text"/>; <see langword="null"/>
    /// otherwise.</summary>
    public string? TextAddress { get; }

    /// <summary>The recording session <see cref="RecordTo"/> placed, while it
    /// records: a call handle of its own, whose events arrive on
    /// <see cref="SipralStack.Events"/>.</summary>
    public ulong? RecordingSession { get; private set; }

    /// <summary>Fired synchronously, on the stack's poll thread, for
    /// every event this call's handle names — see
    /// <see cref="SipralStack.EventReceived"/> for the same shape and the
    /// same reason.</summary>
    public event EventHandler<SipralEventArgs>? EventReceived;

    internal Call(SipralStack stack, ulong handle, Socket mediaSocket, string mediaAddress, Socket? textSocket = null)
    {
        _stack = stack;
        _handle.SetValue(handle);
        _mediaSocket = mediaSocket;
        _mediaAddress = mediaAddress;
        _textSocket = textSocket;
        TextAddress = textSocket is null ? null : SipralStack.FormatAddress((IPEndPoint)textSocket.LocalEndPoint!);
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
            Media = new CallMedia(_stack, Handle, _mediaSocket, pumped: _stack.AudioMode == SipralAudio.Device, textSocket: _textSocket);
        }
        if (args.Kind == SipralEventKind.MediaSecured && args.Media is { } secured)
        {
            _suite = secured.Suite;
        }
        if (args.Kind == SipralEventKind.CallEnded)
        {
            Ended = true;
        }
        if (args.Kind == SipralEventKind.MediaStatistics && args.Media?.Statistics is { } record)
        {
            FinalStatistics = record;
            Media?.EndedWith(record);
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
        if (args.Kind == SipralEventKind.TextReceived && args.Text is { } typed)
        {
            _text.Writer.TryWrite(typed.Text);
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

    /// <summary><c>sipral_call_answer_with</c>: accept as
    /// <see cref="Answer"/> does, with a real-time text stream, RTCP feedback,
    /// this end named the conference's focus or this call's own codecs as
    /// <paramref name="options"/> say. Text needs the call to have been
    /// built with a text socket, which <see cref="SipralStack.AnswerCall"/>
    /// opens when its options ask for text.</summary>
    internal void AnswerWith(SipralCallOptions options)
    {
        var address = Encoding.UTF8.GetBytes(_mediaAddress);
        var text = TextAddress is null ? null : Encoding.UTF8.GetBytes(TextAddress);
        var codecs = options.Codecs is null ? null : Encoding.UTF8.GetBytes(options.Codecs);
        using var addressPin = new PinnedBytes(address);
        using var textPin = new PinnedBytes(text);
        using var codecsPin = new PinnedBytes(codecs);
        var config = SipralCallConfig.Sized();
        config.MediaAddress = addressPin.Pointer;
        config.MediaAddressLen = (nuint)address.Length;
        config.TextAddress = textPin.Pointer;
        config.TextAddressLen = (nuint)(text?.Length ?? 0);
        config.Codecs = codecsPin.Pointer;
        config.CodecsLen = (nuint)(codecs?.Length ?? 0);
        config.Feedback = (uint)(options.Feedback ? SipralToggle.On : SipralToggle.Default);
        config.Focus = options.Focus ? 1u : 0u;
        SipralErrors.Call(() => NativeMethods.sipral_call_answer_with(_stack.Handle, Handle, config, _stack.NowMs), "sipral_call_answer_with");
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

    /// <summary><c>sipral_call_transfer</c>: ask the far end to call
    /// <paramref name="target"/> instead, a blind transfer (RFC 3515). This
    /// end stays in the call until the far end reports the new call up;
    /// <see cref="SipralEventKind.TransferProgress"/> and then
    /// <see cref="SipralEventKind.TransferDone"/> arrive on
    /// <see cref="Events"/> with <see cref="SipralEventArgs.Transfer"/> set,
    /// and <see cref="WaitForTransferAsync"/> waits for the last.</summary>
    public void Transfer(string target)
    {
        var bytes = ToSBytes(target);
        SipralErrors.Call(
            () => NativeMethods.sipral_call_transfer(_stack.Handle, Handle, bytes, (nuint)bytes.Length, _stack.NowMs),
            "sipral_call_transfer");
    }

    /// <summary><c>sipral_call_transfer_to</c>: hand this call to the far
    /// end of <paramref name="other"/>, the attended half of a transfer (RFC
    /// 3891). <paramref name="other"/> is normally a consultation call this
    /// end placed to the target and is up; the party there replaces it with
    /// this one rather than answering a second call. Progress arrives as
    /// <see cref="Transfer"/>'s does. Putting this call on hold first is the
    /// application's choice.</summary>
    public void TransferTo(Call other) => TransferTo(other.Handle);

    /// <summary><see cref="TransferTo(Call)"/> for a call named by its
    /// handle.</summary>
    public void TransferTo(ulong other)
    {
        SipralErrors.Call(
            () => NativeMethods.sipral_call_transfer_to(_stack.Handle, Handle, other, _stack.NowMs),
            "sipral_call_transfer_to");
    }

    /// <summary>Waits for the <see cref="SipralEventKind.TransferDone"/> a
    /// <see cref="Transfer"/> or <see cref="TransferTo(Call)"/> ends with and
    /// returns what it carries — a 2xx <see cref="SipralTransferEventInfo.StatusCode"/>
    /// when the new call came up — or null when this call ends
    /// first.</summary>
    public async Task<SipralTransferEventInfo?> WaitForTransferAsync(CancellationToken cancellationToken = default)
    {
        await foreach (var args in Events.WithCancellation(cancellationToken))
        {
            if (args.Kind == SipralEventKind.TransferDone)
            {
                return args.Transfer;
            }
            if (args.Kind == SipralEventKind.CallEnded)
            {
                return null;
            }
        }
        return null;
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

    // -- real-time text ---------------------------------------------------

    /// <summary><c>sipral_media_send_text</c>: queue text the user typed for
    /// the far end (RFC 4103). It goes in the next 300 ms interval; a line
    /// break goes as a new line and BACKSPACE (U+0008) erases the far end's
    /// last character. <see cref="SipralStatus.NotNegotiated"/> on a call
    /// that agreed no text stream, <see cref="SipralStatus.Exhausted"/> when
    /// more is waiting unsent than a stream holds, and
    /// <see cref="InvalidOperationException"/> before media starts.</summary>
    public void SendText(string text)
    {
        var media = Media ?? throw new InvalidOperationException("the call has no media yet; wait for MediaStarted");
        media.SendText(text);
    }

    // -- conferences --------------------------------------------------------

    /// <summary><c>sipral_call_set_focus</c>: say, or stop saying, that this
    /// end is the focus of a conference the call belongs to (RFC 4579):
    /// <c>isfocus</c> goes on the <c>Contact</c> of everything the call sends
    /// from here on — the answer, or the next re-INVITE for a call that is
    /// up.</summary>
    public void SetFocus(bool focus)
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_set_focus(_stack.Handle, Handle, focus ? 1u : 0u), "sipral_call_set_focus");
    }

    /// <summary><c>sipral_call_conference_uri</c>: the URI of the conference
    /// this call belongs to, when its far end said it is a focus
    /// (<c>isfocus</c>, RFC 4579 §4.2), or <see langword="null"/> when it did
    /// not.</summary>
    public string? ConferenceUri
    {
        get
        {
            try
            {
                return SipralText.Read(
                    buffer =>
                    {
                        var status = NativeMethods.sipral_call_conference_uri(
                            _stack.Handle, Handle, buffer, (nuint)buffer.Length, out var needed);
                        return (status, needed);
                    },
                    "sipral_call_conference_uri");
            }
            catch (SipralException notFocus) when (notFocus.Status == SipralStatus.NotAFocus)
            {
                return null;
            }
        }
    }

    /// <summary><c>sipral_call_subscribe_conference</c>: watch the
    /// conference of this call's focus (RFC 4579 §3.4) from the call's own
    /// account. The subscription outlives the call;
    /// <see cref="SipralEventKind.ConferenceChanged"/> says what it learns
    /// and <see cref="SipralSubscription.Conference"/> reads the picture.
    /// <see cref="SipralStatus.NotAFocus"/> when the far end is not a
    /// focus.</summary>
    public SipralSubscription SubscribeConference()
    {
        ulong subscription = 0;
        SipralErrors.Call(
            () => NativeMethods.sipral_call_subscribe_conference(_stack.Handle, Handle, out subscription, _stack.NowMs),
            "sipral_call_subscribe_conference");
        return new SipralSubscription(_stack, subscription, "conference");
    }

    // -- recording to a server (SIPREC) ------------------------------------

    /// <summary>
    /// <c>sipral_call_record_to</c>: record this call to a recording server
    /// (RFC 7866). Two sockets are opened beside the call's media socket —
    /// one the copy of what this end sends leaves from, labelled <c>1</c>,
    /// and one for the far end's audio, labelled <c>2</c> — and a recording
    /// session is placed to <paramref name="server"/> (its URI) from the
    /// call's account, where the account sends or at
    /// <paramref name="destination"/> (<c>host:port</c>), with the metadata
    /// beside the offer. That INVITE is too large for a datagram, so the
    /// stack must reach the server over a stream: a stack signalling over
    /// TCP or TLS to it. Once the server answers, the copies leave from the
    /// two sockets as this call's media runs. Needs media started;
    /// <see cref="SipralStatus.WrongState"/> before that and while a
    /// recording already runs. Returns the recording session's handle, as
    /// <see cref="RecordingSession"/> keeps it.
    /// </summary>
    public ulong RecordTo(string server, string? destination = null)
    {
        var media = Media ?? throw new SipralException(SipralStatus.WrongState, "sipral_call_record_to: the call has no media yet");
        var host = SipralStack.ParseAddress(_mediaAddress).Host;
        var thisEnd = _stack.OpenMediaSocket(host);
        var farEnd = _stack.OpenMediaSocket(host);
        var serverBytes = Encoding.UTF8.GetBytes(server);
        var destinationBytes = destination is null ? null : Encoding.UTF8.GetBytes(destination);
        var thisEndBytes = Encoding.UTF8.GetBytes(SipralStack.FormatAddress((IPEndPoint)thisEnd.LocalEndPoint!));
        var farEndBytes = Encoding.UTF8.GetBytes(SipralStack.FormatAddress((IPEndPoint)farEnd.LocalEndPoint!));
        ulong recording = 0;
        try
        {
            using var serverPin = new PinnedBytes(serverBytes);
            using var destinationPin = new PinnedBytes(destinationBytes);
            using var thisEndPin = new PinnedBytes(thisEndBytes);
            using var farEndPin = new PinnedBytes(farEndBytes);
            var config = SipralRecordConfig.Sized();
            config.Server = serverPin.Pointer;
            config.ServerLen = (nuint)serverBytes.Length;
            config.Destination = destinationPin.Pointer;
            config.DestinationLen = (nuint)(destinationBytes?.Length ?? 0);
            config.ThisEnd = thisEndPin.Pointer;
            config.ThisEndLen = (nuint)thisEndBytes.Length;
            config.FarEnd = farEndPin.Pointer;
            config.FarEndLen = (nuint)farEndBytes.Length;
            SipralErrors.Call(
                () => NativeMethods.sipral_call_record_to(_stack.Handle, Handle, config, out recording, _stack.NowMs),
                "sipral_call_record_to");
        }
        catch
        {
            _stack.CloseSocket(thisEnd);
            _stack.CloseSocket(farEnd);
            throw;
        }
        media.AttachRecording(thisEnd, farEnd);
        RecordingSession = recording;
        return recording;
    }

    /// <summary><c>sipral_call_stop_recording_to</c>: the copies stop at
    /// once, the recording session is hung up and its two sockets closed.
    /// <see cref="SipralStatus.WrongState"/> when nothing records the
    /// call.</summary>
    public void StopRecordingTo()
    {
        SipralErrors.Call(
            () => NativeMethods.sipral_call_stop_recording_to(_stack.Handle, Handle, _stack.NowMs),
            "sipral_call_stop_recording_to");
        Media?.DetachRecording();
        RecordingSession = null;
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
            if (_textSocket is not null)
            {
                _stack.CloseSocket(_textSocket);
            }
        }
        _stack.ForgetCall(Handle);
        _events.Writer.TryComplete();
        _dtmf.Writer.TryComplete();
        _text.Writer.TryComplete();
        _handle.Dispose();
    }

    /// <summary>Same as <see cref="Close"/>.</summary>
    public void Dispose() => Close();
}

/// <summary>What a call carries beyond its audio, for
/// <see cref="SipralStack.PlaceCall"/> and <see cref="SipralStack.AnswerCall"/>.
///
/// <see cref="Text"/> opens a second socket beside the audio one and offers
/// (or accepts) a real-time text stream on it (RFC 4103): T.140 with its
/// redundancy, which <see cref="Call.SendText"/> writes to and
/// <see cref="Call.Text"/> reads. It is not offered on a call keyed by SRTP
/// or gathering ICE: the text stream has no key or candidates of its own.
/// <see cref="Feedback"/> offers RTP/AVPF (RFC 4585) with Generic NACKs and
/// reduced-size RTCP (RFC 5506); off by default, since a far end that knows
/// only RTP/AVP refuses the profile, and an offer that asks for it is
/// answered in kind whatever this says. <see cref="Focus"/> says this end is
/// the focus of a conference (RFC 4579): <c>isfocus</c> on its
/// <c>Contact</c>. <see cref="Codecs"/> is this call's codec order in place
/// of the stack's (<c>sipral_call_config_t::codecs</c>).</summary>
public sealed record SipralCallOptions(bool Text = false, bool Feedback = false, bool Focus = false)
{
    /// <summary>The codecs this call offers, or accepts when answering, as
    /// <c>sipral_codec_info_t::name</c> spells them, separated by commas —
    /// <c>"PCMA,PCMU"</c> — in place of the stack's own order; null keeps the
    /// stack's. An answer lists what it takes in the offer's order (RFC 3264
    /// §6.1), so answering, this chooses which codecs rather than which comes
    /// first. A name this build has no encoder for is refused with
    /// <see cref="SipralStatus.InvalidArgument"/>.</summary>
    public string? Codecs { get; init; }
}
