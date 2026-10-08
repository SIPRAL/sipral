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
/// One call handle, its events and, once media starts, its audio. Built by
/// <see cref="SipralStack.PlaceCall"/> or <see cref="SipralStack.AnswerCall"/>,
/// and registered with the stack before the caller sees it.
/// </summary>
public sealed class Call : IDisposable
{
    private readonly SipralStack _stack;
    private readonly CallSafeHandle _handle = new();
    // Replaced by Readdress; read from the audio engine's thread.
    private volatile Socket _mediaSocket;
    private volatile string _mediaAddress;
    private SipralSrtpSuite? _suite;
    private readonly Channel<SipralEventArgs> _events =
        Channel.CreateUnbounded<SipralEventArgs>(new UnboundedChannelOptions { SingleWriter = true });
    private readonly Channel<char> _dtmf =
        Channel.CreateUnbounded<char>(new UnboundedChannelOptions { SingleWriter = true });
    private readonly Channel<string> _text =
        Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleWriter = true });
    // Handed to CallMedia once media starts.
    private readonly Socket? _textSocket;

    private int _disposed;
    // Orders the poll thread starting Media against Close and Readdress on
    // the application's: each decides from one view of Media whether the
    // media socket is the media's or still the call's to close.
    private readonly object _mediaLock = new();

    /// <summary>The raw <c>sipral_handle_t</c>, for entry points this class
    /// does not wrap. Valid while the call is.</summary>
    public ulong Handle => _handle.Value;

    /// <summary>Set once <see cref="SipralEventKind.MediaStarted"/>
    /// arrives; <see langword="null"/> before that.</summary>
    public CallMedia? Media { get; private set; }

    /// <summary>Set once <see cref="SipralEventKind.CallEnded"/> has been
    /// delivered.</summary>
    public bool Ended { get; private set; }

    /// <summary>The final <see cref="SipralEventKind.MediaStatistics"/>
    /// record, which arrives right after
    /// <see cref="SipralEventKind.CallEnded"/>; <see langword="null"/> before
    /// that or when media never started.</summary>
    public SipralStreamStatistics? FinalStatistics { get; private set; }

    /// <summary>Every event this call's handle names, decoded whole, in
    /// order.</summary>
    public IAsyncEnumerable<SipralEventArgs> Events => _events.Reader.ReadAllAsync();

    /// <summary>Received digits, from both
    /// <see cref="SipralEventKind.DigitReceived"/> and
    /// <see cref="SipralEventKind.InBandDigit"/>.</summary>
    public IAsyncEnumerable<char> Dtmf => _dtmf.Reader.ReadAllAsync();

    /// <summary>Received real-time text (RFC 4103) in typing order, control
    /// characters included (see <see cref="SipralTextEventInfo"/>).</summary>
    public IAsyncEnumerable<string> Text => _text.Reader.ReadAllAsync();

    /// <summary>The real-time text socket as <c>host:port</c>, or
    /// <see langword="null"/> without <see cref="SipralCallOptions.Text"/>.</summary>
    public string? TextAddress { get; }

    /// <summary>The recording session <see cref="RecordTo"/> placed, while it
    /// records: a call handle of its own, whose events arrive on
    /// <see cref="SipralStack.Events"/>.</summary>
    public ulong? RecordingSession { get; private set; }

    /// <summary>Fired synchronously on the poll thread for every event of
    /// this call; see <see cref="SipralStack.EventReceived"/>.</summary>
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

    // On the poll thread. Side effects happen before any reader sees the
    // event, so a woken reader already finds Media set.
    internal void Deliver(SipralEventArgs args)
    {
        if (args.Kind == SipralEventKind.MediaStarted && Media is null)
        {
            // release from STUN first so the two readers never race
            _stack.ReleaseStunSocket(_mediaAddress);
            lock (_mediaLock)
            {
                // Close, on another thread, may have closed the socket after
                // the stack looked this call up for the event: then there is
                // no media to start, only a socket already gone.
                if (Volatile.Read(ref _disposed) == 0 && Media is null)
                {
                    Media = new CallMedia(_stack, Handle, _mediaSocket, pumped: _stack.AudioMode == SipralAudio.Device, textSocket: _textSocket);
                }
            }
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

        // must not unwind into the native poll frame
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

    /// <summary><c>sipral_call_state</c>, read fresh rather than cached
    /// from the last event.</summary>
    public SipralCallState State
    {
        get
        {
            uint state = 0;
            SipralErrors.Call(() => NativeMethods.sipral_call_state(_stack.Handle, Handle, out state), "sipral_call_state");
            return (SipralCallState)state;
        }
    }

    /// <summary><c>sipral_call_answer_media</c>: accept on this call's media
    /// socket.</summary>
    public void Answer()
    {
        var address = ToSBytes(_mediaAddress);
        SipralErrors.Call(() => NativeMethods.sipral_call_answer_media(_stack.Handle, Handle, address, (nuint)address.Length, _stack.NowMs), "sipral_call_answer_media");
    }

    // Text needs the text socket AnswerCall opens when options ask for it.
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

    /// <summary><c>sipral_call_restart_ice</c>: re-offer with new ICE
    /// credentials (RFC 8445 §9); audio stays on the current path until a
    /// new <see cref="SipralEventKind.MediaPathChosen"/>.</summary>
    public void RestartIce()
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_restart_ice(_stack.Handle, Handle, _stack.NowMs), "sipral_call_restart_ice");
    }

    /// <summary><c>sipral_call_transfer</c>: blind transfer to
    /// <paramref name="target"/> (RFC 3515). This end stays in the call until
    /// the new call is up; <see cref="SipralEventKind.TransferProgress"/> and
    /// <see cref="SipralEventKind.TransferDone"/> report it (see
    /// <see cref="WaitForTransferAsync"/>).</summary>
    public void Transfer(string target)
    {
        var bytes = ToSBytes(target);
        SipralErrors.Call(
            () => NativeMethods.sipral_call_transfer(_stack.Handle, Handle, bytes, (nuint)bytes.Length, _stack.NowMs),
            "sipral_call_transfer");
    }

    /// <summary><c>sipral_call_transfer_to</c>: attended transfer (RFC 3891)
    /// to the far end of <paramref name="other"/>, usually a consultation
    /// call, which that party replaces with this one. Progress arrives as for
    /// <see cref="Transfer"/>. Holding this call first is up to the
    /// application.</summary>
    public void TransferTo(Call other) => TransferTo(other.Handle);

    /// <summary><see cref="TransferTo(Call)"/> for a call named by its
    /// handle.</summary>
    public void TransferTo(ulong other)
    {
        SipralErrors.Call(
            () => NativeMethods.sipral_call_transfer_to(_stack.Handle, Handle, other, _stack.NowMs),
            "sipral_call_transfer_to");
    }

    /// <summary>Waits for <see cref="SipralEventKind.TransferDone"/> (a 2xx
    /// <see cref="SipralTransferEventInfo.StatusCode"/> means success), or
    /// null when this call ends first.</summary>
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

    internal Socket MediaSocket => _mediaSocket;

    /// <summary>The media socket as <c>host:port</c>, as described in the
    /// SDP.</summary>
    public string MediaAddress => _mediaAddress;

    /// <summary>The SRTP suite DTLS-SRTP settled on, from the last
    /// <see cref="SipralEventKind.MediaSecured"/>; <see langword="null"/>
    /// before the handshake or for SDES-keyed calls, which raise no such
    /// event (see <see cref="SipralMediaSnapshot"/>).</summary>
    public SipralSrtpSuite? SrtpSuite => _suite;

    /// <summary><c>sipral_call_hangup_for</c>: hang up with a <c>Reason</c>
    /// (RFC 3326): a SIP status, a Q.850 cause (16 is normal clearing), or
    /// both, plus <paramref name="text"/>. Refusing an unanswered incoming
    /// call carries only the Q.850 value (RFC 6432).</summary>
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
    /// Moves this call's audio to a new network, answering
    /// <see cref="SipralEventKind.CallAddressWanted"/>.
    ///
    /// Binds a new socket and sends a re-INVITE with only <c>c=</c> and the
    /// <c>m=</c> port changed (<c>sipral_call_media_readdress</c>), or
    /// <paramref name="publicAddress"/> when a known NAT mapping applies. The
    /// new socket is kept whatever the answer
    /// (<see cref="SipralEventKind.SessionChanged"/> or
    /// <see cref="SipralEventKind.SessionChangeFailed"/>); the old one is
    /// closed. <see cref="SipralStatus.WrongState"/> under ICE (use
    /// <see cref="RestartIce"/>) or with a change already pending.
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
        Socket old;
        CallMedia? started;
        lock (_mediaLock)
        {
            old = _mediaSocket;
            _mediaSocket = socket;
            _mediaAddress = address;
            started = Media;
        }
        if (started is { } media)
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

    /// <summary><c>sipral_call_dtmf_detection</c>: when to listen for digits
    /// in the far end's audio (<see cref="SipralEventKind.InBandDigit"/>).</summary>
    public void SetDtmfDetection(SipralDtmfDetection mode)
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_dtmf_detection(_stack.Handle, Handle, (uint)mode), "sipral_call_dtmf_detection");
    }

    /// <summary><c>sipral_call_detect_progress</c>: detect call-progress
    /// tones, answering machines and beeps. Call it right after
    /// <see cref="SipralStack.PlaceCall"/>, before the answer; results arrive
    /// as <see cref="SipralEventKind.ProgressDetected"/>.</summary>
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

    /// <summary><c>sipral_call_consent_tone</c>: beep while recording. Zero
    /// means the default (1400 Hz, -18 dBm0, 200 ms every 15 s);
    /// <paramref name="local"/> plays it here too.</summary>
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

    /// <summary><c>sipral_media_send_text</c>: queue typed text (RFC 4103)
    /// for the next 300 ms interval; BACKSPACE (U+0008) erases the far end's
    /// last character. <see cref="SipralStatus.NotNegotiated"/> on a call
    /// that agreed no text stream, <see cref="SipralStatus.Exhausted"/> when
    /// more is waiting unsent than a stream holds, and
    /// <see cref="InvalidOperationException"/> before media starts.</summary>
    public void SendText(string text)
    {
        var media = Media ?? throw new InvalidOperationException("the call has no media yet; wait for MediaStarted");
        media.SendText(text);
    }

    /// <summary><c>sipral_call_set_focus</c>: mark this end as conference
    /// focus (RFC 4579), adding <c>isfocus</c> to the <c>Contact</c> from the
    /// next answer or re-INVITE.</summary>
    public void SetFocus(bool focus)
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_set_focus(_stack.Handle, Handle, focus ? 1u : 0u), "sipral_call_set_focus");
    }

    /// <summary><c>sipral_call_conference_uri</c>: the conference URI when
    /// the far end is a focus (RFC 4579 §4.2), else
    /// <see langword="null"/>.</summary>
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

    /// <summary><c>sipral_call_subscribe_conference</c>: watch the focus's
    /// conference (RFC 4579 §3.4). The subscription outlives the call;
    /// <see cref="SipralEventKind.ConferenceChanged"/> reports changes.
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

    /// <summary>
    /// <c>sipral_call_record_to</c>: record this call to a SIPREC server (RFC
    /// 7866). Two sockets are opened, labelled <c>1</c> (this end) and
    /// <c>2</c> (far end), and a recording session is placed to
    /// <paramref name="server"/>, optionally via
    /// <paramref name="destination"/>. The INVITE is too large for a
    /// datagram, so the stack must signal over TCP or TLS.
    /// <see cref="SipralStatus.WrongState"/> before media starts or while
    /// already recording. Returns the session handle.
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

    /// <summary><c>sipral_call_stop_recording_to</c>: stop at once, hang up
    /// the session and close its sockets. <see cref="SipralStatus.WrongState"/>
    /// when not recording.</summary>
    public void StopRecordingTo()
    {
        SipralErrors.Call(
            () => NativeMethods.sipral_call_stop_recording_to(_stack.Handle, Handle, _stack.NowMs),
            "sipral_call_stop_recording_to");
        Media?.DetachRecording();
        RecordingSession = null;
    }

    /// <summary>
    /// True when the call reaches <see cref="SipralCallState.Confirmed"/>,
    /// false when it ends first.
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

    /// <summary>Waits for <see cref="Media"/>, or null when the call ends
    /// first.</summary>
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
        // _disposed is set: past this lock the poll thread starts no media
        CallMedia? started;
        lock (_mediaLock)
        {
            started = Media;
        }
        if (started is not null)
        {
            started.Dispose();
        }
        else
        {
            // no media ever started: unmap before closing the socket
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
/// <see cref="Text"/> adds a real-time text stream (RFC 4103) on its own
/// socket; not offered with SRTP or ICE, since the text stream has no key or
/// candidates of its own. <see cref="Feedback"/> offers RTP/AVPF (RFC 4585)
/// with NACKs and reduced-size RTCP (RFC 5506); off by default because
/// RTP/AVP-only peers refuse it, and an AVPF offer is answered in kind
/// anyway. <see cref="Focus"/> marks this end as conference focus (RFC
/// 4579).</summary>
public sealed record SipralCallOptions(bool Text = false, bool Feedback = false, bool Focus = false)
{
    /// <summary>This call's codecs, e.g. <c>"PCMA,PCMU"</c>; null keeps the
    /// stack's. An answer keeps the offer's order (RFC 3264 §6.1), so when
    /// answering this picks which codecs, not which first. An unknown name
    /// is <see cref="SipralStatus.InvalidArgument"/>.</summary>
    public string? Codecs { get; init; }

    /// <summary>Follow a 3xx to its targets in preference order (RFC 3261
    /// §8.1.3.4). Off by default: a 3xx ends the call and its
    /// <c>Contact</c> is left to the application. Placing only.</summary>
    public bool FollowRedirects { get; init; }
}
