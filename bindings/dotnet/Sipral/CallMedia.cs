// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Channels;
using Sipral.Interop;
using static Sipral.Interop.NativeText;

namespace Sipral;

/// <summary>
/// One call's audio, paced at its own frame rate — the .NET counterpart
/// of <c>bindings/python/sipral/media.py</c>'s <c>Media</c>.
///
/// A call's media has a handle of its own and never takes the stack's
/// lock (<c>docs/08-ffi.md</c>, "A call's media has a handle of its
/// own"), so it runs on a thread of its own too, reading and writing
/// 16-bit mono PCM as <see cref="Span{T}"/>/<see cref="ReadOnlySpan{T}"/>
/// at the two points this ABI actually carries a frame —
/// <see cref="Playback"/> and <see cref="Capture"/> — the way an
/// application that wants to drive its own frame pump (a real audio
/// device callback, on a real thread with real timing) would call them
/// directly instead of reading <see cref="Frames"/> and calling
/// <see cref="SendAudio"/>, which this type's own background thread uses
/// for exactly that pump when nothing else is driving one.
///
/// Not built directly: <see cref="Call"/> mints one from its own
/// <see cref="SipralEventKind.MediaStarted"/> and hands it over as
/// <see cref="Call.Media"/>.
/// </summary>
public sealed class CallMedia : IDisposable
{
    private const int PacketBytes = 1500;
    private const int AddressBytes = 128;

    private readonly SipralStack _stack;
    /// <summary>Replaced by <see cref="Rebind"/> under <see cref="_socketLock"/>.</summary>
    private volatile Socket _socket;
    private readonly object _socketLock = new();
    /// <summary>This call's media socket, as <c>host:port</c>: the name of its
    /// connection to a TURN server reached over TCP or TLS.</summary>
    private volatile string _localAddress;
    private readonly MediaSafeHandle _handle = new();
    private readonly Thread _thread;
    private readonly ManualResetEventSlim _closed = new(initialState: false);
    private readonly ConcurrentQueue<short[]> _toSend = new();
    private readonly Channel<short[]> _frames = Channel.CreateUnbounded<short[]>(new UnboundedChannelOptions { SingleWriter = true });
    private readonly IntPtr _packetData = Marshal.AllocHGlobal(PacketBytes);
    private readonly IntPtr _packetDestination = Marshal.AllocHGlobal(AddressBytes);

    /// <summary>The socket real-time text arrives on and leaves from, when
    /// the call was built with one.</summary>
    private readonly Socket? _textSocket;
    /// <summary>The two sockets a recording server's copies leave from —
    /// this end's audio, then the far end's — while
    /// <see cref="Call.RecordTo"/> records; swapped under
    /// <see cref="_socketLock"/>.</summary>
    private (Socket ThisEnd, Socket FarEnd)? _recording;

    private bool _active = true;
    private int _disposed;
    private short[] _pending = Array.Empty<short>();

    internal ulong Handle => _handle.Value;

    /// <summary>The rate the samples crossing this call's media are at.</summary>
    public uint SampleRate { get; }
    /// <summary>Samples in one frame — what <see cref="Playback"/> fills
    /// and what <see cref="Capture"/> wants.</summary>
    public int FrameSamples { get; }
    private readonly double _frameSeconds;

    /// <summary>Where the last datagram this call's media received came
    /// from — the address the stack's own RTCP goodbye is sent to once
    /// the call has ended. <see langword="null"/> until at least one
    /// packet has arrived.</summary>
    public string? RemoteAddress { get; private set; }

    /// <summary>Decoded 16-bit mono PCM, one frame per item, as this
    /// call's own background thread reads it off the wire.</summary>
    public IAsyncEnumerable<short[]> Frames => _frames.Reader.ReadAllAsync();

    /// <summary>Fired synchronously, from this media's own background
    /// thread, with every frame <see cref="Playback"/> produces — the
    /// low-allocation path for an application that reads audio off a
    /// hot loop instead of an <see langword="await foreach"/> on
    /// <see cref="Frames"/>.</summary>
    public event FrameHandler? FrameDecoded;

    /// <summary>A decoded frame, valid for the length of this call
    /// only.</summary>
    public delegate void FrameHandler(ReadOnlySpan<short> samples);

    /// <summary>The socket this media reads and sends on, as <c>host:port</c>
    /// — a new one after <see cref="Call.Readdress"/>.</summary>
    public string LocalAddress => _localAddress;

    /// <summary>Whether the library's own audio engine pumps this call
    /// (device mode): then no frame crosses here — <see cref="Frames"/> stays
    /// empty, <see cref="FrameDecoded"/> never fires and
    /// <see cref="SendAudio"/> throws — and this media's thread only reads
    /// the socket and sends what RTCP and DTMF owe. Also true while the call
    /// is a member of a <see cref="SipralLocalConference"/>, which carries
    /// its frames.</summary>
    public bool Pumped
    {
        get => _pumped;
        internal set => _pumped = value;
    }

    private volatile bool _pumped;

    internal CallMedia(SipralStack stack, ulong callHandle, Socket socket, bool pumped = false, Socket? textSocket = null)
    {
        _pumped = pumped;
        _stack = stack;
        _socket = socket;
        _socket.Blocking = false;
        _textSocket = textSocket;
        if (_textSocket is not null)
        {
            _textSocket.Blocking = false;
        }
        _localAddress = SipralStack.FormatAddress((IPEndPoint)socket.LocalEndPoint!);

        ulong media = 0;
        SipralErrors.Call(() => NativeMethods.sipral_call_media(stack.Handle, callHandle, out media), "sipral_call_media");
        _handle.SetValue(media);

        var info = Info();
        SampleRate = info.SampleRate;
        FrameSamples = info.FrameSamples;
        _frameSeconds = Math.Max(info.FrameMs, 1) / 1000.0;

        _thread = new Thread(Run) { IsBackground = true, Name = "sipral-media" };
        _thread.Start();
    }

    // -- info -------------------------------------------------------------

    /// <summary><c>sipral_media_info</c>.</summary>
    public SipralMediaSnapshot Info()
    {
        var info = SipralMediaInfo.Sized();
        SipralErrors.Call(() => NativeMethods.sipral_media_info(Handle, ref info), "sipral_media_info");
        return new SipralMediaSnapshot(
            (SipralCodec)info.Codec, info.PayloadType, info.ClockRate, info.SampleRate, info.FrameMs,
            (int)info.FrameSamples, (SipralDirection)info.Direction, info.Sending != 0, info.Receiving != 0,
            info.HasDtmf != 0, info.DtmfPayloadType, (SipralRtcp)info.Rtcp, info.Secured != 0,
            info.Recording != 0, info.RecordedMs, info.Stalled != 0, info.HasText != 0, info.Feedback != 0,
            info.GenericNack != 0, info.ReducedSize != 0);
    }

    // -- recording ----------------------------------------------------------

    /// <summary><c>sipral_media_record_start_with</c>: record both
    /// directions to <paramref name="path"/> — WAV, or Ogg Opus where the
    /// build has Opus; one channel, or this end on the left and the far end
    /// on the right; at <paramref name="sampleRate"/> (zero for the call's);
    /// Ogg Opus at <paramref name="bitrate"/> (zero for libopus's choice);
    /// made to survive a crash every <paramref name="checkpointMs"/> (zero
    /// for five seconds). The file is finished by
    /// <see cref="StopRecording"/>, by the call ending, or by the stack
    /// going.</summary>
    public void Record(
        string path,
        SipralRecordingFormat format = SipralRecordingFormat.Wav,
        SipralRecordingLayout layout = SipralRecordingLayout.Mixed,
        uint sampleRate = 0,
        uint bitrate = 0,
        uint checkpointMs = 0)
    {
        var encoded = ToSBytes(path);
        var options = new SipralRecordingOptions
        {
            Size = (nuint)Marshal.SizeOf<SipralRecordingOptions>(),
            Format = (uint)format,
            Layout = (uint)layout,
            SampleRate = sampleRate,
            Bitrate = bitrate,
            CheckpointMs = checkpointMs,
        };
        SipralErrors.Call(() => NativeMethods.sipral_media_record_start_with(Handle, encoded, (nuint)encoded.Length, options), "sipral_media_record_start_with");
    }

    /// <summary><c>sipral_media_record_stop</c>: stop, and finish the
    /// file.</summary>
    public void StopRecording()
    {
        SipralErrors.Call(() => NativeMethods.sipral_media_record_stop(Handle), "sipral_media_record_stop");
    }

    /// <summary><c>sipral_media_record_state</c>: whether a recording is
    /// running, and how many milliseconds of audio it has taken.</summary>
    public (bool Running, ulong RecordedMs) Recording
    {
        get
        {
            uint running = 0;
            ulong taken = 0;
            SipralErrors.Call(() => NativeMethods.sipral_media_record_state(Handle, out running, out taken), "sipral_media_record_state");
            return (running != 0, taken);
        }
    }

    /// <summary><c>sipral_media_statistics</c>. Once the call has ended the
    /// stream is gone and the library answers
    /// <see cref="SipralStatus.WrongState"/>; from the moment the end-of-call
    /// record has arrived this answers with that record
    /// (<see cref="Call.FinalStatistics"/>) instead.</summary>
    public SipralStreamStatistics Statistics()
    {
        var stats = SipralStreamStats.Sized();
        try
        {
            SipralErrors.Call(() => NativeMethods.sipral_media_statistics(Handle, _stack.NowMs, ref stats), "sipral_media_statistics");
        }
        catch (SipralException refused) when (refused.Status == SipralStatus.WrongState && _finalStatistics is { } final)
        {
            return final;
        }
        return SipralEventArgs.Statistics(stats);
    }

    private volatile SipralStreamStatistics? _finalStatistics;

    /// <summary>The end-of-call record arrived: what <see cref="Statistics"/>
    /// answers from now on, when the library no longer can.</summary>
    internal void EndedWith(SipralStreamStatistics record) => _finalStatistics = record;

    /// <summary>Every path this call's ICE agent tried — the candidate
    /// pairs its checklist held, then the relays it held — and what became
    /// of each (<c>sipral_media_path_candidate_count</c>/<c>_at</c>; D5's
    /// transport and NAT half, <c>docs/05-media.md</c>). Empty for a call
    /// not using ICE.</summary>
    public IReadOnlyList<SipralPath> PathCandidates()
    {
        nuint count = 0;
        SipralErrors.Call(() => NativeMethods.sipral_media_path_candidate_count(Handle, out count), "sipral_media_path_candidate_count");
        var paths = new List<SipralPath>((int)count);
        var local = Marshal.AllocHGlobal(AddressBytes);
        var remote = Marshal.AllocHGlobal(AddressBytes);
        try
        {
            for (nuint index = 0; index < count; index++)
            {
                var path = SipralPathCandidate.Sized();
                path.Local = local;
                path.LocalCapacity = AddressBytes;
                path.Remote = remote;
                path.RemoteCapacity = AddressBytes;
                SipralErrors.Check(NativeMethods.sipral_media_path_candidate_at(Handle, index, ref path), "sipral_media_path_candidate_at");
                paths.Add(new SipralPath(
                    (SipralPathKind)path.Kind, (SipralPathOutcome)path.Outcome, path.Code,
                    (SipralCandidateKind)path.LocalKind, (SipralCandidateKind)path.RemoteKind, path.Priority,
                    Marshal.PtrToStringUTF8(local, (int)path.LocalLen) ?? string.Empty,
                    Marshal.PtrToStringUTF8(remote, (int)path.RemoteLen) ?? string.Empty));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(local);
            Marshal.FreeHGlobal(remote);
        }
        return paths;
    }

    /// <summary>The call's encryption report, now
    /// (<c>sipral_media_encryption_count</c> and
    /// <c>sipral_media_encryption_at</c>): per stream, whether it is
    /// encrypted, how its keys were exchanged, the suite, and whether the
    /// exchange authenticated the far end — SDES never does, a DTLS-SRTP
    /// handshake whose certificate matched the signalled fingerprint
    /// does.</summary>
    public IReadOnlyList<SipralStreamProtection> Encryption()
    {
        nuint count = 0;
        SipralErrors.Call(() => NativeMethods.sipral_media_encryption_count(Handle, out count), "sipral_media_encryption_count");
        var streams = new List<SipralStreamProtection>((int)count);
        for (nuint index = 0; index < count; index++)
        {
            var stream = SipralStreamEncryption.Sized();
            SipralErrors.Check(NativeMethods.sipral_media_encryption_at(Handle, index, ref stream), "sipral_media_encryption_at");
            streams.Add(new SipralStreamProtection(
                (SipralMediaKind)stream.Media, stream.Encrypted != 0, (SipralKeyExchange)stream.KeyExchange,
                (SipralSrtpSuite)stream.Suite, stream.Authenticated != 0, stream.AwaitingKeys != 0));
        }
        return streams;
    }

    // -- real-time text and the copies for a recording server ---------------

    /// <summary><c>sipral_media_send_text</c>: see
    /// <see cref="Call.SendText"/>.</summary>
    public void SendText(string text)
    {
        var encoded = ToSBytes(text);
        SipralErrors.Check(NativeMethods.sipral_media_send_text(Handle, encoded, (nuint)encoded.Length), "sipral_media_send_text");
    }

    /// <summary>Starts sending the recording server's copies from
    /// <paramref name="thisEnd"/> and <paramref name="farEnd"/>: what
    /// <see cref="Call.RecordTo"/> does once the recording session is
    /// placed.</summary>
    internal void AttachRecording(Socket thisEnd, Socket farEnd)
    {
        thisEnd.Blocking = false;
        farEnd.Blocking = false;
        lock (_socketLock)
        {
            _recording = (thisEnd, farEnd);
        }
    }

    /// <summary>Closes the two sockets <see cref="AttachRecording"/> took, once
    /// the recording stopped.</summary>
    internal void DetachRecording()
    {
        (Socket ThisEnd, Socket FarEnd)? taken;
        lock (_socketLock)
        {
            taken = _recording;
            _recording = null;
        }
        if (taken is { } sockets)
        {
            _stack.CloseSocket(sockets.ThisEnd);
            _stack.CloseSocket(sockets.FarEnd);
        }
    }

    /// <summary>Every datagram waiting on the text socket to
    /// <c>sipral_media_receive_text</c>, then every one
    /// <c>sipral_media_poll_text</c> has due, sent from it.</summary>
    private void CarryText()
    {
        if (_textSocket is not { } socket)
        {
            return;
        }
        var buffer = new byte[2048];
        while (true)
        {
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            int count;
            try
            {
                if (!socket.Poll(0, SelectMode.SelectRead))
                {
                    break;
                }
                count = socket.ReceiveFrom(buffer, ref from);
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                return;
            }
            var fromBytes = ToSBytes(SipralStack.FormatAddress((IPEndPoint)from));
            var data = buffer.AsSpan(0, count).ToArray();
            NativeMethods.sipral_media_receive_text(Handle, data, (nuint)count, fromBytes, (nuint)fromBytes.Length, _stack.NowMs, out _);
        }
        while (true)
        {
            var packet = SipralMediaPacket.Sized();
            packet.Data = _packetData;
            packet.Capacity = PacketBytes;
            packet.Destination = _packetDestination;
            packet.DestinationCapacity = AddressBytes;
            var status = NativeMethods.sipral_media_poll_text(Handle, _stack.NowMs, ref packet);
            if (status != SipralStatus.Ok || packet.Len == 0)
            {
                return;
            }
            SendFrom(socket, packet);
        }
    }

    /// <summary>Every copy <c>sipral_media_poll_recording</c> has waiting,
    /// each from the socket it names; what the server sends back to those
    /// sockets — its own RTCP — is read and let go.</summary>
    private void CarryRecording()
    {
        (Socket ThisEnd, Socket FarEnd)? sockets;
        lock (_socketLock)
        {
            sockets = _recording;
        }
        if (sockets is not { } open)
        {
            return;
        }
        Discard(open.ThisEnd);
        Discard(open.FarEnd);
        while (true)
        {
            var packet = SipralMediaPacket.Sized();
            packet.Data = _packetData;
            packet.Capacity = PacketBytes;
            packet.Destination = _packetDestination;
            packet.DestinationCapacity = AddressBytes;
            var status = NativeMethods.sipral_media_poll_recording(Handle, ref packet, out var farEnd);
            if (status != SipralStatus.Ok || packet.Len == 0)
            {
                return;
            }
            SendFrom(farEnd != 0 ? open.FarEnd : open.ThisEnd, packet);
        }
    }

    private static void Discard(Socket socket)
    {
        var buffer = new byte[2048];
        try
        {
            while (socket.Poll(0, SelectMode.SelectRead))
            {
                socket.Receive(buffer);
            }
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
        }
    }

    /// <summary>One datagram out of <paramref name="socket"/>, to where
    /// <paramref name="packet"/> says; best effort, like every send
    /// here.</summary>
    private void SendFrom(Socket socket, SipralMediaPacket packet)
    {
        var payload = new byte[(int)packet.Len];
        Marshal.Copy(_packetData, payload, 0, payload.Length);
        var text = Marshal.PtrToStringUTF8(_packetDestination, (int)packet.DestinationLen);
        if (text is null)
        {
            return;
        }
        try
        {
            var (host, port) = SipralStack.ParseAddress(text);
            socket.SendTo(payload, new IPEndPoint(IPAddress.Parse(host), port));
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or FormatException)
        {
        }
    }

    // -- the two frame-carrying calls, as Span/ReadOnlySpan ---------------

    /// <summary><c>sipral_media_playback</c>: the frame due for the
    /// earpiece, written into <paramref name="destination"/> (at least
    /// <see cref="FrameSamples"/> long). Returns how many samples were
    /// written and, in <paramref name="source"/>, where they came from.</summary>
    public int Playback(Span<short> destination, out SipralPlayback source)
    {
        var status = PlaybackOnce(out var scratch, out var written, out var sourceValue);
        source = (SipralPlayback)sourceValue;
        SipralErrors.Check(status, "sipral_media_playback");
        scratch.AsSpan(0, written).CopyTo(destination);
        return written;
    }

    private SipralStatus PlaybackOnce(out short[] scratch, out int written, out uint source)
    {
        scratch = RentFrame();
        var status = NativeMethods.sipral_media_playback(Handle, scratch, (nuint)scratch.Length, out var writtenCount, out source);
        written = (int)writtenCount;
        return status;
    }

    /// <summary><c>sipral_media_capture</c>: encodes exactly one frame
    /// from <paramref name="samples"/> (exactly <see cref="FrameSamples"/>
    /// long) and sends the packet it produces, if any, on this media's
    /// own socket.</summary>
    public void Capture(ReadOnlySpan<short> samples)
    {
        var scratch = RentFrame();
        samples.CopyTo(scratch);
        var packet = SipralMediaPacket.Sized();
        packet.Data = _packetData;
        packet.Capacity = PacketBytes;
        packet.Destination = _packetDestination;
        packet.DestinationCapacity = AddressBytes;
        var status = NativeMethods.sipral_media_capture(Handle, _stack.NowMs, scratch, (nuint)scratch.Length, ref packet);
        if (status != SipralStatus.Ok || packet.Len == 0)
        {
            return;
        }
        SendPacket(packet);
    }

    /// <summary>Queues 16-bit mono PCM to go out, one frame at a time, cut
    /// to whatever <see cref="FrameSamples"/> this call negotiated as it
    /// is sent rather than as it is queued. Thread-safe. Throws
    /// <see cref="InvalidOperationException"/> in device mode
    /// (<see cref="Pumped"/>), where the microphone is the call's audio and
    /// nothing else is.</summary>
    public void SendAudio(ReadOnlySpan<short> samples)
    {
        if (Pumped)
        {
            throw new InvalidOperationException(
                "this call's audio is pumped by the library's own engine (device mode); " +
                "create the stack with audio: SipralAudio.Application to send frames of your own");
        }
        _toSend.Enqueue(samples.ToArray());
    }

    /// <summary>Carries this call's media on <paramref name="socket"/> from
    /// now on and closes the one it had: what <see cref="Call.Readdress"/>
    /// does once the call was offered at the new socket's address.</summary>
    internal void Rebind(Socket socket)
    {
        socket.Blocking = false;
        Socket old;
        lock (_socketLock)
        {
            old = _socket;
            _socket = socket;
            _localAddress = SipralStack.FormatAddress((IPEndPoint)socket.LocalEndPoint!);
        }
        old.Dispose();
    }

    /// <summary>Writes straight to this call's own RTP socket — used by
    /// <see cref="SipralStack"/> to send the RTCP goodbye
    /// <c>sipral_stack_poll_farewell</c> hands back once the signalling
    /// that owned it has already ended. Called from the stack's own poll
    /// thread, never this media's own frame-rate thread, so it can
    /// race an application thread's <see cref="Dispose"/> of this same
    /// call — closing the socket out from under a send already in
    /// flight is an ordinary shutdown race, not a caller bug, and is
    /// swallowed the same best-effort way a send that fails for any
    /// other reason already is: nothing here may throw, or the poll
    /// thread that called it would never poll again.</summary>
    internal void SendTo(byte[] payload, string address)
    {
        try
        {
            var (host, port) = SipralStack.ParseAddress(address);
            _socket.SendTo(payload, new IPEndPoint(IPAddress.Parse(host), port));
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    // -- the frame-rate thread ---------------------------------------------

    private void Run()
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var schedule = new FrameSchedule(_frameSeconds, () => clock.Elapsed.TotalSeconds);
        while (!_closed.IsSet)
        {
            DrainReceive();

            if (_active && Pumped)
            {
                // the engine plays and captures; this thread still carries
                // what RTCP and DTMF owe, which are not frames
                DrainPackets(NativeMethods.sipral_media_poll_rtcp);
                DrainPackets(NativeMethods.sipral_media_poll_transmit);
                CarryText();
                CarryRecording();
            }
            else if (_active)
            {
                var status = PlaybackOnce(out var scratch, out var written, out _);
                if (status == SipralStatus.Ok && written > 0)
                {
                    var frame = scratch.AsSpan(0, written).ToArray();
                    // Same guard as `SipralStack.EventReceived`: an
                    // unhandled exception on any .NET thread, background
                    // or not, ends the whole process, and this is this
                    // call's own frame-rate thread — one bad handler must
                    // not take every other call and stack down with it.
                    try
                    {
                        FrameDecoded?.Invoke(frame);
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Trace.TraceError($"Sipral: CallMedia.FrameDecoded handler threw: {ex}");
                    }
                    _frames.Writer.TryWrite(frame);
                }

                var chunk = NextChunk();
                Capture(chunk);
                DrainPackets(NativeMethods.sipral_media_poll_rtcp);
                DrainPackets(NativeMethods.sipral_media_poll_transmit);
                CarryText();
                CarryRecording();

                if (status is not (SipralStatus.Ok or SipralStatus.Busy))
                {
                    _active = false;
                }
            }

            var wait = schedule.Next();
            if (wait > TimeSpan.Zero)
            {
                _closed.Wait(wait);
            }
        }
    }

    private void DrainReceive()
    {
        var buffer = new byte[2048];
        while (true)
        {
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            int count;
            lock (_socketLock)
            {
                try
                {
                    if (!_socket.Poll(0, SelectMode.SelectRead))
                    {
                        return;
                    }
                    count = _socket.ReceiveFrom(buffer, ref from);
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                {
                    return;
                }
            }
            RemoteAddress = SipralStack.FormatAddress((IPEndPoint)from);
            var fromBytes = ToSBytes(RemoteAddress);
            var data = new byte[count];
            Array.Copy(buffer, data, count);
            NativeMethods.sipral_media_receive(Handle, data, (nuint)count, fromBytes, (nuint)fromBytes.Length, _stack.NowMs, out var arrival);
        }
    }

    private delegate SipralStatus PollFn(ulong media, ulong nowMs, ref SipralMediaPacket packet);

    private void DrainPackets(PollFn poll)
    {
        while (true)
        {
            var packet = SipralMediaPacket.Sized();
            packet.Data = _packetData;
            packet.Capacity = PacketBytes;
            packet.Destination = _packetDestination;
            packet.DestinationCapacity = AddressBytes;
            var status = poll(Handle, _stack.NowMs, ref packet);
            if (status != SipralStatus.Ok || packet.Len == 0)
            {
                return;
            }
            SendPacket(packet);
        }
    }

    /// <summary>One packet out where it says: a datagram from this call's
    /// socket, or — marked TCP or TLS — bytes on the socket's connection to
    /// the TURN server, which the stack holds.</summary>
    private void SendPacket(SipralMediaPacket packet)
    {
        var payload = new byte[(int)packet.Len];
        Marshal.Copy(_packetData, payload, 0, payload.Length);
        if (SipralStack.OverStream(packet.Protocol))
        {
            _stack.WriteTurn(_localAddress, payload);
            return;
        }
        var text = Marshal.PtrToStringUTF8(_packetDestination, (int)packet.DestinationLen);
        if (text is null)
        {
            return;
        }
        SendTo(payload, text);
    }

    private short[] NextChunk()
    {
        var needed = FrameSamples;
        while (_pending.Length < needed)
        {
            if (!_toSend.TryDequeue(out var more))
            {
                return new short[needed];
            }
            var combined = new short[_pending.Length + more.Length];
            _pending.CopyTo(combined, 0);
            more.CopyTo(combined, _pending.Length);
            _pending = combined;
        }
        var chunk = _pending[..needed];
        _pending = _pending[needed..];
        return chunk;
    }

    private short[] RentFrame() => new short[FrameSamples];

    // -- lifetime -----------------------------------------------------------

    /// <summary>Stops the frame-rate thread, <c>sipral_media_release</c>,
    /// closes the socket. Called by <see cref="Call.Close"/>, not usually
    /// by an application directly.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        _closed.Set();
        if (Thread.CurrentThread != _thread)
        {
            _thread.Join(TimeSpan.FromSeconds(5));
        }
        _frames.Writer.TryComplete();
        _handle.Dispose();
        _socket.Dispose();
        if (_textSocket is not null)
        {
            _stack.CloseSocket(_textSocket);
        }
        DetachRecording();
        Marshal.FreeHGlobal(_packetData);
        Marshal.FreeHGlobal(_packetDestination);
    }
}
