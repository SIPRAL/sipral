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
/// One call's audio, paced on its own thread at the frame rate. A media
/// handle never takes the stack's lock. Frames are 16-bit mono PCM: either
/// read <see cref="Frames"/> and call <see cref="SendAudio"/>, or drive
/// <see cref="Playback"/> and <see cref="Capture"/> from your own audio
/// callback. Obtained from <see cref="Call.Media"/>.
/// </summary>
public sealed class CallMedia : IDisposable
{
    private const int PacketBytes = 1500;
    private const int AddressBytes = 128;

    private readonly SipralStack _stack;
    // Replaced by Rebind under _socketLock.
    private volatile Socket _socket;
    private readonly object _socketLock = new();
    // Also names the socket's TURN connection.
    private volatile string _localAddress;
    private readonly MediaSafeHandle _handle = new();
    private readonly Thread _thread;
    private readonly ManualResetEventSlim _closed = new(initialState: false);
    private readonly ConcurrentQueue<short[]> _toSend = new();
    private readonly Channel<short[]> _frames = Channel.CreateUnbounded<short[]>(new UnboundedChannelOptions { SingleWriter = true });
    private readonly IntPtr _packetData = Marshal.AllocHGlobal(PacketBytes);
    private readonly IntPtr _packetDestination = Marshal.AllocHGlobal(AddressBytes);

    private readonly Socket? _textSocket;
    // SIPREC copy sockets while recording; swapped under _socketLock.
    private (Socket ThisEnd, Socket FarEnd)? _recording;

    private bool _active = true;
    private int _disposed;
    private short[] _pending = Array.Empty<short>();

    internal ulong Handle => _handle.Value;

    /// <summary>The sample rate of frames crossing here: the codec's, or
    /// the one <see cref="SetAppRate"/> chose.</summary>
    public uint SampleRate { get; private set; }
    /// <summary>Samples in one frame — what <see cref="Playback"/> fills
    /// and what <see cref="Capture"/> wants, at <see cref="SampleRate"/>.</summary>
    public int FrameSamples { get; private set; }
    // Held across one frame, and while SetAppRate changes the frame length.
    private readonly object _frameLock = new();
    private readonly double _frameSeconds;

    /// <summary>Source of the last received datagram, where the final RTCP
    /// goodbye goes; <see langword="null"/> until a packet arrives.</summary>
    public string? RemoteAddress { get; private set; }

    /// <summary>Decoded 16-bit mono PCM, one frame per item.</summary>
    public IAsyncEnumerable<short[]> Frames => _frames.Reader.ReadAllAsync();

    /// <summary>Fired on the media thread with every decoded frame; the
    /// low-allocation alternative to <see cref="Frames"/>.</summary>
    public event FrameHandler? FrameDecoded;

    /// <summary>A decoded frame, valid for the length of this call
    /// only.</summary>
    public delegate void FrameHandler(ReadOnlySpan<short> samples);

    /// <summary>The media socket as <c>host:port</c>, new after
    /// <see cref="Call.Readdress"/>.</summary>
    public string LocalAddress => _localAddress;

    /// <summary>Whether the library pumps this call's audio (device mode, or
    /// membership in a <see cref="SipralLocalConference"/>). Then no frame
    /// crosses here: <see cref="Frames"/> stays empty and
    /// <see cref="SendAudio"/> throws.</summary>
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

    /// <summary><c>sipral_media_record_start_with</c>: record both directions
    /// to <paramref name="path"/> as WAV or Ogg Opus, mixed or stereo (this
    /// end left). Zero values take defaults; the file is made crash-safe
    /// every <paramref name="checkpointMs"/> (5 s by default) and finished by
    /// <see cref="StopRecording"/>, the call ending, or the stack
    /// closing.</summary>
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

    /// <summary><c>sipral_media_record_state</c>.</summary>
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

    /// <summary><c>sipral_media_statistics</c>. After the call ends, returns
    /// <see cref="Call.FinalStatistics"/> instead of failing.</summary>
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

    internal void EndedWith(SipralStreamStatistics record) => _finalStatistics = record;

    /// <summary>Every path ICE tried (candidate pairs, then relays) and its
    /// outcome. Empty without ICE.</summary>
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

    /// <summary>Per-stream encryption. SDES never authenticates the far end;
    /// DTLS-SRTP does when the certificate matched the signalled
    /// fingerprint.</summary>
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

    /// <summary><c>sipral_media_send_text</c>: see
    /// <see cref="Call.SendText"/>.</summary>
    public void SendText(string text)
    {
        var encoded = ToSBytes(text);
        SipralErrors.Check(NativeMethods.sipral_media_send_text(Handle, encoded, (nuint)encoded.Length), "sipral_media_send_text");
    }

    internal void AttachRecording(Socket thisEnd, Socket farEnd)
    {
        thisEnd.Blocking = false;
        farEnd.Blocking = false;
        lock (_socketLock)
        {
            _recording = (thisEnd, farEnd);
        }
    }

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

    // The server's RTCP on the copy sockets is read and dropped.
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

    // Best effort, like every send here.
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

    /// <summary><c>sipral_media_capture</c>: encode one frame of exactly
    /// <see cref="FrameSamples"/> and send the resulting packet, if
    /// any.</summary>
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

    /// <summary><c>sipral_media_set_app_rate</c>: the application-side rate
    /// (8000, 16000, 24000 or 48000; 0 for the codec's), resampled by the
    /// library. The frame keeps its duration, so <see cref="SampleRate"/> and
    /// <see cref="FrameSamples"/> change. Unsent queued audio is dropped.
    /// Other rates throw with <see cref="SipralStatus.InvalidArgument"/>;
    /// device mode with <see cref="SipralStatus.WrongState"/>.</summary>
    public void SetAppRate(uint hz)
    {
        lock (_frameLock)
        {
            SipralErrors.Call(() => NativeMethods.sipral_media_set_app_rate(Handle, hz), "sipral_media_set_app_rate");
            var info = Info();
            SampleRate = info.SampleRate;
            FrameSamples = info.FrameSamples;
            _pending = Array.Empty<short>();
            while (_toSend.TryDequeue(out _))
            {
            }
        }
    }

    /// <summary>Queues 16-bit mono PCM, cut into frames as it is sent.
    /// Thread-safe. Throws <see cref="InvalidOperationException"/> when
    /// <see cref="Pumped"/>.</summary>
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

    // Also called from the poll thread for the farewell RTCP, racing
    // Dispose. Must not throw, or the poll thread stops.
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

    private void Run()
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var schedule = new FrameSchedule(_frameSeconds, () => clock.Elapsed.TotalSeconds);
        while (!_closed.IsSet)
        {
            DrainReceive();

            if (_active && Pumped)
            {
                // the engine carries frames; RTCP and DTMF still go here
                DrainPackets(NativeMethods.sipral_media_poll_rtcp);
                DrainPackets(NativeMethods.sipral_media_poll_transmit);
                CarryText();
                CarryRecording();
            }
            else if (_active)
            {
                SipralStatus status;
                lock (_frameLock)
                {
                    status = PlayAndCapture();
                }
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

    private SipralStatus PlayAndCapture()
    {
        var status = PlaybackOnce(out var scratch, out var written, out _);
        if (status == SipralStatus.Ok && written > 0)
        {
            var frame = scratch.AsSpan(0, written).ToArray();
            // an unhandled exception on any thread ends the process
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

        Capture(NextChunk());
        return status;
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

    // A datagram, or bytes on the stack's TURN connection when marked TCP/TLS.
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

    /// <summary>Stops the media thread, releases the handle and closes the
    /// socket. <see cref="Call.Close"/> calls it.</summary>
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
