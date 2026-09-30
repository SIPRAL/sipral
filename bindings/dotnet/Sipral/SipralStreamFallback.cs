// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Sipral.Interop;
using static Sipral.Interop.NativeText;

namespace Sipral;

/// <summary>What <see cref="SipralEventKind.TransportWanted"/> carries: a
/// request too large for a datagram (RFC 3261 §18.1.1), where it was going,
/// and the two sizes that say why.</summary>
public sealed record SipralTransportWantedEventInfo(
    SipralTransport Protocol,
    string? Destination,
    ulong RequestBytes,
    uint LimitBytes);

public sealed partial class SipralStack
{
    /// <summary>The first number a connection this class opens for
    /// <see cref="SipralEventKind.TransportWanted"/> is bound at, one more for
    /// each destination after it: well clear of <c>Sipral.TransportMain</c>
    /// and of the small numbers an application driving the native layer itself
    /// would pick.</summary>
    internal const uint FirstStream = 1024;

    private bool _streamFallback = true;

    /// <summary>Where such a connection goes, when not to the address asked
    /// for (<c>streamServer</c>).</summary>
    private string? _streamServer;

    /// <summary>Where <see cref="SipralEventKind.TransportWanted"/> asked for
    /// a stream, during the poll that raised it, acted on right after that
    /// poll.</summary>
    private readonly ConcurrentQueue<string> _streamsAsked = new();

    /// <summary>The transport numbers <see cref="SipralEventKind.TransportFailed"/>
    /// named during that same poll, acted on at the same moment.</summary>
    private readonly ConcurrentQueue<uint> _streamsLetGo = new();

    /// <summary>Every connection opened for one, by the transport number it
    /// is bound at, and the destinations one is being opened to, both under
    /// <see cref="_streamLock"/>.</summary>
    private readonly object _streamLock = new();
    private readonly Dictionary<uint, SipStream> _sipStreams = new();
    private readonly HashSet<string> _streamsOpening = new();
    private uint _nextStream = FirstStream;

    /// <summary>One TCP connection opened because a request was too large
    /// for a datagram.</summary>
    private sealed class SipStream
    {
        public required uint Transport { get; init; }
        public required string Destination { get; init; }
        public required TcpClient Client { get; init; }
        public required NetworkStream Stream { get; init; }
        public object WriteLock { get; } = new();
    }

    /// <summary>Remembers a <see cref="SipralEventKind.TransportWanted"/> for
    /// after the poll that raised it; nothing may call back into the stack
    /// from inside its own callback here.</summary>
    private void NoteStreamWanted(SipralEventArgs args)
    {
        if (!Streamed && args.TransportWanted?.Destination is { } destination)
        {
            _streamsAsked.Enqueue(destination);
        }
        if (!Streamed && args.Kind == SipralEventKind.TransportFailed && args.TransportFailed is { } lost)
        {
            NoteStreamLetGo(lost.Transport);
        }
        if (Streamed && args.Kind == SipralEventKind.TransportFailed
            && args.TransportFailed?.Transport == global::Sipral.Sipral.TransportMain)
        {
            _mainLetGo = true;
        }
    }

    /// <summary>Remembers a transport the stack let go of, for after the poll
    /// that said so: a connection this class opened that stopped answering
    /// keep-alives (RFC 5626 §4.4.1) is retired by the stack while its socket
    /// is still open here, and a connection kept open that the stack will
    /// never write to again would stand in for the new one it asks
    /// for.</summary>
    internal void NoteStreamLetGo(uint transport) => _streamsLetGo.Enqueue(transport);

    /// <summary>Answers what <see cref="SipralEventKind.TransportWanted"/>
    /// asked for in the poll that just ran: a connection to each destination
    /// not already connected or being connected to, opened on a thread of its
    /// own, or — with <c>streamFallback</c> off — the word that none is
    /// coming. First the connections the stack let go of in that
    /// poll.</summary>
    private void ActOnStreamsWanted()
    {
        while (_streamsLetGo.TryDequeue(out var letGo))
        {
            LoseSipStream(letGo, tell: false);
        }
        var seen = new HashSet<string>();
        while (_streamsAsked.TryDequeue(out var destination))
        {
            if (!seen.Add(destination))
            {
                continue;
            }
            uint transport;
            lock (_streamLock)
            {
                if (_streamsOpening.Contains(destination)
                    || _sipStreams.Values.Any(stream => stream.Destination == destination))
                {
                    continue;
                }
                transport = _nextStream++;
                if (_streamFallback)
                {
                    _streamsOpening.Add(destination);
                }
            }
            if (!_streamFallback)
            {
                SayNoStream(transport, SipralTransportError.ConnectionRefused);
                continue;
            }
            new Thread(() => OpenSipStream(transport, destination))
            {
                IsBackground = true,
                Name = "sipral-stream",
            }.Start();
        }
    }

    /// <summary>Connects over TCP to <paramref name="destination"/> — or to
    /// <c>streamServer</c> when one was given — binds the connection at
    /// <paramref name="transport"/> as the stream to
    /// <paramref name="destination"/> and reads it until it closes; a
    /// connection that cannot be made is told to the stack on that same
    /// number, which ends what was waiting for it.</summary>
    private void OpenSipStream(uint transport, string destination)
    {
        SipStream stream;
        try
        {
            var (host, port) = ParseAddress(_streamServer ?? destination);
            var address = IPAddress.Parse(host);
            var client = new TcpClient(address.AddressFamily) { NoDelay = true };
            try
            {
                if (!client.ConnectAsync(address, port).Wait(SignallingPatience))
                {
                    throw new SocketException((int)SocketError.TimedOut);
                }
            }
            catch
            {
                client.Dispose();
                throw;
            }
            stream = new SipStream
            {
                Transport = transport,
                Destination = destination,
                Client = client,
                Stream = client.GetStream(),
            };
        }
        catch (Exception ex) when (ex is SocketException or AggregateException or FormatException
                                       or ArgumentException or IOException)
        {
            lock (_streamLock)
            {
                _streamsOpening.Remove(destination);
            }
            var socket = ex as SocketException ?? ex.InnerException as SocketException;
            SayNoStream(transport, socket is not null ? Refused(socket).Error : SipralTransportError.Other);
            return;
        }
        lock (_streamLock)
        {
            _streamsOpening.Remove(destination);
            if (_closed.IsSet)
            {
                stream.Stream.Dispose();
                stream.Client.Dispose();
                return;
            }
            _sipStreams[transport] = stream;
        }
        var local = ToSBytes(FormatAddress((IPEndPoint)stream.Client.Client.LocalEndPoint!));
        var remote = ToSBytes(destination);
        try
        {
            SipralErrors.Call(
                () => NativeMethods.sipral_stack_transport_bind(
                    Handle, transport, (uint)SipralTransport.Tcp, local, (nuint)local.Length,
                    remote, (nuint)remote.Length, NowMs, out _),
                "sipral_stack_transport_bind");
        }
        catch (Exception ex) when (ex is SipralException or ObjectDisposedException)
        {
            LoseSipStream(transport, tell: false);
            SayNoStream(transport, SipralTransportError.Other);
            return;
        }
        ReadSipStream(stream);
    }

    /// <summary>What the connection carried, to
    /// <c>sipral_stack_receive_stream</c>, every byte and in order; the far
    /// end closing it is <c>sipral_stack_stream_closed</c>.</summary>
    private void ReadSipStream(SipStream stream)
    {
        var buffer = new byte[TransmitBytes];
        while (!_closed.IsSet)
        {
            int read;
            try
            {
                read = stream.Stream.Read(buffer, 0, buffer.Length);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or SocketException)
            {
                read = 0;
            }
            if (read == 0)
            {
                LoseSipStream(stream.Transport, tell: true);
                return;
            }
            var bytes = buffer.AsSpan(0, read).ToArray();
            var status = SipralStatus.Busy;
            while (!_closed.IsSet)
            {
                status = NativeMethods.sipral_stack_receive_stream(
                    Handle, stream.Transport, bytes, (nuint)bytes.Length, NowMs);
                if (status != SipralStatus.Busy)
                {
                    break;
                }
                Thread.Sleep(1);
            }
            if (status != SipralStatus.Ok && status != SipralStatus.Busy)
            {
                // the framing is lost: the stack retired the transport itself
                LoseSipStream(stream.Transport, tell: false);
                return;
            }
        }
    }

    /// <summary>Writes one message on the connection bound at
    /// <paramref name="transport"/>, whole; a write that fails loses the
    /// connection.</summary>
    private void WriteSipStream(uint transport, byte[] payload)
    {
        SipStream? stream;
        lock (_streamLock)
        {
            _sipStreams.TryGetValue(transport, out stream);
        }
        if (stream is null)
        {
            return;
        }
        try
        {
            lock (stream.WriteLock)
            {
                stream.Stream.Write(payload, 0, payload.Length);
                stream.Stream.Flush();
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or SocketException)
        {
            LoseSipStream(transport, tell: true);
        }
    }

    /// <summary>Closes the connection bound at <paramref name="transport"/>
    /// and, when <paramref name="tell"/>, says so with
    /// <c>sipral_stack_stream_closed</c>.</summary>
    private void LoseSipStream(uint transport, bool tell)
    {
        SipStream? stream;
        lock (_streamLock)
        {
            if (!_sipStreams.Remove(transport, out stream))
            {
                return;
            }
        }
        lock (stream.WriteLock)
        {
            stream.Stream.Dispose();
            stream.Client.Dispose();
        }
        if (!tell || _closed.IsSet)
        {
            return;
        }
        try
        {
            SipralErrors.Call(() => NativeMethods.sipral_stack_stream_closed(Handle, transport, NowMs),
                "sipral_stack_stream_closed");
        }
        catch (Exception ex) when (ex is SipralException or ObjectDisposedException)
        {
            // the stack is going away
        }
    }

    /// <summary><c>sipral_stack_transport_failed</c> for a connection that
    /// was not made; never throwing on the way out.</summary>
    private void SayNoStream(uint transport, SipralTransportError error)
    {
        try
        {
            SipralErrors.Call(() => NativeMethods.sipral_stack_transport_failed(Handle, transport, (uint)error, NowMs),
                "sipral_stack_transport_failed");
        }
        catch (Exception ex) when (ex is SipralException or ObjectDisposedException)
        {
            // nothing was waiting any more, or the stack is going away
        }
    }

    /// <summary>Closes every connection opened for a request too large for a
    /// datagram, for <see cref="Dispose"/>.</summary>
    private void CloseSipStreams()
    {
        List<uint> open;
        lock (_streamLock)
        {
            open = _sipStreams.Keys.ToList();
        }
        foreach (var transport in open)
        {
            LoseSipStream(transport, tell: false);
        }
    }
}
