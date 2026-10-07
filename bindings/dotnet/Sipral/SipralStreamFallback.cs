// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using Sipral.Interop;
using static Sipral.Interop.NativeText;

namespace Sipral;

/// <summary>What <see cref="SipralEventKind.TransportWanted"/> carries: a
/// request too large for a datagram (RFC 3261 §18.1.1), its destination and
/// the two sizes.</summary>
public sealed record SipralTransportWantedEventInfo(
    SipralTransport Protocol,
    string? Destination,
    ulong RequestBytes,
    uint LimitBytes);

public sealed partial class SipralStack
{
    // Transport ids for our connections start here, clear of TransportMain
    // and of small ids an application might pick itself.
    internal const uint FirstStream = 1024;

    private bool _streamFallback = true;

    private string? _streamServer;

    // Both queues are filled during the poll and acted on right after it.
    private readonly ConcurrentQueue<SipralTransportWantedEventInfo> _streamsAsked = new();

    // null: the destination's host.
    private string? _givenTlsServerName;

    private readonly ConcurrentQueue<uint> _streamsLetGo = new();

    // Guards the connections by transport id and the destinations being
    // connected to.
    private readonly object _streamLock = new();
    private readonly Dictionary<uint, SipStream> _sipStreams = new();
    private readonly HashSet<string> _streamsOpening = new();
    private uint _nextStream = FirstStream;

    // A TCP connection for an oversized request, or an account's own
    // TCP/TLS connection.
    private sealed class SipStream
    {
        public required uint Transport { get; init; }
        public required string Destination { get; init; }
        public required TcpClient Client { get; init; }
        public required Stream Stream { get; init; }
        public object WriteLock { get; } = new();
    }

    // Deferred: nothing may call into the stack from its own callback.
    private void NoteStreamWanted(SipralEventArgs args)
    {
        if (!Streamed && args.TransportWanted is { Destination: not null } wanted)
        {
            _streamsAsked.Enqueue(wanted);
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

    // The stack retires a connection that missed keep-alives (RFC 5626
    // §4.4.1) while our socket is still open; left open, it would stand in
    // for the new one the stack asks for.
    internal void NoteStreamLetGo(uint transport) => _streamsLetGo.Enqueue(transport);

    // One connecting thread per new destination, or with streamFallback off
    // a report that none is coming. Retired connections are closed first.
    private void ActOnStreamsWanted()
    {
        while (_streamsLetGo.TryDequeue(out var letGo))
        {
            LoseSipStream(letGo, tell: false);
        }
        var seen = new HashSet<string>();
        while (_streamsAsked.TryDequeue(out var wanted))
        {
            var destination = wanted.Destination!;
            if (!seen.Add(destination))
            {
                continue;
            }
            // an account's own connection (no sizes) opens regardless of
            // streamFallback
            var opens = _streamFallback || (wanted.RequestBytes == 0 && wanted.LimitBytes == 0);
            // a WebSocket is a TCP or TLS connection bound as WS or WSS, whose
            // handshake and frames are the stack's
            var bound = wanted.Protocol is SipralTransport.Tls or SipralTransport.Ws or SipralTransport.Wss
                ? wanted.Protocol
                : SipralTransport.Tcp;
            var over = bound is SipralTransport.Tls or SipralTransport.Wss ? SipralTransport.Tls : SipralTransport.Tcp;
            uint transport;
            lock (_streamLock)
            {
                if (_streamsOpening.Contains(destination)
                    || _sipStreams.Values.Any(stream => stream.Destination == destination))
                {
                    continue;
                }
                transport = _nextStream++;
                if (opens)
                {
                    _streamsOpening.Add(destination);
                }
            }
            if (!opens)
            {
                SayNoStream(transport, SipralTransportError.ConnectionRefused,
                    $"to {destination} not tried: streamFallback is off");
                continue;
            }
            new Thread(() => OpenSipStream(transport, destination, over, bound))
            {
                IsBackground = true,
                Name = "sipral-stream",
            }.Start();
        }
    }

    // The pin of an account on that server if it has one, else tlsTrust.
    private SipralTlsTrust StreamTrust(string destination)
    {
        Account? pinned;
        lock (_accounts)
        {
            pinned = _accounts.FirstOrDefault(account
                => account.StreamProtocol is SipralTransport.Tls or SipralTransport.Wss
                && account.RegistrarAddress == destination && account.TlsPin is not null);
        }
        return pinned?.TlsPin is { } pin ? SipralTlsTrust.Pinned(pin) : _tlsTrust;
    }

    // Connects (to streamServer instead, for TCP, when given), binds it as
    // the stream to destination, as `bound` (WS/WSS for a WebSocket), and
    // reads it. A failure is reported on the same transport id, which ends
    // whatever was waiting.
    private void OpenSipStream(
        uint transport, string destination, SipralTransport over = SipralTransport.Tcp, SipralTransport? bound = null)
    {
        SipStream stream;
        var server = over == SipralTransport.Tcp ? _streamServer ?? destination : destination;
        try
        {
            var (host, port) = ParseAddress(server);
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
            Stream carried = client.GetStream();
            if (over == SipralTransport.Tls)
            {
                var tls = new SslStream(carried, leaveInnerStreamOpen: false);
                var verdict = new SipralTlsTrust.Verdict();
                var options = new SslClientAuthenticationOptions { TargetHost = _givenTlsServerName ?? host };
                StreamTrust(destination).Apply(options, verdict);
                try
                {
                    tls.AuthenticateAsClient(options);
                }
                catch (Exception handshake) when (handshake is AuthenticationException or IOException)
                {
                    tls.Dispose();
                    client.Dispose();
                    throw Refused(verdict, handshake);
                }
                carried = tls;
            }
            stream = new SipStream
            {
                Transport = transport,
                Destination = destination,
                Client = client,
                Stream = carried,
            };
        }
        catch (Exception ex) when (ex is SocketException or AggregateException or FormatException
                                       or ArgumentException or IOException or SignallingRefusedException)
        {
            lock (_streamLock)
            {
                _streamsOpening.Remove(destination);
            }
            var socket = ex as SocketException ?? ex.InnerException as SocketException;
            var refused = ex as SignallingRefusedException ?? (socket is not null ? Refused(socket) : null);
            var error = refused?.Error ?? SipralTransportError.Other;
            var target = server == destination ? destination : $"{server} (for {destination})";
            var said = refused?.Message ?? ex.Message;
            SayNoStream(transport, error,
                $"to {target} {Verdict(error)}{(said.Length == 0 ? "" : ": " + said)}", over,
                refused?.Tls ?? SipralTlsFailure.None);
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
                    Handle, transport, (uint)(bound ?? over), local, (nuint)local.Length,
                    remote, (nuint)remote.Length, NowMs, out _),
                "sipral_stack_transport_bind");
        }
        catch (Exception ex) when (ex is SipralException or ObjectDisposedException)
        {
            LoseSipStream(transport, tell: false);
            SayNoStream(transport, SipralTransportError.Other,
                $"to {destination} connected, and the stack would not bind it: {ex.Message}");
            return;
        }
        ReadSipStream(stream);
    }

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

    // A failed write loses the connection.
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

    // what: the rest of a sentence starting with "TCP" or "TLS", for the
    // event's detail.
    private void SayNoStream(uint transport, SipralTransportError error, string what,
        SipralTransport over = SipralTransport.Tcp, SipralTlsFailure tls = SipralTlsFailure.None)
    {
        var detail = Encoding.UTF8.GetBytes(Sentence((over == SipralTransport.Tls ? "TLS " : "TCP ") + what));
        var pinned = GCHandle.Alloc(detail, GCHandleType.Pinned);
        try
        {
            var failure = SipralTransportFailure.Sized();
            failure.Transport = transport;
            failure.Error = (uint)error;
            failure.Tls = (uint)tls;
            failure.Detail = pinned.AddrOfPinnedObject();
            failure.DetailLen = (nuint)detail.Length;
            SipralErrors.Call(() => NativeMethods.sipral_stack_transport_failed_with(Handle, in failure, NowMs),
                "sipral_stack_transport_failed_with");
        }
        catch (Exception ex) when (ex is SipralException or ObjectDisposedException)
        {
            // nothing was waiting any more, or the stack is going away
        }
        finally
        {
            pinned.Free();
        }
    }

    private static string Verdict(SipralTransportError error) => error switch
    {
        SipralTransportError.ConnectionRefused => "refused",
        SipralTransportError.TimedOut => "timed out",
        SipralTransportError.Unreachable => "unreachable",
        SipralTransportError.ConnectionReset => "reset",
        SipralTransportError.Closed => "closed",
        _ => "failed",
    };

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
