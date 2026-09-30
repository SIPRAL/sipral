// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// RFC 3261 §18.1.1 through <see cref="SipralStack"/>: a call whose answer
/// to a challenge is too large for a datagram — the .NET counterpart of
/// <c>bindings/python/tests/test_datagram_limit.py</c>. The PBX is this
/// test's own, on loopback: a UDP socket that answers every INVITE without
/// credentials with a 401 whose nonce takes the answer past 1300 bytes, and
/// — when asked for — a TCP listener on the same port that answers the INVITE
/// carrying credentials with a 486. With the listener there the stack opens
/// the connection itself and the call carries on over it; with none, or with
/// <c>streamFallback: false</c>, the call ends at once with a 513 naming the
/// limit, never hanging.
/// </summary>
public sealed class DatagramLimitTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(8);

    private static string? Header(string name, string message) =>
        message.Split("\r\n")
            .FirstOrDefault(line => line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
            ?.Split(':', 2)[1].Trim();

    private static byte[] Response(string request, string status, string extra = "")
    {
        var lines = new List<string> { $"SIP/2.0 {status}" };
        foreach (var name in new[] { "Via", "From", "To", "Call-ID", "CSeq" })
        {
            var value = Header(name, request);
            if (name == "To" && value is not null && !value.Contains(";tag="))
            {
                value += ";tag=pbx";
            }
            lines.Add($"{name}: {value}");
        }
        return Encoding.UTF8.GetBytes(string.Join("\r\n", lines) + "\r\n" + extra + "Content-Length: 0\r\n\r\n");
    }

    /// <summary>A PBX that challenges INVITEs over UDP, with a TCP listener
    /// on the same port when asked for.</summary>
    private sealed class Pbx : IDisposable
    {
        private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly TcpListener? _listener;
        private readonly object _lock = new();
        private readonly List<string> _overTcp = new();
        private readonly Thread _udpThread;
        private volatile bool _stopped;
        private int _connections;

        public Pbx(bool tcp, bool apart = false)
        {
            // a UDP socket disposed while a thread is blocked receiving on it
            // can wait for that thread on this platform, so the thread
            // wakes by itself and is let go of first
            _udp.Client.ReceiveTimeout = 50;
            var port = ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;
            Address = $"127.0.0.1:{port}";
            if (tcp)
            {
                // apart: TCP on a port of its own, as a PBX that takes UDP on
                // 5060 and TCP on 5160 has it
                _listener = new TcpListener(IPAddress.Loopback, apart ? 0 : port);
                _listener.Start();
                TcpAddress = $"127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}";
                new Thread(Accept) { IsBackground = true }.Start();
            }
            _udpThread = new Thread(ServeUdp) { IsBackground = true };
            _udpThread.Start();
        }

        public string Address { get; }

        /// <summary>Where TCP is taken, null without it.</summary>
        public string? TcpAddress { get; }

        public int Connections => Volatile.Read(ref _connections);

        public List<string> OverTcp()
        {
            lock (_lock)
            {
                return new List<string>(_overTcp);
            }
        }

        private void ServeUdp()
        {
            var nonce = new string('n', 700);
            while (!_stopped)
            {
                IPEndPoint? from = null;
                byte[] data;
                try
                {
                    data = _udp.Receive(ref from);
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                {
                    continue;
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                {
                    return;
                }
                var message = Encoding.UTF8.GetString(data);
                if (message.StartsWith("INVITE ", StringComparison.Ordinal) && Header("Authorization", message) is null)
                {
                    var challenge = $"WWW-Authenticate: Digest realm=\"asterisk\", nonce=\"{nonce}\", qop=\"auth\"\r\n";
                    _udp.Send(Response(message, "401 Unauthorized", challenge), from!);
                }
            }
        }

        private void Accept()
        {
            while (true)
            {
                TcpClient client;
                try
                {
                    client = _listener!.AcceptTcpClient();
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
                {
                    return;
                }
                Interlocked.Increment(ref _connections);
                new Thread(() => Serve(client)) { IsBackground = true }.Start();
            }
        }

        private void Serve(TcpClient client)
        {
            using var _ = client;
            var stream = client.GetStream();
            var held = string.Empty;
            var buffer = new byte[65536];
            while (true)
            {
                int read;
                try
                {
                    read = stream.Read(buffer, 0, buffer.Length);
                }
                catch (Exception ex) when (ex is System.IO.IOException or ObjectDisposedException)
                {
                    return;
                }
                if (read == 0)
                {
                    return;
                }
                held += Encoding.UTF8.GetString(buffer, 0, read);
                while (held.Contains("\r\n\r\n", StringComparison.Ordinal))
                {
                    var end = held.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                    var head = held[..end] + "\r\n";
                    var length = int.Parse(Header("Content-Length", head) ?? "0");
                    if (held.Length < end + 4 + length)
                    {
                        break;
                    }
                    held = held[(end + 4 + length)..];
                    lock (_lock)
                    {
                        _overTcp.Add(head);
                    }
                    if (head.StartsWith("INVITE ", StringComparison.Ordinal))
                    {
                        var busy = Response(head, "486 Busy Here");
                        stream.Write(busy, 0, busy.Length);
                    }
                }
            }
        }

        public void Dispose()
        {
            _stopped = true;
            _udpThread.Join();
            _udp.Dispose();
            _listener?.Stop();
        }
    }

    private static SipralStack Stack(bool streamFallback = true, string? streamServer = null) =>
        new(audio: SipralAudio.Application, streamFallback: streamFallback, streamServer: streamServer);

    private static void Place(SipralStack stack, Pbx pbx)
    {
        var account = stack.AddAccount("sip:alice@example.com", pbx.Address,
            authUser: "alice", authPassword: "open sesame",
            security: new AccountSecurity(SipralSrtp.Offered,
                new[] { "AEAD_AES_256_GCM", "AES_CM_128_HMAC_SHA1_80" }));
        stack.PlaceCall(account, "sip:bob@example.com");
    }

    private static async Task<List<SipralEventArgs>> UntilTheEnd(SipralStack stack)
    {
        var seen = new List<SipralEventArgs>();
        using var cancel = new CancellationTokenSource(Timeout);
        await foreach (var args in stack.Events.WithCancellation(cancel.Token))
        {
            seen.Add(args);
            if (args.Kind == SipralEventKind.CallEnded)
            {
                return seen;
            }
        }
        throw new TimeoutException("the call never ended");
    }

    [Fact]
    public async Task APbxListeningOnTcpGetsTheAnswerOverAConnectionTheStackOpened()
    {
        using var pbx = new Pbx(tcp: true);
        using var stack = Stack();
        Place(stack, pbx);
        var seen = await UntilTheEnd(stack);

        var wanted = seen.Where(args => args.Kind == SipralEventKind.TransportWanted)
            .Select(args => args.TransportWanted!).ToList();
        Assert.Single(wanted);
        Assert.Equal(pbx.Address, wanted[0].Destination);
        Assert.True(wanted[0].RequestBytes > 1300, $"{wanted[0].RequestBytes}");
        Assert.Equal(1300u, wanted[0].LimitBytes);

        var ended = seen[^1].CallInfo!;
        Assert.Equal(486u, ended.StatusCode);
        Assert.Equal(SipralCallEndReason.Refused, ended.EndReason);
        Assert.Equal(1, pbx.Connections);
        var invites = pbx.OverTcp().Where(m => m.StartsWith("INVITE ", StringComparison.Ordinal)).ToList();
        Assert.Single(invites);
        Assert.NotNull(Header("Authorization", invites[0]));
        Assert.StartsWith("SIP/2.0/TCP ", Header("Via", invites[0]));
        // the dialog carries on over the connection: the 486 is acknowledged
        // on it (RFC 3261 §17.1.1.3)
        var clock = Stopwatch.StartNew();
        while (!pbx.OverTcp().Any(m => m.StartsWith("ACK ", StringComparison.Ordinal)) && clock.Elapsed < TimeSpan.FromSeconds(2))
        {
            await Task.Delay(20);
        }
        Assert.Contains(pbx.OverTcp(), m => m.StartsWith("ACK ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task APbxOnUdpAloneEndsTheCallAtOnceWithTheLimitNamed()
    {
        using var pbx = new Pbx(tcp: false);
        using var stack = Stack();
        var clock = Stopwatch.StartNew();
        Place(stack, pbx);
        var seen = await UntilTheEnd(stack);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), "ended by the refusal, not by the wait");

        var lost = seen.Where(args => args.Kind == SipralEventKind.TransportFailed).ToList();
        Assert.NotEmpty(lost);
        Assert.Equal(SipralTransportError.ConnectionRefused, lost[0].TransportFailed!.Error);
        var ended = seen[^1].CallInfo!;
        Assert.Equal(SipralCallEndReason.Unreachable, ended.EndReason);
        Assert.Equal(513u, ended.StatusCode);
        Assert.Equal(513u, ended.Cause!.Sip);
        Assert.Contains("1300-byte", ended.Cause.Text);
        Assert.Contains("18.1.1", ended.Cause.Text);
    }

    [Fact]
    public async Task APbxTakingTcpOnAnotherPortIsReachedAtTheStreamServer()
    {
        using var pbx = new Pbx(tcp: true, apart: true);
        using var stack = Stack(streamServer: pbx.TcpAddress);
        Place(stack, pbx);
        var seen = await UntilTheEnd(stack);
        Assert.Equal(486u, seen[^1].CallInfo!.StatusCode);
        Assert.Equal(1, pbx.Connections);
        var invites = pbx.OverTcp().Where(m => m.StartsWith("INVITE ", StringComparison.Ordinal)).ToList();
        Assert.Single(invites);
        Assert.NotNull(Header("Authorization", invites[0]));
    }

    [Fact]
    public async Task AStackToldToOpenNoStreamEndsTheCallWithoutTrying()
    {
        using var pbx = new Pbx(tcp: true);
        using var stack = Stack(streamFallback: false);
        Place(stack, pbx);
        var seen = await UntilTheEnd(stack);
        Assert.Equal(513u, seen[^1].CallInfo!.StatusCode);
        Assert.Equal(0, pbx.Connections);
    }
}
