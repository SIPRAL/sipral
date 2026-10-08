// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
/// RFC 3261 §18.1.1: an authenticated INVITE too large for a datagram. The
/// loopback PBX challenges with a nonce that pushes the retry past 1300
/// bytes, optionally with a TCP listener answering 486. With TCP the call
/// moves to it; without, or with <c>streamFallback: false</c>, it ends at
/// once with a 513.
/// </summary>
public sealed class DatagramLimitTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(8);

    /// <summary>RFC 3261 §7.3.3 compact names: an oversized request is
    /// compacted before it is measured.</summary>
    private static readonly Dictionary<string, string> Compact = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Via"] = "v", ["From"] = "f", ["To"] = "t", ["Call-ID"] = "i", ["Content-Length"] = "l",
    };

    private static string? Header(string name, string message)
    {
        var compact = Compact.GetValueOrDefault(name, name);
        return message.Split("\r\n")
            .Select(line => line.Split(':', 2))
            .FirstOrDefault(field => field.Length == 2
                && (field[0].Trim().Equals(name, StringComparison.OrdinalIgnoreCase)
                    || field[0].Trim().Equals(compact, StringComparison.OrdinalIgnoreCase)))
            ?[1].Trim();
    }

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
        private readonly UdpClient _udp;
        private readonly TcpListener? _listener;
        private readonly object _lock = new();
        private readonly List<string> _overTcp = new();
        private readonly List<(string Message, int Bytes)> _answeredOverUdp = new();
        private readonly Thread _udpThread;
        private volatile bool _stopped;
        private int _connections;
        private int _closedByTheStack;

        public Pbx(bool tcp, bool apart = false)
        {
            if (tcp && apart)
            {
                // apart: TCP on its own port, like UDP 5060 and TCP 5160
                _udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
                _listener = new TcpListener(IPAddress.Loopback, 0);
                _listener.Start();
            }
            else
            {
                (_udp, _listener) = SamePort.Take(tcp);
            }
            // disposing a UDP socket can wait for a blocked receiver here,
            // so the receiver wakes on its own
            _udp.Client.ReceiveTimeout = 50;
            var port = ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;
            Address = $"127.0.0.1:{port}";
            if (_listener is not null)
            {
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

        /// <summary>How many of those connections the stack closed.</summary>
        public int ClosedByTheStack => Volatile.Read(ref _closedByTheStack);

        /// <summary>Every INVITE carrying credentials that arrived over UDP,
        /// and its size.</summary>
        public List<(string Message, int Bytes)> AnsweredOverUdp()
        {
            lock (_lock)
            {
                return new List<(string Message, int Bytes)>(_answeredOverUdp);
            }
        }

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
                else if (message.StartsWith("INVITE ", StringComparison.Ordinal))
                {
                    lock (_lock)
                    {
                        _answeredOverUdp.Add((message, data.Length));
                    }
                    _udp.Send(Response(message, "486 Busy Here"), from!);
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
                    Interlocked.Increment(ref _closedByTheStack);
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
        // the 486 is acknowledged on the connection (RFC 3261 §17.1.1.3)
        var clock = Stopwatch.StartNew();
        while (!pbx.OverTcp().Any(m => m.StartsWith("ACK ", StringComparison.Ordinal)) && clock.Elapsed < TimeSpan.FromSeconds(2))
        {
            await Task.Delay(20);
        }
        Assert.Contains(pbx.OverTcp(), m => m.StartsWith("ACK ", StringComparison.Ordinal));
    }

    /// <summary>A deliberate deviation from §18.1.1: no stream is coming, and
    /// the stack was told the server takes a large request over UDP.</summary>
    [Fact]
    public async Task APbxOnUdpAloneTakesTheRequestOverUdpUpToTheStacksLimit()
    {
        using var pbx = new Pbx(tcp: false);
        using var stack = new SipralStack(audio: SipralAudio.Application, pathMtu: 1500, datagramWithoutStreamBytes: 4000);
        Place(stack, pbx);
        var seen = await UntilTheEnd(stack);
        Assert.Equal(486u, seen[^1].CallInfo!.StatusCode);
        var (invite, bytes) = Assert.Single(pbx.AnsweredOverUdp());
        Assert.NotNull(Header("Authorization", invite));
        Assert.True(bytes > 1300, $"{bytes}");
        var diagnostics = stack.DiagnosticsJson();
        Assert.Contains("transport.kept.datagram", diagnostics);
        // written compact first, and still over the line
        Assert.Contains("transport.compacted.size", diagnostics);
    }

    [Fact]
    public void ALimitPastOneDatagramAndAPathUnderTheIpv4FloorAreRefused()
    {
        var past = Assert.Throws<SipralException>(
            () => new SipralStack(audio: SipralAudio.Application, datagramWithoutStreamBytes: 65508));
        Assert.Equal(SipralStatus.InvalidArgument, past.Status);
        var under = Assert.Throws<SipralException>(() => new SipralStack(audio: SipralAudio.Application, pathMtu: 575));
        Assert.Equal(SipralStatus.InvalidArgument, under.Status);
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
        // where the connection was going and what became of it, for a log
        Assert.StartsWith($"TCP to {pbx.Address} refused", lost[0].TransportFailed!.Detail);
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
        var lost = seen.First(args => args.Kind == SipralEventKind.TransportFailed);
        Assert.Equal($"TCP to {pbx.Address} not tried: streamFallback is off", lost.TransportFailed!.Detail);
    }

    [Fact]
    public async Task AConnectionTheStackLetGoOfIsClosedHereToo()
    {
        // RFC 5626 §4.4.1: a retired stream's socket must be closed here, or
        // it would stand in for the next connection
        using var pbx = new Pbx(tcp: true);
        using var stack = Stack();
        Place(stack, pbx);
        await UntilTheEnd(stack);
        Assert.Equal(1, pbx.Connections);
        Assert.Equal(0, pbx.ClosedByTheStack);

        stack.NoteStreamLetGo(SipralStack.FirstStream);
        var clock = Stopwatch.StartNew();
        while (pbx.ClosedByTheStack == 0 && clock.Elapsed < TimeSpan.FromSeconds(3))
        {
            await Task.Delay(20);
        }
        Assert.Equal(1, pbx.ClosedByTheStack);
    }
}
