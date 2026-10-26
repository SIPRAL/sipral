// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
/// <see cref="SipralStack.SetMessageHook"/>: a header added to an INVITE on
/// its way out, a response stopped on its way in, and a hook that throws.
/// A loopback PBX on UDP answers every INVITE 486 and writes down what it
/// received.
/// </summary>
public sealed class MessageHookTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(8);

    private static string? Header(string name, string message) =>
        message.Split("\r\n")
            .Select(line => line.Split(':', 2))
            .FirstOrDefault(field => field.Length == 2 && field[0].Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
            ?[1].Trim();

    private static byte[] WithHeader(byte[] message, string line)
    {
        var text = Encoding.UTF8.GetString(message);
        var end = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        return Encoding.UTF8.GetBytes(text[..end] + "\r\n" + line + text[end..]);
    }

    private sealed class Pbx : IDisposable
    {
        private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly Thread _thread;
        private volatile bool _stopped;

        public Pbx()
        {
            _udp.Client.ReceiveTimeout = 50;
            Address = $"127.0.0.1:{((IPEndPoint)_udp.Client.LocalEndPoint!).Port}";
            _thread = new Thread(Serve) { IsBackground = true };
            _thread.Start();
        }

        public string Address { get; }

        public ConcurrentQueue<string> Received { get; } = new();

        private void Serve()
        {
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
                Received.Enqueue(message);
                if (!message.StartsWith("INVITE ", StringComparison.Ordinal))
                {
                    continue;
                }
                var lines = new List<string> { "SIP/2.0 486 Busy Here" };
                foreach (var name in new[] { "Via", "From", "To", "Call-ID", "CSeq" })
                {
                    var value = Header(name, message);
                    if (name == "To" && value is not null && !value.Contains(";tag="))
                    {
                        value += ";tag=pbx";
                    }
                    lines.Add($"{name}: {value}");
                }
                _udp.Send(Encoding.UTF8.GetBytes(string.Join("\r\n", lines) + "\r\nContent-Length: 0\r\n\r\n"), from!);
            }
        }

        public void Dispose()
        {
            _stopped = true;
            _thread.Join();
            _udp.Dispose();
        }
    }

    private static SipralStack Stack() => new(audio: SipralAudio.Application);

    private static void Place(SipralStack stack, Pbx pbx)
    {
        var account = stack.AddAccount("sip:alice@example.com", pbx.Address);
        stack.PlaceCall(account, "sip:bob@example.com");
    }

    private static async Task<SipralEventArgs?> Ended(SipralStack stack, TimeSpan within)
    {
        using var cancel = new CancellationTokenSource(within);
        try
        {
            await foreach (var args in stack.Events.WithCancellation(cancel.Token))
            {
                if (args.Kind == SipralEventKind.CallEnded)
                {
                    return args;
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        return null;
    }

    [Fact]
    public async Task AHeaderAddedToAnOutgoingInviteReachesThePbx()
    {
        using var pbx = new Pbx();
        using var stack = Stack();
        var remotes = new ConcurrentQueue<string>();
        stack.SetMessageHook((outgoing, message, remote) =>
        {
            remotes.Enqueue(remote);
            return outgoing && Encoding.UTF8.GetString(message).StartsWith("INVITE ", StringComparison.Ordinal)
                ? SipralMessageVerdict.Replace(WithHeader(message, "X-Tenant: blue"))
                : SipralMessageVerdict.Keep;
        });
        Place(stack, pbx);
        var ended = await Ended(stack, Timeout);
        Assert.Equal(486u, ended!.CallInfo!.StatusCode);
        var invite = Assert.Single(pbx.Received, m => m.StartsWith("INVITE ", StringComparison.Ordinal));
        Assert.Equal("blue", Header("X-Tenant", invite));
        Assert.All(remotes, remote => Assert.Equal(pbx.Address, remote));
    }

    [Fact]
    public async Task AnIncomingResponseTheHookDropsIsNotRead()
    {
        using var pbx = new Pbx();
        using var stack = Stack();
        var dropped = 0;
        stack.SetMessageHook((outgoing, message, _) =>
        {
            if (!outgoing && Encoding.UTF8.GetString(message).StartsWith("SIP/2.0 486", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref dropped);
                return SipralMessageVerdict.Drop;
            }
            return SipralMessageVerdict.Keep;
        });
        Place(stack, pbx);
        Assert.Null(await Ended(stack, TimeSpan.FromSeconds(1.5)));
        Assert.True(Volatile.Read(ref dropped) > 0);

        stack.SetMessageHook(null);
        var ended = await Ended(stack, Timeout);
        Assert.Equal(486u, ended!.CallInfo!.StatusCode);
    }

    [Fact]
    public async Task AHookThatThrowsKeepsTheMessage()
    {
        using var pbx = new Pbx();
        using var stack = Stack();
        stack.SetMessageHook((_, _, _) => throw new InvalidOperationException("a mistake in the application's hook"));
        Place(stack, pbx);
        var ended = await Ended(stack, Timeout);
        Assert.Equal(486u, ended!.CallInfo!.StatusCode);
        Assert.Single(pbx.Received, m => m.StartsWith("INVITE ", StringComparison.Ordinal));
    }
}
