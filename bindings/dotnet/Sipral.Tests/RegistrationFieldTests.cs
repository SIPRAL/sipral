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
/// An account's RFC 5626 instance id and its own header fields
/// (<see cref="SipralStack.AddAccount"/>'s <c>instanceId</c> and
/// <c>headers</c>) on every REGISTER: a push proxy (RFC 8599) refuses one
/// whose <c>Contact</c> has no <c>+sip.instance</c>. A loopback registrar
/// challenges the first REGISTER, grants the answer for a few seconds so the
/// refresh comes soon, and writes down every REGISTER once, a retransmission
/// answered as the request it repeats.
/// </summary>
public sealed class RegistrationFieldTests
{
    private const string Urn = "urn:uuid:f81d4fae-7ced-11d0-a765-00a0c91e6bf6";

    private static string? Header(string name, string message) =>
        message.Split("\r\n").Skip(1)
            .Select(line => line.Split(':', 2))
            .FirstOrDefault(field => field.Length == 2 && field[0].Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
            ?[1].Trim();

    private sealed class Registrar : IDisposable
    {
        private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly Thread _thread;
        private readonly HashSet<string> _seen = new();
        private volatile bool _stopped;

        public Registrar()
        {
            _udp.Client.ReceiveTimeout = 50;
            Address = $"127.0.0.1:{((IPEndPoint)_udp.Client.LocalEndPoint!).Port}";
            _thread = new Thread(Serve) { IsBackground = true };
            _thread.Start();
        }

        public string Address { get; }

        public ConcurrentQueue<string> Registers { get; } = new();

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
                if (!message.StartsWith("REGISTER ", StringComparison.Ordinal))
                {
                    continue;
                }
                // a stack slowed down retransmits before the answer lands
                if (_seen.Add(Header("CSeq", message) ?? string.Empty))
                {
                    Registers.Enqueue(message);
                }
                var lines = new List<string>();
                foreach (var name in new[] { "Via", "From", "To", "Call-ID", "CSeq" })
                {
                    var value = Header(name, message);
                    if (name == "To" && value is not null && !value.Contains(";tag="))
                    {
                        value += ";tag=registrar";
                    }
                    lines.Add($"{name}: {value}");
                }
                string status;
                if (Header("Authorization", message) is null && Registers.Count == 1)
                {
                    status = "401 Unauthorized";
                    lines.Add("WWW-Authenticate: Digest realm=\"example.com\", nonce=\"n1\", qop=\"auth\"");
                }
                else
                {
                    status = "200 OK";
                    var expires = Header("Expires", message) == "0" ? "0" : "4";
                    lines.Add($"Contact: {Header("Contact", message)};expires={expires}");
                }
                var answer = $"SIP/2.0 {status}\r\n" + string.Join("\r\n", lines) + "\r\nContent-Length: 0\r\n\r\n";
                _udp.Send(Encoding.UTF8.GetBytes(answer), from!);
            }
        }

        public void Dispose()
        {
            _stopped = true;
            _thread.Join();
            _udp.Dispose();
        }
    }

    private static async Task Until(Registrar registrar, int count, TimeSpan within)
    {
        var deadline = DateTime.UtcNow + within;
        while (registrar.Registers.Count < count && DateTime.UtcNow < deadline)
        {
            await Task.Delay(50);
        }
    }

    [Fact]
    public async Task TheInstanceAndTheFieldsRideOnTheFirstRegisterTheAnswerTheRefreshAndTheGoodbye()
    {
        using var registrar = new Registrar();
        using var stack = new SipralStack(audio: SipralAudio.Application);
        var account = stack.AddAccount(
            "sip:alice@example.com", registrar.Address, registrar: "sip:example.com",
            authUser: "alice", authPassword: "open sesame",
            instanceId: Urn, headers: new[] { ("X-Push-Key", "k-17") });
        account.Register();
        await Until(registrar, 3, TimeSpan.FromSeconds(10));
        Assert.True(registrar.Registers.Count >= 3, string.Join("\n---\n", registrar.Registers));
        account.Unregister();
        await Until(registrar, 4, TimeSpan.FromSeconds(5));

        var registers = registrar.Registers.ToArray();
        Assert.True(registers.Length >= 4, string.Join("\n---\n", registers));
        Assert.Null(Header("Authorization", registers[0]));
        Assert.NotNull(Header("Authorization", registers[1]));
        Assert.Equal("0", Header("Expires", registers[3]));
        foreach (var register in registers.Take(4))
        {
            Assert.Equal("k-17", Header("X-Push-Key", register));
            Assert.Contains($"+sip.instance=\"<{Urn}>\"", Header("Contact", register) ?? string.Empty);
        }
    }

    [Fact]
    public void AFieldTheStackWritesItselfIsRefused()
    {
        using var stack = new SipralStack(audio: SipralAudio.Application);
        var refused = Assert.Throws<SipralException>(() => stack.AddAccount(
            "sip:alice@example.com", "127.0.0.1:5060", registrar: "sip:example.com",
            headers: new[] { ("Expires", "60") }));
        Assert.Equal(SipralStatus.InvalidArgument, refused.Status);
    }
}
