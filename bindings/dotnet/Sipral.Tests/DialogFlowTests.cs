// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// A server reached at one address whose answer names another in its
/// <c>Contact</c> -- the lab's Asterisk, published on a mapped port and
/// naming the port it listens on inside its container, or any registrar
/// behind a NAT. The dialog's requests have to stay on the path the
/// INVITE took: the ACK did all along, and the BYE has to follow it
/// rather than go to an address nothing answers on. The .NET counterpart
/// of <c>bindings/swift/Tests/SipralTests/DialogFlowTests.swift</c>.
/// </summary>
public sealed class DialogFlowTests : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    private readonly Socket _server = MakeSocket();
    private readonly Socket _named = MakeSocket();
    private readonly Socket _audio = MakeSocket();
    private readonly SipralStack _stack = new();

    private static Socket MakeSocket()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        socket.Blocking = false;
        return socket;
    }

    private static string AddressOf(Socket socket)
    {
        var endpoint = (IPEndPoint)socket.LocalEndPoint!;
        return $"{endpoint.Address}:{endpoint.Port}";
    }

    public void Dispose()
    {
        _stack.Dispose();
        _server.Dispose();
        _named.Dispose();
        _audio.Dispose();
    }

    [Fact]
    public async Task EveryRequestOfTheDialogTakesThePathTheInviteTook()
    {
        var serverAddress = AddressOf(_server);
        var namedAddress = AddressOf(_named);
        var audioPort = ((IPEndPoint)_audio.LocalEndPoint!).Port;

        var account = _stack.AddAccount("sip:alice@sipral.invalid", registrarAddress: serverAddress);
        var call = _stack.PlaceCall(account, $"sip:bob@{serverAddress}");

        var arrived = await RequestsUntilAsync(_server, "INVITE", Timeout);
        var invite = Array.Find(arrived, m => m.StartsWith("INVITE ", StringComparison.Ordinal));
        Assert.NotNull(invite);

        var sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
            + $"m=audio {audioPort} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        var toHeader = Header("To", invite!) ?? "To: <sip:bob@sipral.invalid>";
        var lines = new System.Collections.Generic.List<string> { "SIP/2.0 200 OK" };
        foreach (var name in new[] { "Via", "From", "Call-ID", "CSeq" })
        {
            var header = Header(name, invite!);
            if (header is not null)
            {
                lines.Add(header);
            }
        }
        lines.Add($"{toHeader};tag=far");
        lines.Add($"Contact: <sip:bob@{namedAddress}>");
        lines.Add("Content-Type: application/sdp");
        lines.Add($"Content-Length: {Encoding.UTF8.GetByteCount(sdp)}");
        lines.Add("");
        lines.Add(sdp);
        var answer = string.Join("\r\n", lines);

        var via = Header("Via", invite!) ?? "";
        var viaPort = int.Parse(Regex.Match(via, @"127\.0\.0\.1:(\d+)").Groups[1].Value);
        var answerBytes = Encoding.UTF8.GetBytes(answer);
        _server.SendTo(answerBytes, new IPEndPoint(IPAddress.Loopback, viaPort));

        var confirmed = await FirstMatchingAsync(call.Events, e => e.Kind == SipralEventKind.CallConfirmed, Timeout);
        Assert.NotNull(confirmed);
        call.Hangup();

        var atServer = await RequestsUntilAsync(_server, "BYE", Timeout);
        var atNamed = await RequestsUntilAsync(_named, "BYE", TimeSpan.FromMilliseconds(500));
        Assert.Contains(atServer, m => m.StartsWith("ACK ", StringComparison.Ordinal));
        Assert.Contains(atServer, m => m.StartsWith("BYE ", StringComparison.Ordinal));
        Assert.DoesNotContain(atNamed, m => m.StartsWith("BYE ", StringComparison.Ordinal));

        call.Close();
    }

    private static string? Header(string name, string message)
    {
        foreach (var line in message.Split("\r\n"))
        {
            if (line.StartsWith(name + ":", StringComparison.Ordinal))
            {
                return line;
            }
        }
        return null;
    }

    private static async Task<string?> FirstMatchingAsync(
        System.Collections.Generic.IAsyncEnumerable<SipralEventArgs> source, Func<SipralEventArgs, bool> predicate, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            await foreach (var item in source.WithCancellation(cts.Token))
            {
                if (predicate(item))
                {
                    return item.Kind.ToString();
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        return null;
    }

    private static async Task<string[]> RequestsUntilAsync(Socket socket, string method, TimeSpan timeout)
    {
        var seen = new System.Collections.Generic.List<string>();
        var buffer = new byte[65536];
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (socket.Available > 0)
            {
                var read = socket.Receive(buffer);
                var text = Encoding.UTF8.GetString(buffer, 0, read);
                seen.Add(text);
                if (text.StartsWith(method + " ", StringComparison.Ordinal))
                {
                    return seen.ToArray();
                }
            }
            else
            {
                await Task.Delay(10);
            }
        }
        return seen.ToArray();
    }
}
