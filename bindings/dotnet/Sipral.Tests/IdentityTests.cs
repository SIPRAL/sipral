// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Generic;
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
/// Caller identity, end causes, redirection and account privacy, against a
/// plain UDP far end that writes every header.
/// </summary>
public sealed class IdentityTests : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    private const string Asserting =
        "P-Asserted-Identity: \"Bob Jones\" <tel:+15551234567;verstat=TN-Validation-Passed>\r\n"
        + "Diversion: <sip:desk@example.com>;reason=no-answer, <sip:front@example.com>;reason=unconditional\r\n"
        + "History-Info: <sip:front@example.com>;index=1\r\n"
        + "Privacy: id\r\n"
        + "Answer-Mode: Auto;require\r\n"
        + "Alert-Info: <urn:alert:source:external>\r\n";

    private readonly Socket _far = MakeSocket();
    private readonly Socket _audio = MakeSocket();
    private readonly SipralStack _stack = new(audio: SipralAudio.Application);

    private static Socket MakeSocket()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        socket.Blocking = false;
        return socket;
    }

    private string FarAddress => SipralStack.FormatAddress((IPEndPoint)_far.LocalEndPoint!);

    public void Dispose()
    {
        _stack.Dispose();
        _far.Dispose();
        _audio.Dispose();
    }

    private string Sdp() =>
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
        + $"m=audio {((IPEndPoint)_audio.LocalEndPoint!).Port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";

    private string Invite(string extra = "")
    {
        var body = Sdp();
        var to = _stack.BindAddress;
        return $"INVITE sip:bob@{to} SIP/2.0\r\n"
            + $"Via: SIP/2.0/UDP {FarAddress};branch=z9hG4bK-far-1\r\n"
            + "Max-Forwards: 70\r\n"
            + $"From: <sip:caller@{FarAddress}>;tag=far\r\n"
            + $"To: <sip:bob@{to}>\r\n"
            + "Call-ID: identity-1@far\r\n"
            + "CSeq: 1 INVITE\r\n"
            + $"Contact: <sip:caller@{FarAddress}>\r\n"
            + extra
            + "Content-Type: application/sdp\r\n"
            + $"Content-Length: {Encoding.UTF8.GetByteCount(body)}\r\n\r\n{body}";
    }

    private string Cancel(string extra)
    {
        var to = _stack.BindAddress;
        return $"CANCEL sip:bob@{to} SIP/2.0\r\n"
            + $"Via: SIP/2.0/UDP {FarAddress};branch=z9hG4bK-far-1\r\n"
            + "Max-Forwards: 70\r\n"
            + $"From: <sip:caller@{FarAddress}>;tag=far\r\n"
            + $"To: <sip:bob@{to}>\r\n"
            + "Call-ID: identity-1@far\r\n"
            + "CSeq: 1 CANCEL\r\n"
            + extra
            + "Content-Length: 0\r\n\r\n";
    }

    private void Send(string text, string to)
    {
        var (host, port) = SipralStack.ParseAddress(to);
        _far.SendTo(Encoding.UTF8.GetBytes(text), new IPEndPoint(IPAddress.Parse(host), port));
    }

    private async Task<string> ReceiveAsync(string starts)
    {
        var buffer = new byte[65536];
        var deadline = DateTime.UtcNow + Timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (_far.Available > 0)
            {
                var text = Encoding.UTF8.GetString(buffer, 0, _far.Receive(buffer));
                if (text.StartsWith(starts, StringComparison.Ordinal))
                {
                    return text;
                }
            }
            else
            {
                await Task.Delay(10);
            }
        }
        throw new Xunit.Sdk.XunitException($"nothing starting {starts} arrived");
    }

    private static string? Header(string name, string message)
    {
        foreach (var line in message.Split("\r\n"))
        {
            if (line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
            {
                return line[(name.Length + 1)..].Trim();
            }
        }
        return null;
    }

    private static async Task<SipralEventArgs> NextAsync(IAsyncEnumerable<SipralEventArgs> events, SipralEventKind kind)
    {
        using var cts = new CancellationTokenSource(Timeout);
        await foreach (var e in events.WithCancellation(cts.Token))
        {
            if (e.Kind == kind)
            {
                return e;
            }
        }
        throw new Xunit.Sdk.XunitException($"no {kind}");
    }

    [Fact]
    public async Task ATrustedPeerIsBelievedAndEveryListIsRead()
    {
        _stack.AddAccount("sip:bob@sipral.invalid", registrarAddress: FarAddress, trustedPeers: new[] { "127.0.0.1" });
        Send(Invite(Asserting), _stack.BindAddress);
        var incoming = await NextAsync(_stack.Events, SipralEventKind.IncomingCall);

        var identity = incoming.CallInfo!.Identity;
        Assert.True(identity.Trusted);
        Assert.Equal("tel:+15551234567;verstat=TN-Validation-Passed", identity.AssertedUri);
        Assert.Equal("Bob Jones", identity.AssertedDisplay);
        Assert.Equal(SipralVerstat.Passed, identity.Verstat);
        Assert.Equal(global::Sipral.Sipral.PrivacyId, identity.Privacy);
        Assert.Equal("sip:desk@example.com", identity.DivertedFrom);
        Assert.Equal("no-answer", identity.DiversionReason);
        Assert.Equal((2u, 1u), (identity.DiversionCount, identity.HistoryCount));

        var answering = incoming.CallInfo.Answering;
        Assert.Equal(SipralAnswerMode.Auto, answering.AnswerMode);
        Assert.True(answering.AnswerModeRequired);
        Assert.Equal(0ul, answering.AnswerAfterMs);
        Assert.Equal(SipralRingSource.External, answering.RingSource);
        Assert.Equal("urn:alert:source:external", answering.AlertInfo);
        Assert.Null(incoming.CallInfo.Cause);

        Assert.Equal(
            new[] { "sip:desk@example.com", "sip:front@example.com" },
            _stack.CallIdentity(incoming.Call, SipralIdentityText.Diversion));
        Assert.Equal(
            new[] { "no-answer", "unconditional" },
            _stack.CallIdentity(incoming.Call, SipralIdentityText.DiversionReason));
        Assert.Equal(new[] { "sip:front@example.com" }, _stack.CallIdentity(incoming.Call, SipralIdentityText.History));
        _stack.RejectCall(incoming);
    }

    [Fact]
    public async Task APeerTheAccountDoesNotTrustAssertsNothing()
    {
        _stack.AddAccount("sip:bob@sipral.invalid", registrarAddress: FarAddress);
        Send(Invite(Asserting), _stack.BindAddress);
        var incoming = await NextAsync(_stack.Events, SipralEventKind.IncomingCall);
        var identity = incoming.CallInfo!.Identity;
        Assert.False(identity.Trusted);
        Assert.Null(identity.AssertedUri);
        Assert.Equal(SipralVerstat.None, identity.Verstat);
        Assert.Equal("sip:desk@example.com", identity.DivertedFrom);
        Assert.Empty(_stack.CallIdentity(incoming.Call, SipralIdentityText.Asserted));
        _stack.RejectCall(incoming);
    }

    [Fact]
    public async Task ACallRedirectedIsAnswered3xxWithWhereToGoAndWhy()
    {
        _stack.AddAccount("sip:bob@sipral.invalid", registrarAddress: FarAddress);
        Send(Invite(), _stack.BindAddress);
        var incoming = await NextAsync(_stack.Events, SipralEventKind.IncomingCall);

        var refused = Assert.Throws<SipralException>(
            () => _stack.RedirectCall(incoming, new[] { "sip:carol@example.com" }, statusCode: 486));
        Assert.Equal(SipralStatus.InvalidArgument, refused.Status);

        _stack.RedirectCall(incoming, new[] { "sip:carol@example.com", "tel:+15550001111" }, reason: "no-answer");
        var answer = await ReceiveAsync("SIP/2.0 302 ");
        Assert.Equal("<sip:carol@example.com>, <tel:+15550001111>", Header("Contact", answer));
        Assert.Contains(";reason=no-answer", Header("Diversion", answer));
    }

    [Fact]
    public async Task ACancelForACallAnsweredElsewhereIsNotAMissedCall()
    {
        _stack.AddAccount("sip:bob@sipral.invalid", registrarAddress: FarAddress);
        Send(Invite(), _stack.BindAddress);
        await NextAsync(_stack.Events, SipralEventKind.IncomingCall);
        Send(Cancel("Reason: SIP ;cause=200 ;text=\"Call completed elsewhere\"\r\n"), _stack.BindAddress);
        var ended = await NextAsync(_stack.Events, SipralEventKind.CallEnded);
        Assert.Equal(new SipralEndCause(200, 0, "Call completed elsewhere"), ended.CallInfo!.Cause);
    }

    [Fact]
    public async Task AHangupForAReasonWritesItOnTheBye()
    {
        var account = _stack.AddAccount("sip:alice@sipral.invalid", registrarAddress: FarAddress);
        var call = _stack.PlaceCall(account, $"sip:bob@{FarAddress}");
        try
        {
            var invite = await ReceiveAsync("INVITE ");
            var body = Sdp();
            var lines = new List<string> { "SIP/2.0 200 OK" };
            foreach (var name in new[] { "Via", "From", "Call-ID", "CSeq" })
            {
                lines.Add($"{name}: {Header(name, invite)}");
            }
            lines.Add($"To: {Header("To", invite)};tag=far");
            lines.Add($"Contact: <sip:bob@{FarAddress}>");
            lines.Add("Content-Type: application/sdp");
            lines.Add($"Content-Length: {Encoding.UTF8.GetByteCount(body)}");
            lines.Add("");
            lines.Add(body);
            var viaPort = Regex.Match(Header("Via", invite)!, @"127\.0\.0\.1:(\d+)").Groups[1].Value;
            Send(string.Join("\r\n", lines), $"127.0.0.1:{viaPort}");
            Assert.True(await call.WaitForConfirmedAsync(new CancellationTokenSource(Timeout).Token));

            call.HangupFor(q850Cause: 16, text: "Normal call clearing");
            var bye = await ReceiveAsync("BYE ");
            Assert.Equal("Q.850;cause=16;text=\"Normal call clearing\"", Header("Reason", bye));
        }
        finally
        {
            call.Close();
        }
    }

    [Fact]
    public async Task AnAccountSaysItsSessionTimerItsAnonymityAndWhomItTrusts()
    {
        var account = _stack.AddAccount(
            "sip:alice@sipral.invalid", registrarAddress: FarAddress,
            sessionTimer: SipralSessionTimer.Interval, sessionIntervalSeconds: 120,
            privacy: global::Sipral.Sipral.PrivacyId, trustedPeers: new[] { "127.0.0.1" });
        var call = _stack.PlaceCall(account, $"sip:bob@{FarAddress}");
        try
        {
            var invite = await ReceiveAsync("INVITE ");
            Assert.Equal("120", Header("Session-Expires", invite));
            Assert.Contains("anonymous@anonymous.invalid", Header("From", invite));
            Assert.Equal("id", Header("Privacy", invite));
            Assert.Equal("<sip:alice@sipral.invalid>", Header("P-Asserted-Identity", invite));
        }
        finally
        {
            call.Close();
        }
    }

    [Fact]
    public void AnAccountOptionOutOfRangeIsRefused()
    {
        var shortTimer = Assert.Throws<SipralException>(() => _stack.AddAccount(
            "sip:alice@sipral.invalid", registrarAddress: FarAddress,
            sessionTimer: SipralSessionTimer.Interval, sessionIntervalSeconds: 30));
        Assert.Equal(SipralStatus.InvalidArgument, shortTimer.Status);
        var namedPeer = Assert.Throws<SipralException>(() => _stack.AddAccount(
            "sip:alice@sipral.invalid", registrarAddress: FarAddress, trustedPeers: new[] { "proxy.example.com" }));
        Assert.Equal(SipralStatus.InvalidArgument, namedPeer.Status);
    }
}
