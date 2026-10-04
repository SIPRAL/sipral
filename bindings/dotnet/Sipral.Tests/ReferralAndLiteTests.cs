// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
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
/// A REFER outside any dialog, and ICE-lite, through this layer — the .NET
/// counterpart of <c>bindings/python/tests/test_referral.py</c>.
///
/// The referrer is a plain UDP socket writing RFC 3515 §4.1's own REFER by
/// hand: a switchboard asking Bob's line to ring Carol, a second stack that
/// answers. The lite case is two stacks: Alice requires ICE, Bob is
/// <see cref="SipralIce.Lite"/>, both take the one pair and audio crosses it
/// both ways.
/// </summary>
public sealed class ReferralAndLiteTests : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    private readonly Socket _referrer = MakeSocket();
    private readonly List<IDisposable> _owned = new();

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
        foreach (var owned in Enumerable.Reverse(_owned))
        {
            owned.Dispose();
        }
        _referrer.Dispose();
    }

    private T Own<T>(T disposable) where T : IDisposable
    {
        _owned.Add(disposable);
        return disposable;
    }

    private static byte[] Refer(string stackAddress, string referrerAddress, string target) =>
        Encoding.UTF8.GetBytes(
            $"REFER sip:bob@{stackAddress} SIP/2.0\r\n" +
            $"Via: SIP/2.0/UDP {referrerAddress};branch=z9hG4bK-click-to-dial\r\n" +
            "Max-Forwards: 70\r\n" +
            "From: <sip:switchboard@sipral.invalid>;tag=switchboard\r\n" +
            "To: <sip:bob@sipral.invalid>\r\n" +
            "Call-ID: click-to-dial@sipral.invalid\r\n" +
            "CSeq: 1 REFER\r\n" +
            $"Contact: <sip:switchboard@{referrerAddress}>\r\n" +
            $"Refer-To: <{target}>\r\n" +
            "Referred-By: <sip:switchboard@sipral.invalid>\r\n" +
            "Content-Length: 0\r\n\r\n");

    private static string? Header(string name, string message) =>
        message.Split("\r\n")
            .Where(line => line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
            .Select(line => line[(name.Length + 1)..].Trim())
            .FirstOrDefault();

    /// <summary>The switchboard's 200 to a NOTIFY the stack sent it.</summary>
    private static byte[] OkTo(string request)
    {
        var lines = new List<string> { "SIP/2.0 200 OK" };
        foreach (var name in new[] { "Via", "From", "To", "Call-ID", "CSeq" })
        {
            var value = Header(name, request);
            if (value is not null)
            {
                lines.Add($"{name}: {value}");
            }
        }
        lines.Add("Content-Length: 0");
        return Encoding.UTF8.GetBytes(string.Join("\r\n", lines) + "\r\n\r\n");
    }

    /// <summary>What reaches the referrer, each NOTIFY answered 200, until
    /// <paramref name="done"/> holds or time runs out.</summary>
    private async Task<List<string>> ReadAsync(Func<List<string>, bool> done)
    {
        var seen = new List<string>();
        var buffer = new byte[65536];
        var deadline = DateTime.UtcNow + Timeout;
        while (DateTime.UtcNow < deadline && !done(seen))
        {
            if (_referrer.Available > 0)
            {
                EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                var read = _referrer.ReceiveFrom(buffer, ref from);
                var text = Encoding.UTF8.GetString(buffer, 0, read);
                seen.Add(text);
                if (text.StartsWith("NOTIFY ", StringComparison.Ordinal))
                {
                    _referrer.SendTo(OkTo(text), from);
                }
            }
            else
            {
                await Task.Delay(10);
            }
        }
        return seen;
    }

    private static IPEndPoint EndpointOf(string address)
    {
        var (host, port) = SipralStack.ParseAddress(address);
        return new IPEndPoint(IPAddress.Parse(host), port);
    }

    [Fact]
    public async Task AStackThatWasNotToldToTakeThemRefusesThem403()
    {
        var bob = Own(new SipralStack(audio: SipralAudio.Application));
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: AddressOf(_referrer));
        _referrer.SendTo(Refer(bob.BindAddress, AddressOf(_referrer), "sip:carol@sipral.invalid"), EndpointOf(bob.BindAddress));
        var seen = await ReadAsync(s => s.Any(m => m.StartsWith("SIP/2.0 ", StringComparison.Ordinal)));
        Assert.Contains(seen, m => m.StartsWith("SIP/2.0 403 ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AReferralTakenPlacesTheCallAndReportsItToTheReferrer()
    {
        var carol = Own(new SipralStack(audio: SipralAudio.Application));
        var bob = Own(new SipralStack(audio: SipralAudio.Application, referrals: true));
        carol.AddAccount("sip:carol@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: carol.BindAddress);

        var target = $"sip:carol@{carol.BindAddress}";
        _referrer.SendTo(Refer(bob.BindAddress, AddressOf(_referrer), target), EndpointOf(bob.BindAddress));

        var referral = await FirstMatchingAsync(bob.Events, e => e.Kind == SipralEventKind.Referral);
        Assert.NotNull(referral.Referral);
        Assert.Equal(0u, referral.Referral!.StatusCode);
        Assert.Equal(target, referral.Referral.Target);
        Assert.Equal("<sip:switchboard@sipral.invalid>", referral.Referral.ReferredBy);
        Assert.False(referral.Referral.Attended);
        Assert.NotEqual(0ul, referral.Account);

        var placed = bob.AcceptReferral(referral);
        var incoming = await FirstMatchingAsync(carol.Events, e => e.Kind == SipralEventKind.IncomingCall);
        var answered = carol.AnswerCall(incoming);
        try
        {
            var seen = await ReadAsync(s => s.Any(m =>
                m.StartsWith("NOTIFY ", StringComparison.Ordinal) && m.Contains("SIP/2.0 200 OK")));
            Assert.Contains(seen, m => m.StartsWith("SIP/2.0 202 ", StringComparison.Ordinal));
            var notifies = seen.Where(m => m.StartsWith("NOTIFY ", StringComparison.Ordinal)).ToList();
            Assert.NotEmpty(notifies);
            Assert.Contains("SIP/2.0 100 Trying", notifies[0]);
            Assert.StartsWith("active", Header("Subscription-State", notifies[0]));
            Assert.Contains("SIP/2.0 200 OK", notifies[^1]);
            Assert.Equal("terminated;reason=noresource", Header("Subscription-State", notifies[^1]));
            Assert.Equal("message/sipfrag;version=2.0", Header("Content-Type", notifies[^1]));

            using var cts = new CancellationTokenSource(Timeout);
            Assert.NotNull(await placed.WaitForMediaAsync(cts.Token));
        }
        finally
        {
            placed.Close();
            answered.Close();
        }
    }

    /// <summary>On this host's own routable address, never 127.0.0.1: RFC
    /// 8445 §5.1.1.1 keeps a loopback address out of every candidate list,
    /// and a lite end has one candidate to offer and nothing else.</summary>
    [Fact]
    public async Task ALiteStackAnsweringAFullOneCarriesAudioBothWaysOnThePairItNominated()
    {
        var host = NatTests.RoutableAddress();
        if (host is null)
        {
            return; // no routable address on this machine to gather a host candidate from
        }
        var alice = Own(new SipralStack(audio: SipralAudio.Application, bindHost: host));
        var bob = Own(new SipralStack(audio: SipralAudio.Application, bindHost: host, ice: SipralIce.Lite));
        var aliceAccount = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);

        var aliceCall = alice.PlaceCall(aliceAccount, $"sip:bob@{bob.BindAddress}", mediaHost: host, ice: SipralIce.Required);
        var incoming = await FirstMatchingAsync(bob.Events, e => e.Kind == SipralEventKind.IncomingCall);
        var bobCall = bob.AnswerCall(incoming, mediaHost: host);
        try
        {
            foreach (var call in new[] { aliceCall, bobCall })
            {
                var chosen = await FirstMatchingAsync(call.Events,
                    e => e.Kind is SipralEventKind.MediaPathChosen or SipralEventKind.MediaFailed);
                Assert.Equal(SipralEventKind.MediaPathChosen, chosen.Kind);
            }

            using var cts = new CancellationTokenSource(Timeout);
            Assert.NotNull(await aliceCall.WaitForMediaAsync(cts.Token));
            Assert.NotNull(await bobCall.WaitForMediaAsync(cts.Token));
            var frameSamples = aliceCall.Media!.FrameSamples;
            var tone = new short[frameSamples];
            Array.Fill(tone, (short)4096);
            for (var i = 0; i < 5; i++)
            {
                aliceCall.Media.SendAudio(tone);
            }
            Assert.Equal(frameSamples, (await FirstAsync(bobCall.Media!.Frames)).Length);
            for (var i = 0; i < 5; i++)
            {
                bobCall.Media.SendAudio(tone);
            }
            Assert.Equal(frameSamples, (await FirstAsync(aliceCall.Media.Frames)).Length);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    private static async Task<T> FirstAsync<T>(IAsyncEnumerable<T> source)
    {
        using var cts = new CancellationTokenSource(Timeout);
        try
        {
            await foreach (var item in source.WithCancellation(cts.Token))
            {
                return item;
            }
        }
        catch (OperationCanceledException)
        {
        }
        throw new TimeoutException($"no item arrived within {Timeout}");
    }

    private static async Task<T> FirstMatchingAsync<T>(IAsyncEnumerable<T> source, Func<T, bool> predicate)
    {
        using var cts = new CancellationTokenSource(Timeout);
        try
        {
            await foreach (var item in source.WithCancellation(cts.Token))
            {
                if (predicate(item))
                {
                    return item;
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        throw new TimeoutException($"nothing matching arrived within {Timeout}");
    }
}
