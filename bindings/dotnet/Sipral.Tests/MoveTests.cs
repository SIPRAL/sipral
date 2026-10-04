// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// A call in progress moves with the network under it, and a call says which
/// SRTP transform secures it — the .NET counterpart of
/// <c>bindings/python/tests/test_move.py</c>. Alice starts on loopback and
/// moves to this machine's own address on its default route.
/// </summary>
public sealed class MoveTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static async Task<(Call Call, Call Answered)> ConnectAsync(SipralStack alice, SipralStack bob)
    {
        var account = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);
        var call = alice.PlaceCall(account, $"sip:bob@{bob.BindAddress}");
        using var cts = new CancellationTokenSource(Timeout);
        Call? answered = null;
        await foreach (var e in bob.Events.WithCancellation(cts.Token))
        {
            if (e.Kind == SipralEventKind.IncomingCall)
            {
                answered = bob.AnswerCall(e);
                break;
            }
        }
        Assert.NotNull(await call.WaitForMediaAsync(cts.Token));
        Assert.NotNull(await answered!.WaitForMediaAsync(cts.Token));
        return (call, answered);
    }

    private static async Task<SipralEventArgs> UntilAsync(Call call, SipralEventKind kind)
    {
        using var cts = new CancellationTokenSource(Timeout);
        await foreach (var e in call.Events.WithCancellation(cts.Token))
        {
            if (e.Kind == kind)
            {
                return e;
            }
        }
        throw new Xunit.Sdk.XunitException($"no {kind}");
    }

    /// <summary>Whether <paramref name="media"/> decodes a frame with
    /// something in it within a few seconds.</summary>
    private static async Task<bool> HearsAsync(CallMedia media)
    {
        var loud = 0;
        CallMedia.FrameHandler listen = frame =>
        {
            foreach (var sample in frame)
            {
                if (Math.Abs((int)sample) > 1000)
                {
                    Interlocked.Exchange(ref loud, 1);
                    return;
                }
            }
        };
        media.FrameDecoded += listen;
        try
        {
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(3);
            while (DateTime.UtcNow < deadline && Volatile.Read(ref loud) == 0)
            {
                await Task.Delay(50);
            }
            return Volatile.Read(ref loud) == 1;
        }
        finally
        {
            media.FrameDecoded -= listen;
        }
    }

    // a tone, not a constant: Opus rejects DC, so a constant comes out loud
    // only for the few milliseconds of its onset, and a call whose buffer
    // skipped those frames heard nothing loud at all. Forty samples a period
    // is 200 Hz at 8 kHz and 1.2 kHz at 48 kHz
    private static void Speak(CallMedia media) =>
        media.SendAudio(Enumerable.Range(0, media.FrameSamples * 100)
            .Select(n => (short)(8000 * Math.Sin(2 * Math.PI * n / 40)))
            .ToArray());

    [Fact]
    public async Task TheCallIsOfferedAtTheNewAddressAndHeardBothWaysAfter()
    {
        var host = NatTests.RoutableAddress();
        // Windows routes no datagram between a socket bound to loopback and
        // one bound to the machine's own LAN address (WSAENETUNREACH one way,
        // WSAEADDRNOTAVAIL the other), so a far end on loopback can never
        // hear a call moved onto the LAN there; macOS and Linux both can
        if (host is null || host.StartsWith("127.", StringComparison.Ordinal) || OperatingSystem.IsWindows())
        {
            return;
        }
        // bound at one address, which a move binds again at the next: a stack
        // on every interface keeps advertising the route toward its server,
        // loopback here, below
        using var alice = new SipralStack("127.0.0.1", audio: SipralAudio.Application);
        using var bob = new SipralStack(audio: SipralAudio.Application);
        var (call, answered) = await ConnectAsync(alice, bob);
        try
        {
            var before = call.MediaAddress;
            Assert.Equal(SipralRecovery.Rebuild, alice.MoveTo(host));
            Assert.StartsWith($"{host}:", alice.BindAddress);

            var wanted = await UntilAsync(call, SipralEventKind.CallAddressWanted);
            Assert.Equal(call.Handle, wanted.Call);
            var old = call.MediaSocket;
            call.Readdress(host);
            Assert.NotEqual(before, call.MediaAddress);
            Assert.StartsWith($"{host}:", call.MediaAddress);
            // the media reads and sends on the new socket, and the old one is
            // gone: on a real network its address no longer exists, and a far
            // end that latches onto where packets come from must not be led back
            Assert.Equal(call.MediaAddress, call.Media!.LocalAddress);
            Assert.Throws<ObjectDisposedException>(() => old.LocalEndPoint);
            await UntilAsync(call, SipralEventKind.SessionChanged);

            Speak(answered.Media!);
            Assert.True(await HearsAsync(call.Media!), "no audio reached the moved socket");
            Speak(call.Media!);
            Assert.True(await HearsAsync(answered.Media!), "the far end heard nothing from the new address");
        }
        finally
        {
            answered.Close();
            call.Close();
        }
    }

    private static int FreePort(string host)
    {
        using var probe = new System.Net.Sockets.Socket(
            System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram,
            System.Net.Sockets.ProtocolType.Udp);
        probe.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Parse(host), 0));
        return ((System.Net.IPEndPoint)probe.LocalEndPoint!).Port;
    }

    /// <summary>This machine's address on its default route, or a failure
    /// naming why the port checks cannot run.</summary>
    private static string OtherAddress()
    {
        var host = NatTests.RoutableAddress();
        Assert.False(host is null || host.StartsWith("127.", StringComparison.Ordinal),
            "this machine has no address but loopback, and the port checks need one");
        return host!;
    }

    /// <summary>The port the application chose survives a move to another
    /// address and back, and with none chosen the port in use does.</summary>
    [Fact]
    public void TheSignallingPortSurvivesAMoveToAnotherAddress()
    {
        var elsewhere = OtherAddress();
        var chosen = FreePort(elsewhere);
        using (var stack = new SipralStack("127.0.0.1", chosen, audio: SipralAudio.Application))
        {
            stack.MoveTo(elsewhere);
            Assert.Equal($"{elsewhere}:{chosen}", stack.BindAddress);
            Assert.True(stack.KeptSignallingPort);
            stack.MoveTo("127.0.0.1");
            Assert.Equal($"127.0.0.1:{chosen}", stack.BindAddress);
        }
        using (var stack = new SipralStack(audio: SipralAudio.Application))
        {
            var port = stack.BindAddress[(stack.BindAddress.LastIndexOf(':') + 1)..];
            stack.MoveTo(elsewhere);
            Assert.Equal($"{elsewhere}:{port}", stack.BindAddress);
            Assert.True(stack.KeptSignallingPort);
        }
    }

    /// <summary>A port another socket holds at the new address is not fought
    /// over: the system picks one, and the stack says so.</summary>
    [Fact]
    public void APortTakenAtTheNewAddressFallsBackAndSaysSo()
    {
        var elsewhere = OtherAddress();
        using var squatter = new System.Net.Sockets.Socket(
            System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram,
            System.Net.Sockets.ProtocolType.Udp);
        squatter.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Parse(elsewhere), 0));
        var taken = ((System.Net.IPEndPoint)squatter.LocalEndPoint!).Port;
        using var stack = new SipralStack("127.0.0.1", taken, audio: SipralAudio.Application);
        stack.MoveTo(elsewhere);
        var colon = stack.BindAddress.LastIndexOf(':');
        Assert.Equal(elsewhere, stack.BindAddress[..colon]);
        var now = int.Parse(stack.BindAddress[(colon + 1)..], System.Globalization.CultureInfo.InvariantCulture);
        Assert.NotEqual(taken, now);
        Assert.NotEqual(0, now);
        Assert.False(stack.KeptSignallingPort);
    }

    /// <summary>A move to an address this machine lacks fails with the
    /// signalling socket it had still open, so the next move keeps its
    /// port.</summary>
    [Fact]
    public void AMoveToAnAddressThisMachineLacksKeepsTheSocketItHad()
    {
        var elsewhere = OtherAddress();
        using var stack = new SipralStack(audio: SipralAudio.Application);
        var before = stack.BindAddress;
        var port = before[(before.LastIndexOf(':') + 1)..];
        // TEST-NET-1 (RFC 5737): on no interface of this machine
        Assert.ThrowsAny<System.Net.Sockets.SocketException>(() => stack.MoveTo("192.0.2.77"));
        Assert.Equal(before, stack.BindAddress);
        stack.MoveTo(elsewhere);
        Assert.Equal($"{elsewhere}:{port}", stack.BindAddress);
        Assert.True(stack.KeptSignallingPort);
    }

    /// <summary>A stack bound on every interface keeps picking its own
    /// address across a move: its socket stays where it was, on its port, and
    /// what it advertises is the route toward each account's server again
    /// rather than the address the move named, taken as fixed from then
    /// on.</summary>
    [Fact]
    public void AStackOnEveryInterfaceKeepsChoosingItsRouteAcrossAMove()
    {
        var elsewhere = OtherAddress();
        using var stack = new SipralStack(audio: SipralAudio.Application);
        var port = stack.BindAddress[(stack.BindAddress.LastIndexOf(':') + 1)..];
        var away = stack.AddAccount("sip:alice@192.0.2.1", registrarAddress: "192.0.2.1:5060");
        Assert.Equal($"{elsewhere}:{port}", stack.BindAddress);

        stack.MoveTo(elsewhere);
        var here = stack.AddAccount("sip:bob@127.0.0.1", registrarAddress: "127.0.0.1:5060");
        Assert.Equal($"127.0.0.1:{port}", here.Advertised);

        stack.MoveTo("127.0.0.1");
        Assert.Equal($"{elsewhere}:{port}", stack.BindAddress);
        Assert.True(stack.KeptSignallingPort);
        Assert.Equal($"{elsewhere}:{port}", away.Advertised);
        Assert.Equal($"127.0.0.1:{port}", here.Advertised);
    }

    [Fact]
    public async Task ASecondMoveWhileTheFirstIsOnItsWayIsRefused()
    {
        var host = NatTests.RoutableAddress();
        if (host is null || host.StartsWith("127.", StringComparison.Ordinal))
        {
            return;
        }
        using var alice = new SipralStack(audio: SipralAudio.Application);
        using var bob = new SipralStack(audio: SipralAudio.Application);
        var (call, answered) = await ConnectAsync(alice, bob);
        try
        {
            alice.MoveTo(host);
            call.Readdress(host);
            var moved = call.MediaAddress;
            var refused = Assert.Throws<SipralException>(() => call.Readdress(host));
            Assert.Equal(SipralStatus.WrongState, refused.Status);
            Assert.Equal(moved, call.MediaAddress);
        }
        finally
        {
            answered.Close();
            call.Close();
        }
    }

    [Fact]
    public async Task TwoEndsOfThisStackSettleOnAes256Gcm()
    {
        using var alice = new SipralStack(audio: SipralAudio.Application, srtp: SipralSrtp.Dtls);
        using var bob = new SipralStack(audio: SipralAudio.Application, srtp: SipralSrtp.Dtls);
        var (call, answered) = await ConnectAsync(alice, bob);
        try
        {
            if (call.SrtpSuite is null)
            {
                await UntilAsync(call, SipralEventKind.MediaSecured);
            }
            if (answered.SrtpSuite is null)
            {
                await UntilAsync(answered, SipralEventKind.MediaSecured);
            }
            Assert.Equal(SipralSrtpSuite.AeadAes256Gcm, call.SrtpSuite);
            Assert.Equal(SipralSrtpSuite.AeadAes256Gcm, answered.SrtpSuite);
        }
        finally
        {
            answered.Close();
            call.Close();
        }
    }

    [Fact]
    public async Task ACallNotSecuredNamesNoTransform()
    {
        using var alice = new SipralStack(audio: SipralAudio.Application, srtp: SipralSrtp.NotOffered);
        using var bob = new SipralStack(audio: SipralAudio.Application, srtp: SipralSrtp.NotOffered);
        var (call, answered) = await ConnectAsync(alice, bob);
        try
        {
            await Task.Delay(300);
            Assert.Null(call.SrtpSuite);
        }
        finally
        {
            answered.Close();
            call.Close();
        }
    }
}
