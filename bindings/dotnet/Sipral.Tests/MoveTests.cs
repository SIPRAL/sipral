// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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

    private static void Speak(CallMedia media) =>
        media.SendAudio(Enumerable.Repeat((short)0x2000, media.FrameSamples * 100).ToArray());

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
        using var alice = new SipralStack(audio: SipralAudio.Application);
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
