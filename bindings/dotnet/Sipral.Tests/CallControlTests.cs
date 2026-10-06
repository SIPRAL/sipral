// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// Transfer, ringing, screening, a registration refreshed on demand and a
/// call's own codec order, through <see cref="SipralStack"/>,
/// <see cref="Call"/> and <see cref="Account"/>: stacks on loopback talking
/// directly, each account pointed at another stack as its outbound proxy,
/// the way <see cref="TwoStacksTalkDirectlyTests"/> sets them up.
/// </summary>
public sealed class CallControlTests : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    private readonly List<IDisposable> _owned = new();

    public void Dispose()
    {
        foreach (var owned in Enumerable.Reverse(_owned))
        {
            owned.Dispose();
        }
    }

    private T Own<T>(T disposable) where T : IDisposable
    {
        _owned.Add(disposable);
        return disposable;
    }

    private SipralStack Stack(string? codecs = null) =>
        Own(new SipralStack(audio: SipralAudio.Application, codecs: codecs));

    private static async Task<SipralEventArgs> NextAsync(IAsyncEnumerable<SipralEventArgs> events, Func<SipralEventArgs, bool> wanted)
    {
        using var cts = new CancellationTokenSource(Timeout);
        try
        {
            await foreach (var args in events.WithCancellation(cts.Token))
            {
                if (wanted(args))
                {
                    return args;
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        throw new TimeoutException($"nothing matching arrived within {Timeout}");
    }

    private static Task<SipralEventArgs> NextAsync(SipralStack stack, SipralEventKind kind) =>
        NextAsync(stack.Events, e => e.Kind == kind);

    private static async Task ConfirmedAsync(Call call)
    {
        using var cts = new CancellationTokenSource(Timeout);
        Assert.True(await call.WaitForConfirmedAsync(cts.Token));
    }

    private static async Task<CallMedia> MediaAsync(Call call)
    {
        using var cts = new CancellationTokenSource(Timeout);
        var media = await call.WaitForMediaAsync(cts.Token);
        Assert.NotNull(media);
        return media!;
    }

    /// <summary>Alice calls Bob and Bob answers; both calls up.</summary>
    private async Task<(Call Alice, Call Bob)> ConnectAsync(SipralStack alice, Account from, SipralStack bob, string user = "bob")
    {
        var placed = alice.PlaceCall(from, $"sip:{user}@{bob.BindAddress}");
        var answered = bob.AnswerCall(await NextAsync(bob, SipralEventKind.IncomingCall));
        await ConfirmedAsync(placed);
        return (placed, answered);
    }

    // -- transfer ---------------------------------------------------------

    [Fact]
    public async Task ABlindTransferRingsTheTargetAndReportsSuccessToWhoAskedForIt()
    {
        var alice = Stack();
        var bob = Stack();
        var carol = Stack();
        var aliceLine = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: carol.BindAddress);
        carol.AddAccount("sip:carol@sipral.invalid", registrarAddress: bob.BindAddress);

        var (toBob, bobSide) = await ConnectAsync(alice, aliceLine, bob);
        Call? placed = null;
        Call? carolSide = null;
        try
        {
            var done = toBob.WaitForTransferAsync();
            var target = $"sip:carol@{carol.BindAddress}";
            toBob.Transfer(target);

            var asked = await NextAsync(bob, SipralEventKind.TransferRequested);
            Assert.NotNull(asked.Transfer);
            Assert.Equal(target, asked.Transfer!.Target);
            Assert.False(asked.Transfer.Attended);

            placed = bob.AcceptReferral(asked);
            carolSide = carol.AnswerCall(await NextAsync(carol, SipralEventKind.IncomingCall));
            await ConfirmedAsync(placed);

            var outcome = await done.WaitAsync(Timeout);
            Assert.NotNull(outcome);
            Assert.InRange(outcome!.StatusCode, 200u, 299u);
        }
        finally
        {
            carolSide?.Close();
            placed?.Close();
            bobSide.Close();
            toBob.Close();
        }
    }

    [Fact]
    public async Task ARefusedTransferIsReportedWithTheRefusal()
    {
        var alice = Stack();
        var bob = Stack();
        var aliceLine = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);
        var (toBob, bobSide) = await ConnectAsync(alice, aliceLine, bob);
        try
        {
            var done = toBob.WaitForTransferAsync();
            toBob.Transfer("sip:carol@sipral.invalid");
            bob.RejectReferral(await NextAsync(bob, SipralEventKind.TransferRequested), 603);
            var outcome = await done.WaitAsync(Timeout);
            Assert.NotNull(outcome);
            Assert.Equal(603u, outcome!.StatusCode);
            Assert.Equal(SipralCallState.Confirmed, toBob.State);
        }
        finally
        {
            bobSide.Close();
            toBob.Close();
        }
    }

    [Fact]
    public async Task ATransferTakenWithACallOfTheApplicationsOwnReportsThatCall()
    {
        var alice = Stack();
        var bob = Stack();
        var carol = Stack();
        var aliceLine = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        var bobLine = bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: carol.BindAddress);
        carol.AddAccount("sip:carol@sipral.invalid", registrarAddress: bob.BindAddress);

        var (toBob, bobSide) = await ConnectAsync(alice, aliceLine, bob);
        Call? placed = null;
        Call? carolSide = null;
        try
        {
            var done = toBob.WaitForTransferAsync();
            toBob.Transfer($"sip:carol@{carol.BindAddress}");
            var asked = await NextAsync(bob, SipralEventKind.TransferRequested);
            placed = bob.PlaceCall(bobLine, $"sip:carol@{carol.BindAddress}");
            bob.AcceptTransferPlaced(asked, placed);
            carolSide = carol.AnswerCall(await NextAsync(carol, SipralEventKind.IncomingCall));

            var outcome = await done.WaitAsync(Timeout);
            Assert.NotNull(outcome);
            Assert.Equal(200u, outcome!.StatusCode);
        }
        finally
        {
            carolSide?.Close();
            placed?.Close();
            bobSide.Close();
            toBob.Close();
        }
    }

    /// <summary>Bob is asked for an attended transfer and takes it; his
    /// INVITE carries the <c>Replaces</c> naming Alice's consultation with
    /// Carol. Carol's end takes a <c>Replaces</c> only from the far end of
    /// the call it names (RFC 3891 §3), and on loopback without a proxy Bob
    /// is not Alice, so she refuses it 403 — which is what Alice's transfer
    /// reports, through Bob's NOTIFY.</summary>
    [Fact]
    public async Task AnAttendedTransferNamesTheConsultationAndReportsHowItWent()
    {
        var alice = Stack();
        var bob = Stack();
        var carol = Stack();
        var aliceToBob = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        var aliceToCarol = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: carol.BindAddress);
        // Bob's line goes out through Carol's address, so the INVITE the
        // transfer places reaches her rather than coming back to Alice
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: carol.BindAddress);
        carol.AddAccount("sip:carol@sipral.invalid", registrarAddress: alice.BindAddress);

        var (toBob, bobSide) = await ConnectAsync(alice, aliceToBob, bob);
        var (toCarol, carolSide) = await ConnectAsync(alice, aliceToCarol, carol, "carol");
        Call? placed = null;
        try
        {
            var done = toBob.WaitForTransferAsync();
            toBob.TransferTo(toCarol);

            var asked = await NextAsync(bob, SipralEventKind.TransferRequested);
            Assert.True(asked.Transfer!.Attended);
            Assert.Equal($"sip:carol@{carol.BindAddress}", asked.Transfer.Target);

            placed = bob.AcceptReferral(asked);
            var outcome = await done.WaitAsync(Timeout);
            Assert.NotNull(outcome);
            Assert.Equal(403u, outcome!.StatusCode);
            Assert.Equal(1ul, carol.Counters().ScreenedRefusedByReplaces);
            Assert.Equal(SipralCallState.Confirmed, toBob.State);
        }
        finally
        {
            placed?.Close();
            carolSide.Close();
            toCarol.Close();
            bobSide.Close();
            toBob.Close();
        }
    }

    // -- ringing -----------------------------------------------------------

    [Fact]
    public async Task RingingAnIncomingCallTellsTheCallerBeforeItIsAnswered()
    {
        var alice = Stack();
        var bob = Stack();
        var aliceLine = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);

        var placed = alice.PlaceCall(aliceLine, $"sip:bob@{bob.BindAddress}");
        Call? answered = null;
        try
        {
            var incoming = await NextAsync(bob, SipralEventKind.IncomingCall);
            bob.RingCall(incoming);
            await NextAsync(placed.Events, e => e.Kind == SipralEventKind.CallProgress && e.CallInfo!.StatusCode == 180);
            Assert.Equal(SipralCallState.Ringing, placed.State);
            Assert.Null(placed.Media);

            answered = bob.AnswerCall(incoming);
            await ConfirmedAsync(placed);
        }
        finally
        {
            answered?.Close();
            placed.Close();
        }
    }

    [Fact]
    public async Task RingingWithMediaCarriesAudioBeforeTheAnswerAndKeepsItAfter()
    {
        var alice = Stack();
        var bob = Stack();
        var aliceLine = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);

        var placed = alice.PlaceCall(aliceLine, $"sip:bob@{bob.BindAddress}");
        Call? ringing = null;
        try
        {
            var incoming = await NextAsync(bob, SipralEventKind.IncomingCall);
            ringing = bob.RingCallWithMedia(incoming, codecs: "PCMA");
            var bobMedia = await MediaAsync(ringing);
            var aliceMedia = await MediaAsync(placed);
            Assert.Equal(SipralCallState.EarlyMedia, placed.State);
            Assert.Equal(SipralCodec.Pcma, aliceMedia.Info().Codec);

            var tone = new short[bobMedia.FrameSamples];
            Array.Fill(tone, (short)4096);
            for (var i = 0; i < 5; i++)
            {
                bobMedia.SendAudio(tone);
            }
            using (var cts = new CancellationTokenSource(Timeout))
            {
                await foreach (var frame in aliceMedia.Frames.WithCancellation(cts.Token))
                {
                    Assert.Equal(aliceMedia.FrameSamples, frame.Length);
                    break;
                }
            }

            ringing.Answer();
            await ConfirmedAsync(placed);
            Assert.Same(bobMedia, ringing.Media);
        }
        finally
        {
            ringing?.Close();
            placed.Close();
        }
    }

    // -- screening ---------------------------------------------------------

    [Fact]
    public async Task AScreeningPolicyRefusesAnInviteBeforeAnyCallExistsAndRemovingItLetsThemIn()
    {
        var alice = Stack();
        var bob = Stack();
        var aliceLine = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);

        var seen = new ConcurrentQueue<SipralInvite>();
        bob.Screen(invite =>
        {
            seen.Enqueue(invite);
            return invite.Header("From")!.Contains("alice@", StringComparison.Ordinal) ? 603u : global::Sipral.Sipral.ScreenAccept;
        });

        var refused = alice.PlaceCall(aliceLine, $"sip:bob@{bob.BindAddress}");
        try
        {
            var ended = await NextAsync(refused.Events, e => e.Kind == SipralEventKind.CallEnded);
            Assert.Equal(603u, ended.CallInfo!.StatusCode);
        }
        finally
        {
            refused.Close();
        }
        var invite = Assert.Single(seen);
        Assert.Equal(alice.BindAddress, invite.Source);
        Assert.StartsWith("INVITE ", System.Text.Encoding.UTF8.GetString(invite.Message));
        Assert.Equal(1ul, bob.Counters().ScreenedRefusedByPolicy);

        bob.Screen(null);
        var (placed, answered) = await ConnectAsync(alice, aliceLine, bob);
        answered.Close();
        placed.Close();
        Assert.Single(seen);
    }

    // -- refresh -------------------------------------------------------------

    [Fact]
    public async Task RefreshingABindingSendsAnotherRegisterNowAndAnAccountThatNeverRegistersHasNone()
    {
        using var registrar = new ReachabilityTests.Registrar();
        var stack = Stack();
        var account = stack.AddAccount("sip:alice@example.com", registrar.Address, registrar: "sip:example.com");
        account.Register();
        await Until(() => account.RegistrationState() == SipralRegistrationState.Registered);
        Assert.Single(registrar.Registers);

        // asked again while the first REGISTER's transaction still lingers,
        // a refresh sends nothing, so it is asked until one goes
        Assert.True(await Until(() =>
        {
            account.RefreshBinding();
            return registrar.Registers.Count >= 2;
        }, TimeSpan.FromMilliseconds(250)), "no second REGISTER");
        await Until(() => account.RegistrationState() == SipralRegistrationState.Registered);

        var direct = stack.AddAccount("sip:bob@sipral.invalid", registrarAddress: registrar.Address);
        var refused = Assert.Throws<SipralException>(direct.RefreshBinding);
        Assert.Equal(SipralStatus.InvalidArgument, refused.Status);
    }

    private static async Task<bool> Until(Func<bool> what, TimeSpan? every = null)
    {
        var deadline = DateTime.UtcNow + Timeout;
        while (!what() && DateTime.UtcNow < deadline)
        {
            await Task.Delay(every ?? TimeSpan.FromMilliseconds(20));
        }
        return what();
    }

    // -- a call's own codecs --------------------------------------------------

    /// <summary>Alice's stack offers only PCMU; this call offers PCMA first,
    /// and Bob, who takes both, answers in the offer's order.</summary>
    [Fact]
    public async Task ACallPlacedWithItsOwnCodecsNegotiatesTheFirstOfThem()
    {
        var alice = Stack(codecs: "PCMU");
        var bob = Stack();
        var aliceLine = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);

        var placed = alice.PlaceCall(aliceLine, $"sip:bob@{bob.BindAddress}", options: new SipralCallOptions { Codecs = "PCMA,PCMU" });
        var answered = bob.AnswerCall(await NextAsync(bob, SipralEventKind.IncomingCall));
        try
        {
            Assert.Equal(SipralCodec.Pcma, (await MediaAsync(placed)).Info().Codec);
            Assert.Equal(SipralCodec.Pcma, (await MediaAsync(answered)).Info().Codec);
        }
        finally
        {
            answered.Close();
            placed.Close();
        }
    }

    /// <summary>Bob's stack takes only PCMU, which alone would answer PCMU;
    /// this call takes PCMA too, and Alice offers both, PCMA first.</summary>
    [Fact]
    public async Task ACallAnsweredWithItsOwnCodecsNegotiatesPcmaWhenOfferedBoth()
    {
        var alice = Stack(codecs: "PCMA,PCMU");
        var bob = Stack(codecs: "PCMU");
        var aliceLine = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);

        var placed = alice.PlaceCall(aliceLine, $"sip:bob@{bob.BindAddress}");
        var answered = bob.AnswerCall(await NextAsync(bob, SipralEventKind.IncomingCall), options: new SipralCallOptions { Codecs = "PCMA,PCMU" });
        try
        {
            Assert.Equal(SipralCodec.Pcma, (await MediaAsync(answered)).Info().Codec);
            Assert.Equal(SipralCodec.Pcma, (await MediaAsync(placed)).Info().Codec);
        }
        finally
        {
            answered.Close();
            placed.Close();
        }
    }
}
