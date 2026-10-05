// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// Two stacks on 127.0.0.1, talking directly, with no registrar between
/// them — the .NET counterpart of
/// <c>bindings/python/tests/test_call.py</c>. Each account is given the
/// other stack's own <see cref="SipralStack.BindAddress"/> as its
/// outbound proxy (<c>registrarAddress</c>) and no registrar, so nothing
/// here needs a SIP server: it proves this layer against the real ABI on
/// loopback, the same proof <c>bindings/python</c>'s own tests are.
/// </summary>
public sealed class TwoStacksTalkDirectlyTests : IDisposable
{
    // Generous rather than tight: this machine can be shared with several
    // other heavy builds at once, and a SIP round trip (an INVITE or a
    // re-INVITE, answered, ACKed) is a few scheduler hops long even before
    // counting how late any one of them might run under that kind of load.
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    private readonly SipralStack _alice = new(audio: SipralAudio.Application);
    private readonly SipralStack _bob = new(audio: SipralAudio.Application);

    public void Dispose()
    {
        _alice.Dispose();
        _bob.Dispose();
    }

    private async Task<(Call Alice, Call Bob)> PlaceAndAnswerAsync()
    {
        var aliceAccount = _alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: _bob.BindAddress);
        _bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: _alice.BindAddress);

        var aliceCall = _alice.PlaceCall(aliceAccount, $"sip:bob@{_bob.BindAddress}");

        var incoming = await FirstMatchingAsync(_bob.Events, e => e.Kind == SipralEventKind.IncomingCall, Timeout);
        var bobCall = _bob.AnswerCall(incoming);

        using var cts = new CancellationTokenSource(Timeout);
        Assert.NotNull(await aliceCall.WaitForMediaAsync(cts.Token));
        Assert.NotNull(await bobCall.WaitForMediaAsync(cts.Token));

        return (aliceCall, bobCall);
    }

    [Fact]
    public async Task CallReachesConfirmedWithMediaBothWays()
    {
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync();
        try
        {
            Assert.Equal(SipralCallState.Confirmed, aliceCall.State);
            Assert.Equal(SipralCallState.Confirmed, bobCall.State);
            Assert.True(aliceCall.Media!.Info().Sending);
            Assert.True(bobCall.Media!.Info().Receiving);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    [Fact]
    public async Task AudioCrossesAsPcmInBothDirections()
    {
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync();
        try
        {
            var frameSamples = aliceCall.Media!.FrameSamples;
            var tone = new short[frameSamples];
            Array.Fill(tone, (short)4096);
            for (var i = 0; i < 5; i++)
            {
                aliceCall.Media.SendAudio(tone);
            }

            var heard = await FirstAsync(bobCall.Media!.Frames, Timeout);
            Assert.Equal(frameSamples, heard.Length);

            for (var i = 0; i < 5; i++)
            {
                bobCall.Media.SendAudio(tone);
            }
            var heardBack = await FirstAsync(aliceCall.Media.Frames, Timeout);
            Assert.Equal(frameSamples, heardBack.Length);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    /// <summary><see cref="CallMedia.SetAppRate"/>: both ends at 24 kHz
    /// hand out and take 480-sample frames whatever the codec, a rate
    /// outside the four is refused and changes nothing, and 0 is the
    /// codec's own again.</summary>
    [Fact]
    public async Task FramesCrossAtTheRateTheApplicationChose()
    {
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync();
        try
        {
            var codecRate = bobCall.Media!.SampleRate;
            foreach (var media in new[] { aliceCall.Media!, bobCall.Media! })
            {
                media.SetAppRate(24_000);
                Assert.Equal(24_000u, media.SampleRate);
                Assert.Equal(480, media.FrameSamples);
                Assert.Equal(24_000u, media.Info().SampleRate);
            }
            var refused = Assert.Throws<SipralException>(() => bobCall.Media.SetAppRate(44_100));
            Assert.Equal(SipralStatus.InvalidArgument, refused.Status);
            Assert.Equal(480, bobCall.Media.FrameSamples);

            var tone = new short[480 * 5];
            Array.Fill(tone, (short)4096);
            aliceCall.Media!.SendAudio(tone);
            var heard = await FirstMatchingAsync(bobCall.Media.Frames, frame => frame.Length == 480, Timeout);
            Assert.Equal(480, heard.Length);

            bobCall.Media.SetAppRate(0);
            Assert.Equal(codecRate, bobCall.Media.SampleRate);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    [Fact]
    public async Task DtmfAndStatistics()
    {
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync();
        try
        {
            bobCall.SendDtmf("5");
            var digit = await FirstAsync(aliceCall.Dtmf, Timeout);
            Assert.Equal('5', digit);

            var frameSamples = aliceCall.Media!.FrameSamples;
            var silence = new short[frameSamples];
            for (var i = 0; i < 5; i++)
            {
                aliceCall.Media.SendAudio(silence);
            }
            await Task.Delay(300);

            var stats = aliceCall.Media.Statistics();
            Assert.True(stats.PacketsSent > 0);

            // the record copies frames_underrun, not a neighbour of it: the
            // library's own count, read either side, brackets it
            var before = SipralStreamStats.Sized();
            Assert.Equal(SipralStatus.Ok,
                NativeMethods.sipral_media_statistics(aliceCall.Media.Handle, 0, ref before));
            var read = aliceCall.Media.Statistics();
            var after = SipralStreamStats.Sized();
            Assert.Equal(SipralStatus.Ok,
                NativeMethods.sipral_media_statistics(aliceCall.Media.Handle, 0, ref after));
            Assert.InRange(read.FramesUnderrun, before.FramesUnderrun, after.FramesUnderrun);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    /// <summary>The record <see cref="SipralEventKind.MediaStatistics"/>
    /// carries is kept on the call, and is what the media answers once the
    /// library has nothing left and says <c>WRONG_STATE</c>.</summary>
    [Fact]
    public async Task TheEndOfCallRecordIsKeptAndStillReadable()
    {
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync();
        try
        {
            var media = aliceCall.Media!;
            var silence = new short[media.FrameSamples];
            for (var i = 0; i < 5; i++)
            {
                media.SendAudio(silence);
            }
            var deadline = DateTime.UtcNow + Timeout;
            while (media.Statistics().PacketsSent < 5 && DateTime.UtcNow < deadline)
            {
                await Task.Delay(20);
            }

            bobCall.Hangup();
            while (aliceCall.FinalStatistics is null && DateTime.UtcNow < deadline)
            {
                await Task.Delay(20);
            }
            var record = Assert.IsType<SipralStreamStatistics>(aliceCall.FinalStatistics);
            Assert.True(record.PacketsSent >= 5, $"{record.PacketsSent} packets sent");
            var raw = SipralStreamStats.Sized();
            Assert.Equal(SipralStatus.WrongState, NativeMethods.sipral_media_statistics(media.Handle, 0, ref raw));
            Assert.Equal(record.PacketsSent, media.Statistics().PacketsSent);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    /// <summary>The end-of-call record a MEDIA_STATISTICS event carries
    /// copies <c>frames_underrun</c> into
    /// <see cref="SipralStreamStatistics.FramesUnderrun"/>, the member
    /// beside it untouched.</summary>
    [Fact]
    public void AnUnderRunCountCrossesIntoTheEventsRecord()
    {
        var native = SipralStreamStats.Sized();
        native.FramesUnderrun = 7;
        native.SilentForMs = 11;
        var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<SipralStreamStats>());
        try
        {
            Marshal.StructureToPtr(native, pointer, false);
            var record = SipralEventArgs.ReadStatistics(pointer);
            Assert.NotNull(record);
            Assert.Equal(7UL, record!.FramesUnderrun);
            Assert.Equal(11UL, record.SilentForMs);
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }
    }

    [Fact]
    public async Task HoldAndResumeAreObservedAtTheFarEnd()
    {
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync();
        try
        {
            aliceCall.Hold();
            var held = await FirstMatchingAsync(bobCall.Events, e => e.Kind == SipralEventKind.SessionChanged, Timeout);
            Assert.True(held.CallInfo!.HeldThere);

            aliceCall.Resume();
            var resumed = await FirstMatchingAsync(
                bobCall.Events, e => e.Kind == SipralEventKind.SessionChanged && !e.CallInfo!.HeldThere, Timeout);
            Assert.False(resumed.CallInfo!.HeldThere);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    /// <summary>The loudest sample a held party hears of a tone sent on a
    /// call held from the other end, on stacks whose <c>heldAudio</c> is
    /// <paramref name="heldAudio"/>.</summary>
    private static async Task<int> LoudestHeardOnHoldAsync(SipralHeldAudio heldAudio)
    {
        using var alice = new SipralStack(audio: SipralAudio.Application, heldAudio: heldAudio);
        using var bob = new SipralStack(audio: SipralAudio.Application, heldAudio: heldAudio);
        var aliceAccount = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);
        var aliceCall = alice.PlaceCall(aliceAccount, $"sip:bob@{bob.BindAddress}");
        var incoming = await FirstMatchingAsync(bob.Events, e => e.Kind == SipralEventKind.IncomingCall, Timeout);
        var bobCall = bob.AnswerCall(incoming);
        try
        {
            using (var cts = new CancellationTokenSource(Timeout))
            {
                Assert.NotNull(await aliceCall.WaitForMediaAsync(cts.Token));
                Assert.NotNull(await bobCall.WaitForMediaAsync(cts.Token));
            }
            aliceCall.Hold();
            await FirstMatchingAsync(
                aliceCall.Events, e => e.Kind == SipralEventKind.SessionChanged && e.CallInfo!.HeldHere, Timeout);

            var tone = new short[aliceCall.Media!.FrameSamples * 40];
            Array.Fill(tone, (short)8000);
            aliceCall.Media.SendAudio(tone);
            var loudest = 0;
            using var listening = new CancellationTokenSource(TimeSpan.FromMilliseconds(1500));
            try
            {
                await foreach (var frame in bobCall.Media!.Frames.WithCancellation(listening.Token))
                {
                    foreach (var sample in frame)
                    {
                        loudest = Math.Max(loudest, Math.Abs((int)sample));
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
            return loudest;
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    /// <summary>A party this end holds hears silence by default, in
    /// application mode too, where the frames sent may be a microphone's;
    /// it hears what the application sends — hold music, an announcement, a
    /// voice agent — on a stack told
    /// <see cref="SipralHeldAudio.Application"/>.</summary>
    [Fact]
    public async Task AHeldPartyHearsSilenceUnlessTheStackSaysTheApplication()
    {
        Assert.True(await LoudestHeardOnHoldAsync(SipralHeldAudio.Default) < 100,
            "the held party heard the application on a stack told nothing");
        Assert.True(await LoudestHeardOnHoldAsync(SipralHeldAudio.Application) > 1000,
            "the held party did not hear what the application sent");
    }

    /// <summary>The realms a password answers reach the stack one per line:
    /// a realm with a comma of its own is one realm, and one with a control
    /// byte is refused there.</summary>
    [Fact]
    public void TheRealmsAPasswordAnswersReachTheStackOnePerLine()
    {
        _alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: "127.0.0.1:5060", authUser: "alice",
            authPassword: "open sesame", realms: new[] { "registrar.example", "sbc, inc." });
        var refused = Assert.Throws<SipralException>(() => _alice.AddAccount("sip:bob@sipral.invalid",
            registrarAddress: "127.0.0.1:5060", realms: new[] { "registrar.example", "sbc\texample" }));
        Assert.Equal(SipralStatus.InvalidArgument, refused.Status);
    }

    [Fact]
    public async Task HangupEndsTheCallAtBothEnds()
    {
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync();
        aliceCall.Hangup();
        await FirstMatchingAsync(bobCall.Events, e => e.Kind == SipralEventKind.CallEnded, Timeout);
        Assert.True(bobCall.Ended);
        aliceCall.Close();
        bobCall.Close();
    }

    /// <summary>
    /// <c>docs/08-ffi.md</c>: "called from inside `sipral_stack_poll`, on
    /// the thread that polled" — proved here by comparing the managed
    /// thread id a handler observes against the test's own.
    /// </summary>
    [Fact]
    public async Task EventsAreDeliveredOnThePollThreadNotTheCallersThread()
    {
        using var stack = new SipralStack(audio: SipralAudio.Application);
        int? handlerThreadId = null;
        var seen = new SemaphoreSlim(0);
        stack.EventReceived += (_, _) =>
        {
            handlerThreadId = Environment.CurrentManagedThreadId;
            seen.Release();
        };

        Assert.True(await seen.WaitAsync(Timeout)); // SIPRAL_EVENT_KIND_STARTED, on the first poll pass
        Assert.NotNull(handlerThreadId);
        Assert.NotEqual(Environment.CurrentManagedThreadId, handlerThreadId);
    }

    /// <summary>
    /// Hammers a signalling entry point from many threads at once, so
    /// that at least one collides with the stack's own poll thread and
    /// is answered <see cref="SipralStatus.Busy"/> rather than made to
    /// wait — <c>docs/08-ffi.md</c>: "Every entry point that names a
    /// stack takes its lock without blocking; one that finds it taken
    /// answers SIPRAL_STATUS_BUSY and does nothing." Calls
    /// <see cref="NativeMethods"/> directly, bypassing
    /// <c>SipralErrors.Call</c>'s own retry, since the retry is exactly
    /// what would hide the status this test exists to observe.
    ///
    /// The stack's own poll thread holds the lock only for the brief
    /// span of one <c>sipral_stack_poll</c> call and otherwise sleeps in
    /// a 50 ms socket wait (<see cref="SipralStack"/>'s own poll loop),
    /// so a fixed, short burst of calls can miss that span by chance on
    /// a loaded machine. Registering the account first gives every poll
    /// pass real retransmit-timer work to do, widening the span; and
    /// dedicated threads spin for a bounded wall-clock stretch, not a
    /// fixed call count, stopping the moment both a <c>BUSY</c> and an
    /// <c>OK</c> have actually been seen rather than waiting out the
    /// full budget every time.
    /// </summary>
    [Fact]
    public void BusyIsSurfacedRatherThanBlockedOn()
    {
        using var stack = new SipralStack(audio: SipralAudio.Application);
        var account = stack.AddAccount(
            "sip:alice@sipral.invalid", registrarAddress: "127.0.0.1:9", registrar: "sip:registrar.invalid");
        account.Register(); // a registrar nobody answers on this machine: keeps the poll thread retransmitting

        var sawBusy = 0;
        var sawOk = 0;
        // Three threads and a five-second cap, not every core for ten
        // seconds: this machine can be shared with other heavy work at
        // once, and pegging it harder or longer than it takes to find one
        // collision would just make every neighbouring test's own
        // timing-sensitive wait flakier.
        var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var workers = new List<Thread>();
        for (var i = 0; i < 3; i++)
        {
            var worker = new Thread(() =>
            {
                while (!stop.IsCancellationRequested)
                {
                    var status = NativeMethods.sipral_account_registration_state(stack.Handle, account.Handle, out _);
                    if (status == SipralStatus.Busy)
                    {
                        Interlocked.Increment(ref sawBusy);
                    }
                    else if (status == SipralStatus.Ok)
                    {
                        Interlocked.Increment(ref sawOk);
                    }
                    if (Volatile.Read(ref sawBusy) > 0 && Volatile.Read(ref sawOk) > 0)
                    {
                        stop.Cancel();
                    }
                }
            })
            { IsBackground = true };
            workers.Add(worker);
            worker.Start();
        }
        foreach (var worker in workers)
        {
            worker.Join();
        }

        Assert.True(sawOk > 0, "the entry point should mostly succeed");
        Assert.True(sawBusy > 0, "hammering for up to ten seconds should collide with the poll thread at least once");
    }

    /// <summary>
    /// Forces a full garbage collection with a call in flight, proving
    /// the kept-alive <c>SipralEventCallback</c> delegate
    /// <see cref="SipralStack"/> hands the native side is not collected
    /// while it is still registered — see that field's own doc comment
    /// for why keeping it on the instance is enough.
    /// </summary>
    [Fact]
    public async Task EventCallbackSurvivesGarbageCollectionPressure()
    {
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync();
        try
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            bobCall.SendDtmf("7");
            var digit = await FirstAsync(aliceCall.Dtmf, Timeout);
            Assert.Equal('7', digit);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    /// <summary>
    /// Disposes both stacks while a call is up and nothing has drained
    /// either stack's <see cref="SipralStack.Events"/>, so events are
    /// still queued behind the channel's writer at the moment
    /// <see cref="SipralStack.Dispose"/> runs. Passing proves there is no
    /// use-after-free on the handles those queued events still carry —
    /// <see cref="SipralStack.Dispose"/> joins the poll thread and
    /// destroys the stack only after every call has been hung up and
    /// closed, never while one might still be delivering.
    /// </summary>
    [Fact]
    public async Task DisposeWhileEventsArePendingDoesNotUseAfterFree()
    {
        var alice = new SipralStack(audio: SipralAudio.Application);
        var bob = new SipralStack(audio: SipralAudio.Application);
        var aliceAccount = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);
        alice.PlaceCall(aliceAccount, $"sip:bob@{bob.BindAddress}");

        await Task.Delay(300); // let the INVITE, the 200 nobody answered yet, and its retransmits pile up

        bob.Dispose();
        alice.Dispose();
    }

    /// <summary>
    /// A handler on <see cref="SipralStack.EventReceived"/> that throws
    /// must not unwind back into the native poll call it runs inside of
    /// (<c>docs/08-ffi.md</c>'s "the callback does not unwind", stated by
    /// name for the Kotlin listener and no less true here) — before this
    /// was guarded, this exact scenario took the whole test process down
    /// rather than failing the one test (confirmed with a throwaway
    /// console repro outside xunit, since a crash here would abort the
    /// run instead of reporting a failure). Proves both that the poll
    /// thread survives a throwing handler and that it keeps delivering
    /// events afterwards — a swallowed exception that quietly stopped the
    /// poll thread would hang this test's own second wait forever.
    /// </summary>
    [Fact]
    public async Task ExceptionFromAnEventHandlerDoesNotCrashTheProcessAndPollingContinues()
    {
        using var stack = new SipralStack(audio: SipralAudio.Application);
        var afterThrow = new SemaphoreSlim(0);
        var threw = 0;
        stack.EventReceived += (_, args) =>
        {
            if (Interlocked.Exchange(ref threw, 1) == 0)
            {
                throw new InvalidOperationException("deliberate failure from a test event handler");
            }
            afterThrow.Release();
        };

        var account = stack.AddAccount(
            "sip:alice@sipral.invalid", registrarAddress: "127.0.0.1:9", registrar: "sip:registrar.invalid");
        account.Register(); // a registrar nobody answers on this machine: keeps the poll thread producing further events to retry on

        Assert.True(await afterThrow.WaitAsync(Timeout), "the poll thread should still be delivering events after a handler threw");
    }

    /// <summary>
    /// Same guard, for <see cref="CallMedia.FrameDecoded"/> on the media's
    /// own frame-rate thread: an unhandled exception on any .NET thread
    /// ends the whole process by default, so a throwing handler there must
    /// not either, and the media pump must keep running afterwards.
    /// </summary>
    [Fact]
    public async Task ExceptionFromFrameDecodedDoesNotCrashTheProcessAndPlaybackContinues()
    {
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync();
        try
        {
            var frameSamples = aliceCall.Media!.FrameSamples;
            var tone = new short[frameSamples];
            Array.Fill(tone, (short)4096);

            var threw = 0;
            bobCall.Media!.FrameDecoded += _ =>
            {
                Interlocked.Exchange(ref threw, 1);
                throw new InvalidOperationException("deliberate failure from a test frame handler");
            };

            // The media thread was already decoding silence before this
            // subscription (it starts the moment `Media` is minted), so
            // the first throw can land before this test ever reads a
            // frame off `Frames` — wait for the throw on its own terms
            // rather than tying it to a particular frame's arrival.
            var deadline = DateTime.UtcNow + Timeout;
            while (Volatile.Read(ref threw) == 0 && DateTime.UtcNow < deadline)
            {
                await Task.Delay(10);
            }
            Assert.Equal(1, threw);

            for (var i = 0; i < 5; i++)
            {
                aliceCall.Media.SendAudio(tone);
            }
            var heardAfter = await FirstAsync(bobCall.Media.Frames, Timeout);
            Assert.Equal(frameSamples, heardAfter.Length);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    private static async Task<T> FirstAsync<T>(IAsyncEnumerable<T> source, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
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
        throw new TimeoutException($"no item arrived within {timeout}");
    }

    private static async Task<T> FirstMatchingAsync<T>(IAsyncEnumerable<T> source, Func<T, bool> predicate, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
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
        throw new TimeoutException($"no matching item arrived within {timeout}");
    }
}

/// <summary>
/// <c>maxDialogs</c> reaches the stack: at a ceiling of one call, the
/// second call placed is refused with <see cref="SipralStatus.LimitReached"/>.
/// </summary>
public sealed class ACeilingOnCallsTests
{
    [Fact]
    public void ACallPlacedPastMaxDialogsIsRefused()
    {
        using var alice = new SipralStack(audio: SipralAudio.Application, maxDialogs: 1);
        using var bob = new SipralStack(audio: SipralAudio.Application);
        var account = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);

        var first = alice.PlaceCall(account, $"sip:bob@{bob.BindAddress}");
        try
        {
            var refused = Assert.Throws<SipralException>(
                () => alice.PlaceCall(account, $"sip:bob@{bob.BindAddress}"));
            Assert.Equal(SipralStatus.LimitReached, refused.Status);
        }
        finally
        {
            first.Close();
        }
    }
}
