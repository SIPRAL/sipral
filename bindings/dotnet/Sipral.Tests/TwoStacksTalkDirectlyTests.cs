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
/// Two stacks on 127.0.0.1 talking directly: each account uses the other
/// stack's address as its outbound proxy, with no registrar, so no SIP
/// server is needed.
/// </summary>
public sealed class TwoStacksTalkDirectlyTests : IDisposable
{
    // generous: the machine may be shared with other heavy builds
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

    /// <summary>At 24 kHz both ends use 480-sample frames whatever the
    /// codec; an unsupported rate is refused; 0 restores the codec's.</summary>
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

            // the library's own count, read either side, brackets the copy
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

    /// <summary>The poll thread can look a call up for its MediaStarted
    /// just before the application's Close (or the stack's Dispose)
    /// forgets it and closes its socket. That late event starts nothing:
    /// it used to build the media over the closed socket and throw on the
    /// poll thread, inside the native callback, ending the process.</summary>
    [Fact]
    public async Task AMediaStartedThatLosesTheRaceWithCloseStartsNothing()
    {
        var aliceAccount = _alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: _bob.BindAddress);
        _bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: _alice.BindAddress);
        var aliceCall = _alice.PlaceCall(aliceAccount, $"sip:bob@{_bob.BindAddress}");
        await FirstMatchingAsync(_bob.Events, e => e.Kind == SipralEventKind.IncomingCall, Timeout);
        var handle = aliceCall.Handle;
        aliceCall.Close();

        var evt = global::Sipral.SipralEvent.Sized();
        evt.Kind = SipralEventKind.MediaStarted;
        evt.Call = handle;
        var raw = Marshal.AllocHGlobal(Marshal.SizeOf<global::Sipral.SipralEvent>());
        SipralEventArgs late;
        try
        {
            Marshal.StructureToPtr(evt, raw, false);
            late = SipralEventArgs.Decode(raw);
        }
        finally
        {
            Marshal.FreeHGlobal(raw);
        }

        aliceCall.Deliver(late);
        Assert.Null(aliceCall.Media);
    }

    /// <summary>The final statistics record is kept and served after the
    /// library answers <c>WRONG_STATE</c>.</summary>
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

    /// <summary>MEDIA_STATISTICS copies <c>frames_underrun</c> into
    /// <see cref="SipralStreamStatistics.FramesUnderrun"/>, not a neighbouring
    /// field.</summary>
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

            // The tone goes out a frame at a time for the whole window, so a
            // loaded machine that settles the hold late still has tone to carry.
            var tone = new short[aliceCall.Media!.FrameSamples];
            Array.Fill(tone, (short)8000);
            var loudest = 0;
            using var listening = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var speaking = Task.Run(async () =>
            {
                while (!listening.IsCancellationRequested)
                {
                    aliceCall.Media.SendAudio(tone);
                    await Task.Delay(20);
                }
            });
            try
            {
                await foreach (var frame in bobCall.Media!.Frames.WithCancellation(listening.Token))
                {
                    foreach (var sample in frame)
                    {
                        loudest = Math.Max(loudest, Math.Abs((int)sample));
                    }
                    if (loudest > 1000)
                    {
                        listening.Cancel();
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
            await speaking;
            return loudest;
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    /// <summary>A held party hears silence by default, even in application
    /// mode, and the application's frames with
    /// <see cref="SipralHeldAudio.Application"/>.</summary>
    [Fact]
    public async Task AHeldPartyHearsSilenceUnlessTheStackSaysTheApplication()
    {
        Assert.True(await LoudestHeardOnHoldAsync(SipralHeldAudio.Default) < 100,
            "the held party heard the application on a stack told nothing");
        Assert.True(await LoudestHeardOnHoldAsync(SipralHeldAudio.Application) > 1000,
            "the held party did not hear what the application sent");
    }

    /// <summary>Realms cross one per line: a comma stays inside a realm, a
    /// control byte is refused.</summary>
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
    /// The event callback runs on the polling thread, not the test's.
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
    /// A call colliding with the poll thread gets
    /// <see cref="SipralStatus.Busy"/> instead of waiting. Calls
    /// <see cref="NativeMethods"/> directly, since the binding's retry would
    /// hide it. The poll holds the lock only briefly, so the account
    /// registers first (giving each poll timer work) and threads spin for a
    /// bounded time until both BUSY and OK were seen.
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
        // modest: harder load would make neighbouring timing tests flaky
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
    /// A full GC with a call in flight does not collect the event callback
    /// delegate.
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
    /// Disposing with a call up and events still queued causes no
    /// use-after-free.
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
    /// A throwing <see cref="SipralStack.EventReceived"/> handler does not
    /// unwind into the native poll, and events keep coming afterwards. A
    /// stopped poll thread would hang the second wait.
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
    /// Same for <see cref="CallMedia.FrameDecoded"/> on the media thread.
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

            // the media thread may throw before any frame is read here
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
