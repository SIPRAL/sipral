// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Generic;
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

    private readonly SipralStack _alice = new();
    private readonly SipralStack _bob = new();

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
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
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
        using var stack = new SipralStack();
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
        using var stack = new SipralStack();
        var account = stack.AddAccount(
            "sip:alice@sipral.invalid", registrarAddress: "203.0.113.1:5060", registrar: "sip:registrar.invalid");
        account.Register(); // unreachable registrar: keeps the poll thread retransmitting

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
        var alice = new SipralStack();
        var bob = new SipralStack();
        var aliceAccount = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);
        alice.PlaceCall(aliceAccount, $"sip:bob@{bob.BindAddress}");

        await Task.Delay(300); // let the INVITE, the 200 nobody answered yet, and its retransmits pile up

        bob.Dispose();
        alice.Dispose();
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
