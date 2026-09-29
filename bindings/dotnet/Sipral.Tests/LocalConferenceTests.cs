// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// A local conference through this layer — the .NET counterpart of
/// <c>bindings/python/tests/test_local_conference.py</c>: made on its own and
/// asked about, recorded, refused at a rate it cannot mix, and, with three
/// stacks on 127.0.0.1, two calls bridged so that what one far end says the
/// other hears.
/// </summary>
public sealed class LocalConferenceTests : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
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

    private SipralStack Stack() => Own(new SipralStack(audio: SipralAudio.Application, codecs: "PCMU"));

    private static short[] Square(int samples) =>
        Enumerable.Range(0, samples).Select(n => (short)((n / 8) % 2 == 0 ? 8000 : -8000)).ToArray();

    private static int Loudness(short[] frame) =>
        frame.Length == 0 ? 0 : (int)(frame.Sum(sample => Math.Abs((int)sample)) / frame.Length);

    private static async Task<T> FirstMatchingAsync<T>(IAsyncEnumerable<T> source, Func<T, bool> predicate)
    {
        using var cts = new CancellationTokenSource(Timeout);
        await foreach (var item in source.WithCancellation(cts.Token))
        {
            if (predicate(item))
            {
                return item;
            }
        }
        throw new TimeoutException("nothing matched");
    }

    [Fact]
    public async Task ThisEndIsItsFirstMemberAndIsAnnounced()
    {
        var stack = Stack();
        using var conference = new SipralLocalConference(stack, maxMembers: 3, sampleRate: 8000);
        var info = conference.Info();
        Assert.Equal((1u, 3u, 1u), (info.Members, info.Capacity, info.Local));
        Assert.Equal((8000u, 160), (conference.SampleRate, conference.FrameSamples));
        var members = conference.Members();
        Assert.Equal(conference.Handle, members[0].Member);
        Assert.Equal(256u, members[0].GainInput);

        conference.SetMuted(null, SipralAudioDirection.Input);
        conference.SetGain(null, SipralAudioDirection.Output, 128);
        members = conference.Members();
        Assert.True(members[0].MutedInput);
        Assert.Equal(128u, members[0].GainOutput);

        var changed = await FirstMatchingAsync(stack.Events, e => e.Kind == SipralEventKind.LocalConferenceChanged);
        Assert.Equal(conference.Handle, changed.LocalConference!.Conference);
        Assert.Equal(SipralLocalConferenceChange.Joined, changed.LocalConference.Change);
        Assert.Equal(conference.Handle, changed.LocalConference.Member);
        Assert.Equal(1u, changed.LocalConference.Members);
    }

    [Fact]
    public async Task TheMixIsRecordedToAFile()
    {
        var stack = Stack();
        var path = Path.Combine(Path.GetTempPath(), $"sipral-conference-{Guid.NewGuid():N}.wav");
        try
        {
            using (var conference = new SipralLocalConference(stack, maxMembers: 2, sampleRate: 16000))
            {
                conference.Record(path);
                for (var frame = 0; frame < 10; frame++)
                {
                    conference.SendAudio(Square(320));
                }
                await Task.Delay(300);
                Assert.Equal(1u, conference.Info().Recording);
                conference.StopRecording();
                var refused = Assert.Throws<SipralException>(() => conference.StopRecording());
                Assert.Equal(SipralStatus.WrongState, refused.Status);
            }
            var written = File.ReadAllBytes(path);
            Assert.Equal("RIFF"u8.ToArray(), written[..4]);
            Assert.True(written.Length > 44);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ARateItCannotMixIsRefused()
    {
        var stack = Stack();
        var refused = Assert.Throws<SipralException>(() => new SipralLocalConference(stack, sampleRate: 44100));
        Assert.Equal(SipralStatus.ConferenceRefused, refused.Status);
    }

    private async Task<(Call Near, Call Far)> CallAsync(SipralStack alice, SipralStack far, string user)
    {
        // an account of Alice's own for each far end, naming it as the next hop
        var account = alice.AddAccount($"sip:alice-to-{user}@sipral.invalid", registrarAddress: far.BindAddress);
        far.AddAccount($"sip:{user}@sipral.invalid", registrarAddress: alice.BindAddress);
        var near = Own(alice.PlaceCall(account, $"sip:{user}@{far.BindAddress}"));
        var incoming = await FirstMatchingAsync(far.Events, e => e.Kind == SipralEventKind.IncomingCall);
        var answered = Own(far.AnswerCall(incoming));
        using var cts = new CancellationTokenSource(Timeout);
        Assert.True(await near.WaitForConfirmedAsync(cts.Token));
        Assert.NotNull(await near.WaitForMediaAsync(cts.Token));
        Assert.NotNull(await answered.WaitForMediaAsync(cts.Token));
        return (near, answered);
    }

    /// <summary>Alice calls Bob and Carol and bridges the two calls, taking
    /// no part herself: what Bob says, Carol hears.</summary>
    [Fact]
    public async Task WhatOneFarEndSaysTheOtherHears()
    {
        var alice = Stack();
        var (toBob, bob) = await CallAsync(alice, Stack(), "bob");
        var (toCarol, carol) = await CallAsync(alice, Stack(), "carol");
        using var conference = new SipralLocalConference(alice, maxMembers: 2, local: false);
        conference.Add(toBob);
        conference.Add(toCarol);
        var refused = Assert.Throws<SipralException>(() => conference.Add(toBob));
        Assert.Equal(SipralStatus.ConferenceRefused, refused.Status);
        Assert.Equal(2u, conference.Info().Members);

        for (var frame = 0; frame < 100; frame++)
        {
            bob.Media!.SendAudio(Square(bob.Media.FrameSamples));
        }
        var loudest = await FirstMatchingAsync(carol.Media!.Frames, frame => Loudness(frame) > 2000);
        Assert.True(Loudness(loudest) > 2000, "Carol never heard Bob");
        // and steadily: a call whose own thread still carried frames beside
        // the conference would have every other frame taken from under it
        var steady = 0;
        var counted = 0;
        await FirstMatchingAsync(carol.Media.Frames, frame =>
        {
            steady += Loudness(frame) > 2000 ? 1 : 0;
            return ++counted == 25;
        });
        Assert.True(steady >= 20, $"Carol heard Bob in {steady} of 25 frames");

        conference.Remove(toCarol);
        Assert.Equal(1u, conference.Info().Members);
    }
}
