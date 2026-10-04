// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// What a call carries inside its audio, and how it is recorded, through
/// this layer — the .NET counterpart of
/// <c>bindings/python/tests/test_inband.py</c>: two stacks on 127.0.0.1
/// that offer no telephone event, so a digit can only cross as its two
/// tones; a caller told to listen for who answered; the beep that says a
/// call is recorded; and the files a recording writes.
/// </summary>
public sealed class InBandTests : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    private readonly SipralStack _alice = new(audio: SipralAudio.Application, codecs: "PCMU", offerDtmf: false);
    private readonly SipralStack _bob = new(audio: SipralAudio.Application, codecs: "PCMU", offerDtmf: false);
    private readonly string _scratch = Directory.CreateTempSubdirectory("sipral-inband-").FullName;

    public void Dispose()
    {
        _alice.Dispose();
        _bob.Dispose();
        try
        {
            Directory.Delete(_scratch, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private async Task<(Call Alice, Call Bob)> PlaceAndAnswerAsync(Action<Call>? beforeAnswer = null)
    {
        var aliceAccount = _alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: _bob.BindAddress);
        _bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: _alice.BindAddress);
        var aliceCall = _alice.PlaceCall(aliceAccount, $"sip:bob@{_bob.BindAddress}");
        beforeAnswer?.Invoke(aliceCall);
        var incoming = await FirstMatchingAsync(_bob.Events, e => e.Kind == SipralEventKind.IncomingCall, Timeout);
        var bobCall = _bob.AnswerCall(incoming);
        using var cts = new CancellationTokenSource(Timeout);
        Assert.NotNull(await aliceCall.WaitForMediaAsync(cts.Token));
        Assert.NotNull(await bobCall.WaitForMediaAsync(cts.Token));
        return (aliceCall, bobCall);
    }

    [Fact]
    public async Task ADigitCrossesInTheAudioWhereNoTelephoneEventWasOffered()
    {
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync();
        try
        {
            // past the far end's probation, so the first frame of the tone counts
            await Task.Delay(200);
            aliceCall.SendDtmf("7");
            Assert.Equal('7', await FirstMatchingAsync(bobCall.Dtmf, _ => true, Timeout));
            var heard = await FirstMatchingAsync(bobCall.Events, e => e.Kind == SipralEventKind.InBandDigit, Timeout);
            Assert.Equal(SipralDigitSource.InBand, heard.Media!.Source);
            Assert.Equal(7u, heard.Media.EventCode);
            Assert.InRange(heard.Media.HeldMs, 75UL, 125UL);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    [Fact]
    public async Task ACallToldNotToListenHearsNoDigit()
    {
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync();
        try
        {
            bobCall.SetDtmfDetection(SipralDtmfDetection.Off);
            await Task.Delay(200);
            aliceCall.SendDtmf("3");
            await Assert.ThrowsAsync<TimeoutException>(
                () => FirstMatchingAsync(bobCall.Dtmf, _ => true, TimeSpan.FromSeconds(1.5)));
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    [Fact]
    public async Task AStereoRecordingKeepsThisEndOnTheLeft()
    {
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync();
        try
        {
            var path = Path.Combine(_scratch, "stereo.wav");
            var media = aliceCall.Media!;
            media.Record(path, layout: SipralRecordingLayout.Stereo, sampleRate: 16_000);
            var frame = new short[media.FrameSamples];
            Array.Fill(frame, (short)3_000);
            for (var i = 0; i < 25; i++)
            {
                media.SendAudio(frame);
            }
            await Task.Delay(800);
            var (running, taken) = media.Recording;
            Assert.True(running);
            Assert.True(taken > 0);
            media.StopRecording();
            Assert.False(media.Recording.Running);

            var wav = await File.ReadAllBytesAsync(path);
            Assert.Equal("RIFF"u8.ToArray(), wav[..4]);
            Assert.Equal(2, BinaryPrimitives.ReadUInt16LittleEndian(wav.AsSpan(58)));
            Assert.Equal(16_000u, BinaryPrimitives.ReadUInt32LittleEndian(wav.AsSpan(60)));
            Assert.Equal((uint)(wav.Length - 80), BinaryPrimitives.ReadUInt32LittleEndian(wav.AsSpan(76)));
            var left = Enumerable.Range(0, (wav.Length - 80) / 4)
                .Select(i => BinaryPrimitives.ReadInt16LittleEndian(wav.AsSpan(80 + i * 4)));
            Assert.Contains(left, sample => Math.Abs(sample - 3_000) < 100);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    [Fact]
    public async Task AnOggOpusRecordingIsAnOpusStream()
    {
        if ((global::Sipral.Sipral.Capabilities().Features & global::Sipral.Sipral.FeatureOpus) == 0)
        {
            return;
        }
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync();
        try
        {
            var path = Path.Combine(_scratch, "call.opus");
            aliceCall.Media!.Record(path, SipralRecordingFormat.OggOpus);
            await Task.Delay(500);
            aliceCall.Media.StopRecording();
            var data = await File.ReadAllBytesAsync(path);
            Assert.Equal("OggS"u8.ToArray(), data[..4]);
            Assert.True(data.AsSpan(0, 64).IndexOf("OpusHead"u8) >= 0);
            Assert.True(data.AsSpan().IndexOf("OpusTags"u8) >= 0);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    [Fact]
    public async Task AGreetingThatRunsOnIsReportedAsAMachine()
    {
        // a short greeting limit, so the decision comes in a second
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync(
            call => call.DetectProgress(new SipralProgressOptions { MaxGreetingMs = 600, Beep = false }));
        try
        {
            var rate = bobCall.Media!.Info().SampleRate;
            var greeting = new short[rate * 2];
            for (var n = 0; n < greeting.Length; n++)
            {
                var voiced = n / (int)(rate / 5) % 2 == 0;
                var t = (double)n / rate;
                greeting[n] = voiced
                    ? (short)Math.Round(6_000 * Math.Sin(2 * Math.PI * 180 * t) * (1 + 0.5 * Math.Sin(2 * Math.PI * 700 * t)))
                    : (short)0;
            }
            bobCall.Media.SendAudio(greeting);
            var heard = await FirstMatchingAsync(aliceCall.Events, e => e.Kind == SipralEventKind.ProgressDetected, Timeout);
            Assert.Equal(SipralProgressKind.AnsweredBy, heard.Progress!.What);
            Assert.Equal(SipralAmdVerdict.Machine, heard.Progress.Verdict);
            Assert.True(heard.Progress.AtMs > 0);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    [Fact]
    public async Task TheConsentToneReachesTheFarEndWhileRecording()
    {
        var (aliceCall, bobCall) = await PlaceAndAnswerAsync();
        try
        {
            aliceCall.SetConsentTone(intervalMs: 1_000);
            aliceCall.Media!.Record(Path.Combine(_scratch, "consent.wav"));
            var loud = await FirstMatchingAsync(
                bobCall.Media!.Frames, frame => frame.Max(sample => Math.Abs((int)sample)) > 1_000, TimeSpan.FromSeconds(3));
            Assert.NotNull(loud);
            aliceCall.Media.StopRecording();
            aliceCall.ClearConsentTone();
            Assert.Throws<SipralException>(() => aliceCall.SetConsentTone(frequencyHz: 5_000));
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
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
