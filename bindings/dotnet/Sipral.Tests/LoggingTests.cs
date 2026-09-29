// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// The log, the state snapshot and the RTP port range, carried through
/// <see cref="SipralStack"/> — the .NET counterpart of
/// <c>bindings/python/tests/test_logging.py</c>.
/// </summary>
public sealed class LoggingTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    /// <summary>A call the stack refuses: a stack with no RTP range has no
    /// port to reserve.</summary>
    private static SipralStatus Refuse(SipralStack stack) =>
        NativeMethods.sipral_stack_rtp_port_reserve(stack.Handle, out _);

    [Fact]
    public void ARefusedCallIsLoggedWithNobodyInIt()
    {
        using var stack = new SipralStack(audio: SipralAudio.Application);
        Assert.True(SipralStack.HasFeature(global::Sipral.Sipral.FeatureLogging));
        var heard = new ConcurrentQueue<(SipralLogLevel Level, string Target, string Message, ulong Suppressed)>();
        using var arrived = new ManualResetEventSlim();
        stack.SetLog(SipralLogLevel.Debug, (level, target, message, suppressed) =>
        {
            heard.Enqueue((level, target, message, suppressed));
            arrived.Set();
        });

        Assert.Equal(SipralStatus.WrongState, Refuse(stack));
        Assert.True(arrived.Wait(Timeout));
        Assert.True(heard.TryPeek(out var line));
        Assert.Equal(SipralLogLevel.Debug, line.Level);
        Assert.Equal("api", line.Target);
        Assert.StartsWith("refused, WrongState", line.Message);
        Assert.Equal(0ul, line.Suppressed);

        stack.SetLog(SipralLogLevel.Off, null);
        var count = heard.Count;
        Assert.Equal(SipralStatus.WrongState, Refuse(stack));
        Assert.Equal(count, heard.Count);
    }

    [Fact]
    public void TheStateNamesTheAccountAndNotThePerson()
    {
        using var stack = new SipralStack(audio: SipralAudio.Application);
        stack.AddAccount("sip:alice@example.invalid", registrarAddress: "127.0.0.1:5999");
        var text = stack.State();
        Assert.Contains("accounts: 1", text);
        Assert.Contains("transports: 1", text);
        Assert.Contains("counters: ", text);
        Assert.DoesNotContain("alice", text);
        Assert.DoesNotContain("127.0.0.1", text);
    }

    [Fact]
    public async Task ACallIsCarriedOnEvenPortsFromEachStacksRange()
    {
        using var alice = new SipralStack(audio: SipralAudio.Application, rtpPortMin: 46500, rtpPortMax: 46519);
        using var bob = new SipralStack(audio: SipralAudio.Application, rtpPortMin: 46600, rtpPortMax: 46619);
        var account = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);

        var aliceCall = alice.PlaceCall(account, $"sip:bob@{bob.BindAddress}");
        Call? bobCall = null;
        using var cts = new CancellationTokenSource(Timeout);
        await foreach (var e in bob.Events.WithCancellation(cts.Token))
        {
            if (e.Kind == SipralEventKind.IncomingCall)
            {
                bobCall = bob.AnswerCall(e);
                break;
            }
        }
        Assert.NotNull(bobCall);
        try
        {
            Assert.NotNull(await aliceCall.WaitForMediaAsync(cts.Token));
            Assert.NotNull(await bobCall!.WaitForMediaAsync(cts.Token));
            foreach (var (call, low, high) in new[] { (aliceCall, 46500, 46519), (bobCall, 46600, 46619) })
            {
                var port = ((IPEndPoint)call.MediaSocket.LocalEndPoint!).Port;
                Assert.True(port >= low && port < high && port % 2 == 0, $"{port}");
            }
        }
        finally
        {
            aliceCall.Close();
            bobCall?.Close();
        }
    }

    [Fact]
    public void ARangeWithNoPairLeftSaysSo()
    {
        using var stack = new SipralStack(audio: SipralAudio.Application, rtpPortMin: 46700, rtpPortMax: 46701);
        using var first = stack.OpenMediaSocket("127.0.0.1");
        Assert.Equal(46700, ((IPEndPoint)first.LocalEndPoint!).Port);
        var refused = Assert.Throws<SipralException>(() => stack.OpenMediaSocket("127.0.0.1"));
        Assert.Equal(SipralStatus.Exhausted, refused.Status);
    }
}
