// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// The log, the state snapshot and the RTP port range.
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

    /// <summary>Every event a trace source passed on.</summary>
    private sealed class Caught : TraceListener
    {
        public ConcurrentQueue<(TraceEventType Type, int Id, string Message)> Events { get; } = new();
        public ManualResetEventSlim Arrived { get; } = new();

        public override void TraceEvent(TraceEventCache? cache, string source, TraceEventType type, int id, string? message)
        {
            Events.Enqueue((type, id, message ?? ""));
            Arrived.Set();
        }

        public override void Write(string? message)
        {
        }

        public override void WriteLine(string? message)
        {
        }
    }

    [Fact]
    public void ALineReachesATraceSourceAsItsEventType()
    {
        using var stack = new SipralStack(audio: SipralAudio.Application);
        var source = new TraceSource("sipral-test-verbose", SourceLevels.Verbose);
        var caught = new Caught();
        source.Listeners.Clear();
        source.Listeners.Add(caught);
        stack.LogTo(source);

        Assert.Equal(SipralStatus.WrongState, Refuse(stack));
        Assert.True(caught.Arrived.Wait(Timeout));
        Assert.True(caught.Events.TryPeek(out var line));
        Assert.Equal(TraceEventType.Verbose, line.Type);
        Assert.Equal((int)SipralLogLevel.Debug, line.Id);
        Assert.StartsWith("api: refused, WrongState", line.Message);
        Assert.Contains("log: debug,", StateOnceSettled(stack, "log: debug,"));
    }

    [Fact]
    public void TheStackIsAsQuietAsTheTraceSource()
    {
        using var stack = new SipralStack(audio: SipralAudio.Application);
        var source = new TraceSource("sipral-test-information", SourceLevels.Information);
        var caught = new Caught();
        source.Listeners.Clear();
        source.Listeners.Add(caught);
        stack.LogTo(source);

        Assert.Equal(SipralStatus.WrongState, Refuse(stack));
        Assert.Empty(caught.Events);
        Assert.Contains("log: info,", StateOnceSettled(stack, "log: info,"));
        Assert.Equal(SipralLogLevel.Trace, SipralStack.LogLevelFor(SourceLevels.All));
        Assert.Equal(SipralLogLevel.Off, SipralStack.LogLevelFor(SourceLevels.Off));
        Assert.Equal(TraceEventType.Warning, SipralStack.TraceEventTypeOf(SipralLogLevel.Warn));
    }

    /// <summary>Waits for <paramref name="expected"/>: while the poll holds
    /// the stack, the answer is the last kept snapshot.</summary>
    private static string StateOnceSettled(SipralStack stack, string expected)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(3);
        var text = stack.State();
        while (!text.Contains(expected) && DateTime.UtcNow < deadline)
        {
            Thread.Sleep(50);
            text = stack.State();
        }
        return text;
    }

    [Fact]
    public void ARequestNobodyAnswersIsCountedAsSentAgain()
    {
        using var silent = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        silent.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        using var stack = new SipralStack(audio: SipralAudio.Application);
        Assert.Equal(0ul, stack.Counters().RequestsRetransmitted);
        var account = stack.AddAccount(
            "sip:alice@sipral.invalid", $"127.0.0.1:{((IPEndPoint)silent.LocalEndPoint!).Port}",
            registrar: "sip:sipral.invalid");
        account.Register();

        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (stack.Counters().RequestsRetransmitted == 0 && DateTime.UtcNow < deadline)
        {
            Thread.Sleep(100);
        }
        var counters = stack.Counters();
        Assert.True(counters.RequestsRetransmitted > 0);
        Assert.True(counters.RegistrationsAttempted > 0);
        Assert.Equal(0ul, counters.RequestsRefusedAtLimit);
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
