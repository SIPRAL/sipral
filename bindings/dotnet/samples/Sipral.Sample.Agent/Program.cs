// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

// A headless voice agent: answers, listens, echoes, hangs up on "#".
//
// The .NET counterpart of bindings/python/examples/agent.py, over this same
// layer's public surface (Sipral.SipralStack, Sipral.Account, Sipral.Call):
// registers if SIPRAL_REGISTRAR is given, answers whatever calls arrive,
// echoes audio back a frame at a time, prints each DTMF digit and hangs up
// once "#" is heard, then prints what the call cost.
//
//   SIPRAL_AOR=sip:agent@example.invalid \
//   SIPRAL_REGISTRAR=sip:example.invalid \
//   SIPRAL_REGISTRAR_ADDRESS=203.0.113.10:5060 \
//   SIPRAL_AUTH_USER=agent SIPRAL_AUTH_PASSWORD=secret \
//   dotnet run --project bindings/dotnet/samples/Sipral.Sample.Agent
//
// Doubles as the sample apps' shared, non-UI core: the same register/place
// or answer/hold/resume/DTMF calls the WPF sample's UI makes, run here
// without one, which is what scripts/lab.sh runs headless in a container
// on the lab network as labuser-agent-csharp.

using System.Net;
using System.Net.Sockets;
using Sipral;

// Which of this host's addresses a datagram to `address` leaves from. That
// address goes in the Contact and in every answer's SDP, so it has to be
// one the far end can send to: connecting a datagram socket sends nothing,
// it only asks the system which route it would take — the same trick
// bindings/python/examples/agent.py's own route_to plays.
static string RouteTo(string address)
{
    var (host, port) = SipralStack.ParseAddress(address);
    using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    probe.Connect(IPAddress.Parse(host), port);
    return ((IPEndPoint)probe.LocalEndPoint!).Address.ToString();
}

// The one function a real agent replaces. Default: an echo.
static short[] Respond(short[] pcm) => pcm;

async Task RunCallAsync(Call call, int tag)
{
    Console.WriteLine($"answered {tag:x}");
    var media = await call.WaitForMediaAsync();
    if (media is null)
    {
        Console.WriteLine($"ended {tag:x}: never reached media");
        call.Close();
        return;
    }

    using var stop = new CancellationTokenSource();
    SipralStreamStatistics? stats = null;

    var talking = Task.Run(async () =>
    {
        try
        {
            await foreach (var heard in media.Frames.WithCancellation(stop.Token))
            {
                media.SendAudio(Respond(heard));
            }
        }
        catch (OperationCanceledException)
        {
        }
    });

    // Kept fresh at a steady interval, not read once after the call is seen
    // to have ended: once the far end's BYE is answered the stack tears
    // this call's media down on its own poll thread, so by the time either
    // task below notices the call is over, a statistics call can already
    // answer with the ABI's WRONG_STATE (docs/08-ffi.md:
    // sipral_media_statistics's end-of-call record "arrives instead as
    // SIPRAL_EVENT_KIND_MEDIA_STATISTICS ... because by then the stream is
    // gone"). A read that lands mid-teardown is skipped, not fatal --
    // `stats` just keeps its last good reading, at most one interval stale.
    var polling = Task.Run(async () =>
    {
        try
        {
            while (true)
            {
                try
                {
                    stats = media.Statistics();
                }
                catch (SipralException)
                {
                }
                await Task.Delay(TimeSpan.FromMilliseconds(200), stop.Token);
            }
        }
        catch (OperationCanceledException)
        {
        }
    });

    var hangingUp = Task.Run(async () =>
    {
        await foreach (var digit in call.Dtmf.WithCancellation(stop.Token))
        {
            Console.WriteLine($"dtmf {digit}");
            if (digit == '#')
            {
                // One last read while the call is still certainly up, for
                // the freshest number this path can give.
                try
                {
                    stats = media.Statistics();
                }
                catch (SipralException)
                {
                }
                call.Hangup();
                return;
            }
        }
    });

    var endingRemotely = Task.Run(async () =>
    {
        await foreach (var _ in call.Events.WithCancellation(stop.Token))
        {
            if (call.Ended)
            {
                return;
            }
        }
    });

    await Task.WhenAny(hangingUp, endingRemotely);
    stop.Cancel();
    await Task.WhenAll(talking, polling, hangingUp, endingRemotely).ContinueWith(_ => { });

    call.Close();
    Console.WriteLine(
        $"ended {tag:x}: packets_received={stats?.PacketsReceived ?? 0} " +
        $"packets_sent={stats?.PacketsSent ?? 0}");
}

var registrarAddress = Environment.GetEnvironmentVariable("SIPRAL_REGISTRAR_ADDRESS")
    ?? throw new InvalidOperationException("SIPRAL_REGISTRAR_ADDRESS is required");
var bindHost = RouteTo(registrarAddress);
using var stack = new SipralStack(bindHost: bindHost);

var registrar = Environment.GetEnvironmentVariable("SIPRAL_REGISTRAR");
var account = stack.AddAccount(
    Environment.GetEnvironmentVariable("SIPRAL_AOR") ?? "sip:agent@example.invalid",
    registrarAddress: registrarAddress,
    registrar: registrar,
    authUser: Environment.GetEnvironmentVariable("SIPRAL_AUTH_USER"),
    authPassword: Environment.GetEnvironmentVariable("SIPRAL_AUTH_PASSWORD"));
if (!string.IsNullOrEmpty(registrar))
{
    account.Register();
}

Console.WriteLine($"listening on {stack.BindAddress}");

// Kept only so a call's own failure is reported rather than lost the way an
// exception in a task nobody awaits otherwise is; each removes itself the
// moment it finishes; the same shape bindings/python/examples/agent.py's
// own `calls` set and `report_failure` are, for the same reason.
var calls = new HashSet<Task>();
var nextTag = 0;
await foreach (var e in stack.Events)
{
    if (e.Kind == SipralEventKind.IncomingCall)
    {
        var call = stack.AnswerCall(e, mediaHost: bindHost);
        var tag = ++nextTag;
        Task? task = null;
        task = RunCallAsync(call, tag).ContinueWith(t =>
        {
            if (t.Exception is not null)
            {
                Console.WriteLine($"call failed: {t.Exception.GetBaseException()}");
            }
            calls.Remove(task!);
        });
        calls.Add(task);
    }
}
