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
// SIPRAL_SIGNALLING is udp (the default), tcp or tls: over either of the
// last two the agent keeps one connection to SIPRAL_REGISTRAR_ADDRESS and
// signals on it, and over TLS checks the server's certificate against
// SIPRAL_TLS_SERVER_NAME (the address's host when unset) with SIPRAL_TLS_CA
// as the only authority it trusts (the platform's when unset). A connection
// that fails is printed as "transport failed error=<...> tls=<...>" with
// SslStream's own words, and tried again. SIPRAL_INVITE_LIMIT=voice-agent
// takes a trunk's rush of calls the default rate floor would answer 480.
//
// Doubles as the sample apps' shared, non-UI core: the same register/place
// or answer/hold/resume/DTMF calls the WPF sample's UI makes, run here
// without one, which is what scripts/lab.sh runs headless in a container
// on the lab network as labuser-agent-csharp.
//
// The one sample that handles frames itself, because a voice agent's frames
// are its whole job: its stack is created with audio: SipralAudio.Application,
// which is also what a machine with no sound device runs. The WPF sample lets
// the library open the devices instead and has no audio code at all.

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
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

// "NameMismatch" as the other agents print it, "name_mismatch"
static string Snake(string name) =>
    string.Concat(name.Select((ch, at) => at > 0 && char.IsUpper(ch) ? "_" + char.ToLowerInvariant(ch) : char.ToLowerInvariant(ch).ToString()));

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
    // answer with the ABI's WRONG_STATE (bindings/c/include/sipral.h:
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

// Talk for the life of one call this end placed against a peer with
// nothing of its own that would ever hang up first (the lab's own
// two-NAT pair, scripts/lab.sh's ice_turn_flow, where the far end is the
// harness's own iceanswer role rather than a server): patienceMs is how
// long this end waits for media at all, so a call under SipralIce.Required
// with every path blocked is given up on rather than waited on forever,
// and dwellMs is how long it talks before hanging up on its own once
// media has started. false when it ended before media ever started, which
// RunDirectCallAsync needs to tell apart from an ordinary hangup.
async Task<bool> RunCallDirectAsync(Call call, int patienceMs, int dwellMs)
{
    Console.WriteLine("answered");
    using var mediaWait = new CancellationTokenSource(patienceMs);
    CallMedia? media;
    try
    {
        media = await call.WaitForMediaAsync(mediaWait.Token);
    }
    catch (OperationCanceledException)
    {
        Console.WriteLine($"ended: no media within {patienceMs}ms -- no path was ever chosen");
        try
        {
            call.Hangup();
        }
        catch (SipralException)
        {
        }
        call.Close();
        return false;
    }
    if (media is null)
    {
        Console.WriteLine("ended: no media -- the call never connected");
        call.Close();
        return false;
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
    var dwelling = Task.Delay(dwellMs);

    await Task.WhenAny(dwelling, endingRemotely);
    if (!call.Ended)
    {
        // one last read while the call is still certainly up, for the
        // freshest number this path can give
        try
        {
            stats = media.Statistics();
        }
        catch (SipralException)
        {
        }
        try
        {
            call.Hangup();
        }
        catch (SipralException)
        {
        }
        // the relayed call's farewell -- the TURN Refresh that gives its
        // allocation back, not only the RTCP BYE -- is queued once the far
        // end's 200 to this end's own BYE is read on the poll thread, so
        // this waits for it rather than closing right behind Hangup()
        await Task.WhenAny(endingRemotely, Task.Delay(5000));
    }
    stop.Cancel();
    await Task.WhenAll(talking, polling, endingRemotely).ContinueWith(_ => { });
    // the same short wait bindings/python/examples/agent.py's own
    // hang_up_after_dwell gives, so a relayed call's farewell has had its
    // own turn on the poll thread before the stack tears the socket down
    await Task.Delay(200);

    call.Close();
    Console.WriteLine(
        $"ended: packets_sent={stats?.PacketsSent ?? 0} packets_received={stats?.PacketsReceived ?? 0}");
    return true;
}

// Dial a peer straight at its address, no registrar between them --
// scripts/lab.sh's own ice_turn_flow, where the far end is the harness's
// own iceanswer role rather than a server. SIPRAL_PEER_HOST/
// SIPRAL_PEER_PORT name it, and the account this end adds is one whose
// registrarAddress is just the routing destination for: registrar is
// left null, so nothing is ever registered.
//
// SIPRAL_STUN_SERVER turns on STUN the same way SipralStack's constructor
// already offers any application; SIPRAL_TURN_SERVER/SIPRAL_TURN_USER/
// SIPRAL_TURN_PASSWORD ride on it. SIPRAL_TURN_TRANSPORT is udp, tcp or
// tls (RFC 8656 §3.1); over TLS the server's certificate is checked
// against SIPRAL_TURN_NAME and trusted if it chains to the PEM file
// SIPRAL_TURN_CA names, the platform's roots otherwise -- the lab's own
// coturn presents a certificate made for the run, and this is how the run
// tells the agent to trust it. SIPRAL_ICE=required asks
// SipralIce.Required of the stack, which is what makes a call that
// cannot find a path fail outright rather than fall back to the address
// this end bound to -- the one thing that would let a run through a
// blocked NAT pair pass by accident.
async Task<bool> RunDirectCallAsync()
{
    var peerHost = Environment.GetEnvironmentVariable("SIPRAL_PEER_HOST")
        ?? throw new InvalidOperationException("SIPRAL_PEER_HOST is required");
    var peerPort = Environment.GetEnvironmentVariable("SIPRAL_PEER_PORT") ?? "5060";
    var peerUser = Environment.GetEnvironmentVariable("SIPRAL_PEER_USER") ?? "callee";
    var peer = $"{peerHost}:{peerPort}";
    var host = RouteTo(peer);

    var stunServer = Environment.GetEnvironmentVariable("SIPRAL_STUN_SERVER");
    var turnServer = Environment.GetEnvironmentVariable("SIPRAL_TURN_SERVER");
    var ice = Environment.GetEnvironmentVariable("SIPRAL_ICE") == "required" ? SipralIce.Required : (SipralIce?)null;
    // left unset without SIPRAL_TURN_TRANSPORT: the stack refuses a TURN
    // transport named with no TURN server to use it on, and the lab's call
    // that must find no path without TURN has to be placed to prove it
    var over = Environment.GetEnvironmentVariable("SIPRAL_TURN_TRANSPORT");
    var turnTransport = over switch
    {
        null => default,
        "udp" => SipralTransport.Udp,
        "tcp" => SipralTransport.Tcp,
        "tls" => SipralTransport.Tls,
        _ => throw new InvalidOperationException($"SIPRAL_TURN_TRANSPORT is udp, tcp or tls, not {over}"),
    };
    X509Certificate2Collection? trusted = null;
    if (Environment.GetEnvironmentVariable("SIPRAL_TURN_CA") is { } caPath)
    {
        trusted = new X509Certificate2Collection();
        trusted.ImportFromPemFile(caPath);
    }

    using var stack = new SipralStack(
        bindHost: host,
        audio: SipralAudio.Application,
        ice: ice ?? 0,
        nat: stunServer is not null ? SipralNat.Stun : 0,
        stunServer: stunServer,
        turnServer: turnServer,
        turnUsername: Environment.GetEnvironmentVariable("SIPRAL_TURN_USER"),
        turnPassword: Environment.GetEnvironmentVariable("SIPRAL_TURN_PASSWORD"),
        turnTransport: turnTransport,
        turnServerName: Environment.GetEnvironmentVariable("SIPRAL_TURN_NAME"),
        turnTrustedCertificates: trusted);
    var account = stack.AddAccount($"sip:caller@{stack.BindAddress}", registrarAddress: peer);
    Console.WriteLine($"dialling sip:{peerUser}@{peer} from {stack.BindAddress}");
    Call call;
    try
    {
        call = stack.PlaceCall(account, $"sip:{peerUser}@{peer}", mediaHost: host, destination: peer, ice: ice ?? 0);
    }
    catch (SipralException error)
    {
        Console.WriteLine($"call failed: {error}");
        return false;
    }
    var patienceMs = int.Parse(Environment.GetEnvironmentVariable("SIPRAL_PATIENCE_MS") ?? "20000");
    var dwellMs = int.Parse(Environment.GetEnvironmentVariable("SIPRAL_DWELL_MS") ?? "2000");
    var ok = await RunCallDirectAsync(call, patienceMs, dwellMs);
    if (ok && turnServer is not null && over is "tcp" or "tls")
    {
        Console.WriteLine($"relay over {over.ToUpperInvariant()} to {turnServer}: the call ran through it");
    }
    return ok;
}

// The lab's own NAT-pair flow (ice_turn_flow) runs this mode instead of
// the registrar-and-listen one below: SIPRAL_PEER_HOST is what tells the
// two apart, since a real registrar address never doubles as one -- the
// same tell bindings/python/examples/agent.py's own main reads.
if (Environment.GetEnvironmentVariable("SIPRAL_PEER_HOST") is not null)
{
    if (!await RunDirectCallAsync())
    {
        Environment.Exit(1);
    }
    return;
}

var registrarAddress = Environment.GetEnvironmentVariable("SIPRAL_REGISTRAR_ADDRESS")
    ?? throw new InvalidOperationException("SIPRAL_REGISTRAR_ADDRESS is required");
var bindHost = RouteTo(registrarAddress);
var signalling = Environment.GetEnvironmentVariable("SIPRAL_SIGNALLING") switch
{
    null or "" or "udp" => SipralTransport.Udp,
    "tcp" => SipralTransport.Tcp,
    "tls" => SipralTransport.Tls,
    var other => throw new InvalidOperationException($"SIPRAL_SIGNALLING is udp, tcp or tls, not {other}"),
};
var tlsCa = Environment.GetEnvironmentVariable("SIPRAL_TLS_CA");
using var stack = new SipralStack(
    bindHost: bindHost,
    audio: SipralAudio.Application,
    signalling: signalling,
    signallingServer: signalling == SipralTransport.Udp ? null : registrarAddress,
    tlsServerName: Environment.GetEnvironmentVariable("SIPRAL_TLS_SERVER_NAME"),
    tlsTrust: tlsCa is null ? null : SipralTlsTrust.OnlyAuthority(X509Certificate2.CreateFromPem(File.ReadAllText(tlsCa))),
    inviteLimit: Environment.GetEnvironmentVariable("SIPRAL_INVITE_LIMIT") == "voice-agent"
        ? SipralInviteLimit.VoiceAgent
        : null);

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
    if (e.TransportFailed is { } failed)
    {
        Console.WriteLine(
            $"transport failed error={Snake(failed.Error.ToString())} tls={Snake(failed.Tls.ToString())}: {failed.Detail}");
    }
    if (e.Registration is { } registration)
    {
        Console.WriteLine($"registration {(uint)registration.State}");
    }
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
