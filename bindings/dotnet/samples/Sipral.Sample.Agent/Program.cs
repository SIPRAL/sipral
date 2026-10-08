// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// A headless voice agent: registers if SIPRAL_REGISTRAR is set, answers,
// echoes audio, prints DTMF digits, hangs up on "#", then prints the call's
// statistics.
//
//   SIPRAL_AOR=sip:agent@example.invalid \
//   SIPRAL_REGISTRAR=sip:example.invalid \
//   SIPRAL_REGISTRAR_ADDRESS=203.0.113.10:5060 \
//   SIPRAL_AUTH_USER=agent SIPRAL_AUTH_PASSWORD=secret \
//   dotnet run --project bindings/dotnet/samples/Sipral.Sample.Agent
//
// SIPRAL_SIGNALLING is udp (default), tcp or tls: one connection to
// SIPRAL_REGISTRAR_ADDRESS. TLS checks SIPRAL_TLS_SERVER_NAME (default: the
// address's host) against SIPRAL_TLS_CA as the only authority (default: the
// platform's). Failures print "transport failed error=<...> tls=<...>" and
// are retried. SIPRAL_INVITE_LIMIT=voice-agent accepts a trunk's burst of
// calls that the default limit would answer 480.
//
// SIPRAL_TEXT=1 answers with real-time text (RFC 4103) when offered and
// echoes what the caller types. SIPRAL_PRESENCE=1 publishes "Agent ready"
// (RFC 3903).
//
// scripts/lab.sh runs this headless as labuser-agent-csharp. It uses
// application audio mode, since handling frames is a voice agent's job; the
// WPF sample lets the library drive the devices instead.

using System.Security.Cryptography.X509Certificates;
using Sipral;

// This host's address toward `address`, for the Contact and the SDP. The
// library's route lookup sends nothing; it only picks the route, and asks
// again when the system answers with the wildcard.
static string RouteTo(string address) =>
    SipralStack.ParseAddress(SipralStack.AdvertisedAddress("0.0.0.0:0", address)).Host;

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

    // Polled while the call runs: once the far end's BYE is answered the
    // media is torn down and statistics answer WRONG_STATE. A read during
    // teardown is skipped; `stats` keeps the last good one.
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

    var typing = Task.Run(async () =>
    {
        if (call.TextAddress is null)
        {
            return;
        }
        try
        {
            await foreach (var typed in call.Text.WithCancellation(stop.Token))
            {
                Console.WriteLine($"text {typed}");
                call.SendText(typed);
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
                // last read while the call is surely up
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
    await Task.WhenAll(talking, typing, polling, hangingUp, endingRemotely).ContinueWith(_ => { });

    call.Close();
    Console.WriteLine(
        $"ended {tag:x}: packets_received={stats?.PacketsReceived ?? 0} " +
        $"packets_sent={stats?.PacketsSent ?? 0}");
}

// For a placed call whose peer never hangs up (lab ice_turn_flow).
// patienceMs bounds the wait for media, so a blocked ICE call gives up;
// dwellMs is how long to talk before hanging up. false when media never
// started.
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
        // last read while the call is surely up
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
        // the TURN Refresh is queued only after the 200 to our BYE, so wait
        await Task.WhenAny(endingRemotely, Task.Delay(5000));
    }
    stop.Cancel();
    await Task.WhenAll(talking, polling, endingRemotely).ContinueWith(_ => { });
    // let the relayed call's farewell go out before the socket closes
    await Task.Delay(200);

    call.Close();
    Console.WriteLine(
        $"ended: packets_sent={stats?.PacketsSent ?? 0} packets_received={stats?.PacketsReceived ?? 0}");
    return true;
}

// Dial SIPRAL_PEER_HOST:SIPRAL_PEER_PORT directly, never registering (lab
// ice_turn_flow).
//
// SIPRAL_STUN_SERVER enables STUN; SIPRAL_TURN_SERVER/USER/PASSWORD add
// TURN over SIPRAL_TURN_TRANSPORT (udp, tcp or tls, RFC 8656 §3.1). Over
// TLS the certificate is checked against SIPRAL_TURN_NAME and trusted via
// the PEM in SIPRAL_TURN_CA (the lab's coturn uses a per-run certificate).
// SIPRAL_ICE=required makes a call with no path fail outright instead of
// falling back to the bound address, which would let a blocked NAT run
// pass by accident.
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
    // left unset without TURN: the stack refuses a TURN transport with no
    // server, and the lab's no-TURN call must still be placed
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

// SIPRAL_PEER_HOST selects the direct-dial mode over register-and-listen.
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
if (Environment.GetEnvironmentVariable("SIPRAL_PRESENCE") == "1")
{
    account.PublishPresence(SipralBasic.Open, note: "Agent ready");
}
var text = Environment.GetEnvironmentVariable("SIPRAL_TEXT") == "1";

Console.WriteLine($"listening on {stack.BindAddress}");

// Kept so a call's failure is reported, not lost in an unawaited task.
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
    if (e.Presence is { } presence)
    {
        Console.WriteLine($"presence {Snake(presence.PublicationState.ToString())} status={presence.StatusCode}");
    }
    if (e.Kind == SipralEventKind.IncomingCall)
    {
        var call = stack.AnswerCall(e, mediaHost: bindHost, options: text ? new SipralCallOptions(Text: true) : null);
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
