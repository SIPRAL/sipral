// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Sipral.Interop;
using static Sipral.Interop.NativeText;

namespace Sipral;

/// <summary>
/// One <c>sipral_stack_create</c> handle, its UDP socket and the thread
/// that drains <c>sipral_stack_poll</c> and the transport queues.
///
/// <see cref="Dispose"/> calls <c>sipral_stack_destroy</c> exactly once.
/// A stack never disposed is released by a finalizer, but its port stays
/// taken until the collector runs, so dispose it.
/// </summary>
public sealed partial class SipralStack : IDisposable
{
    private const int TransmitBytes = 1 << 16;
    private const int AddressBytes = 128;

    private readonly StackSafeHandle _handle;
    // Replaced by MoveTo; the poll thread reads it afresh on every pass.
    private volatile Socket? _socket;
    private readonly Stopwatch _origin = Stopwatch.StartNew();
    private readonly SipralEventCallback _callback;
    // Kept alive with the stack: the audio engine calls it per packet.
    private readonly SipralAudioTransmitCallback _audioTransmit;
    private readonly List<Account> _accounts = new();
    // TURN connections the audio thread found broken. Reported from the
    // poll thread, since the engine's thread must not call into the stack.
    private readonly ConcurrentQueue<string> _turnLost = new();
    private readonly Thread _pollThread;
    private readonly ManualResetEventSlim _closed = new(initialState: false);
    private readonly ConcurrentDictionary<ulong, Call> _calls = new();
    private readonly Channel<SipralEventArgs> _events =
        Channel.CreateUnbounded<SipralEventArgs>(new UnboundedChannelOptions { SingleWriter = true });

    private readonly IntPtr _transmitData = Marshal.AllocHGlobal(TransmitBytes);
    private readonly IntPtr _transmitDestination = Marshal.AllocHGlobal(AddressBytes);
    private readonly IntPtr _transmitSource = Marshal.AllocHGlobal(AddressBytes);
    private readonly IntPtr _farewellData = Marshal.AllocHGlobal(TransmitBytes);
    private readonly IntPtr _farewellDestination = Marshal.AllocHGlobal(AddressBytes);
    private readonly IntPtr _stunData = Marshal.AllocHGlobal(TransmitBytes);
    private readonly IntPtr _stunDestination = Marshal.AllocHGlobal(AddressBytes);
    private readonly IntPtr _stunSource = Marshal.AllocHGlobal(AddressBytes);
    private readonly byte[] _receiveBuffer = new byte[TransmitBytes];
    private readonly byte[] _stunReceiveBuffer = new byte[TransmitBytes];

    // Set at creation, then by SetStunServers.
    private volatile SipralNat _nat;
    private readonly bool _turn;
    private readonly object _natLock = new();

    private readonly SipralTransport _turnTransport;
    private readonly string? _turnServerName;
    private readonly X509Certificate2Collection? _turnTrustedCertificates;

    // By the media socket's host:port.
    private readonly ConcurrentDictionary<string, TurnStream> _turnStreams = new();

    // TurnStream requests, acted on after the poll that raised them: the
    // callback must not call back into the stack.
    private readonly ConcurrentQueue<SipralTurnStreamEventInfo> _turnAsked = new();

    // A call's media socket, kept while its TURN connection stands: the
    // Refresh that frees the relay can come after the Call was forgotten.
    private readonly ConcurrentDictionary<ulong, string> _turnSockets = new();

    /// <summary>A media socket's TCP or TLS connection to the TURN server.
    /// Written by the poll and media threads, each write whole under
    /// <see cref="WriteLock"/>; read by its own thread.</summary>
    private sealed class TurnStream
    {
        public required TcpClient Client { get; init; }
        public required Stream Stream { get; init; }
        public object WriteLock { get; } = new();
    }

    // Media sockets under sipral_stack_nat_map, by host:port, from
    // MapMediaSocket until MediaStarted hands them to CallMedia or the call
    // gives up. Used by the calling and poll threads; _natLock guards this
    // and _natWaiters.
    private readonly Dictionary<string, Socket> _stunSockets = new();

    // Per socket, a wait for NatMapping and one for NatRelay. With a TURN
    // server a call waits for both, without one only for the first.
    private readonly Dictionary<string, (ManualResetEventSlim Mapping, ManualResetEventSlim Relay)> _natWaiters = new();

    private int _disposed;

    /// <summary>The address this stack listens on, <c>host:port</c>, new
    /// after <see cref="MoveTo"/>. With no <c>bindHost</c> it is the
    /// advertised address: the route toward the first account's server.</summary>
    public string BindAddress { get; private set; }

    /// <summary>Who pumps this stack's calls' audio: the library, from the
    /// platform's own devices (<see cref="SipralAudio.Device"/>), or the
    /// application, through <see cref="CallMedia"/>
    /// (<see cref="SipralAudio.Application"/>).</summary>
    public SipralAudio AudioMode { get; }

    /// <summary>The library's audio engine, in device mode: devices, roles,
    /// gain, mute, the meter, activation and the ring. On a stack in
    /// application mode every member throws <see cref="SipralException"/>
    /// with <see cref="SipralStatus.WrongState"/>.</summary>
    public SipralAudioEngine Audio { get; }

    /// <summary>The <c>Sipral.Feature*</c> bits this build has compiled in.
    /// <c>Sipral.FeatureAudioDevice</c> is set where the library can open the
    /// platform's audio devices; stacks there default to device mode.</summary>
    public static uint Features()
    {
        NativeLibraryLoader.EnsureRegistered();
        var capabilities = SipralCapabilities.Sized();
        SipralErrors.Check(NativeMethods.sipral_capabilities(ref capabilities), "sipral_capabilities");
        return capabilities.Features;
    }

    /// <summary>Whether <see cref="Features"/> has <paramref name="bit"/>, one
    /// of the <c>Sipral.Feature*</c> constants.</summary>
    public static bool HasFeature(uint bit) => (Features() & bit) == bit;

    /// <summary>
    /// Every event this stack raises, in order. Backed by an unbounded
    /// channel, so a slow reader never blocks the poll thread.
    /// </summary>
    public IAsyncEnumerable<SipralEventArgs> Events => _events.Reader.ReadAllAsync();

    /// <summary>
    /// Fired synchronously on the poll thread for every event. A handler may
    /// call back into the stack, but should be quick. Most applications want
    /// <see cref="Events"/> instead.
    /// </summary>
    public event EventHandler<SipralEventArgs>? EventReceived;

    /// <summary><c>sipral_stack_create</c>: binds the UDP socket and
    /// starts the poll thread, which raises
    /// <see cref="SipralEventKind.Started"/> on its first pass.
    ///
    /// <paramref name="ice"/> and <paramref name="nat"/> are <c>0</c> for off
    /// or a <see cref="SipralIce"/>/<see cref="SipralNat"/> value.
    /// <see cref="SipralNat.Stun"/> needs <paramref name="stunServer"/>
    /// (<c>host:port</c>); <paramref name="turnServer"/> with its credentials
    /// builds on it (<c>docs/06-nat.md</c>). Credentials never reach a log,
    /// event or exception. <see cref="SipralIce.Lite"/> is only for a server
    /// reachable at the address it advertises.
    ///
    /// <paramref name="referrals"/> <see langword="true"/> hands an
    /// out-of-dialog REFER (click-to-dial) to the application as
    /// <see cref="SipralEventKind.Referral"/>. Off by default, and each is
    /// refused 403: a peer that can make a phone dial is a toll-fraud vector.
    ///
    /// <paramref name="registrarKeepalive"/> (on by default) has every account
    /// STUN found behind a NAT send its registrar a double CRLF every
    /// <paramref name="registrarKeepaliveMs"/> (<c>0</c> for 25 s, 1 000 to
    /// 120 000), so the registrar's INVITE still gets in. An interval with it
    /// off is refused. Nothing is sent while suspended.
    ///
    /// <paramref name="turnTransport"/> is how media sockets reach
    /// <paramref name="turnServer"/> (RFC 8656 §3.1): UDP (<c>0</c>), TCP
    /// where no UDP gets out, or TLS (port 5349) where one port gets out or
    /// the server must be checked. The stack opens one connection per media
    /// socket. Over TLS the certificate is checked against
    /// <paramref name="turnServerName"/> (default: the host of
    /// <paramref name="turnServer"/>) with the platform's trust, or only with
    /// <paramref name="turnTrustedCertificates"/> when given. Checking cannot
    /// be turned off.
    ///
    /// <paramref name="audio"/> is who pumps the calls' audio.
    /// <see cref="SipralAudio.Device"/>: the library runs every call through
    /// the platform's microphone and speaker, controlled through
    /// <see cref="Audio"/>; packets still leave from each call's media
    /// socket. <see cref="SipralAudio.Application"/>: frames go through
    /// <see cref="CallMedia"/>. <see langword="null"/> picks device mode where
    /// <c>Sipral.FeatureAudioDevice</c> is set; device mode without it throws
    /// with <see cref="SipralStatus.NotSupported"/>.
    /// <paramref name="audioActivation"/> is when device mode opens the
    /// devices: <see cref="SipralAudioActivation.Automatic"/> with the first
    /// call's media or the first ring, closed with the last;
    /// <see cref="SipralAudioActivation.Manual"/> only between
    /// <see cref="SipralAudioEngine.Activate"/> and
    /// <see cref="SipralAudioEngine.Deactivate"/>.
    /// <paramref name="audioProbeMs"/> bounds every platform call (<c>0</c>
    /// for three seconds): a driver that does not answer is
    /// <see cref="SipralStatus.DeviceTimedOut"/>, not a hang.
    /// <paramref name="audioDeviceRateHz"/> is the rate the devices are asked
    /// for (<c>0</c> for 48 000).
    /// <paramref name="maxDialogs"/> is the most calls the stack holds at
    /// once, either way (<c>0</c> for 128): one that arrives past it is
    /// answered 503, and one placed past it is
    /// <see cref="SipralStatus.LimitReached"/>.
    /// <paramref name="maxServerTransactions"/> is the most requests from
    /// other ends it works on at once (<c>0</c> for 256).
    /// <paramref name="diagnosticDecisions"/> and
    /// <paramref name="diagnosticRecords"/> bound the diagnostic record:
    /// decisions kept per call (<c>0</c> for 64) and calls kept (<c>0</c>
    /// for 32).
    /// <paramref name="stunFallbacks"/> (<c>host:port</c>) are tried in order
    /// when <paramref name="stunServer"/> gives no address within 5.5 s. A
    /// failed server is skipped for 30 s, doubling up to ten minutes;
    /// <see cref="SipralEventKind.StunServer"/> reports each move.
    /// <paramref name="rtpPortMin"/> and <paramref name="rtpPortMax"/> are a
    /// firewall's open range: media sockets opened without a port bind an
    /// even port from it, the odd one above kept for RTCP (RFC 3550 §11).
    /// Both <c>0</c> (the default) leave ports to the OS. A full range throws
    /// with <see cref="SipralStatus.Exhausted"/>.
    /// <paramref name="dtmfDetection"/> is when a call listens for keypad
    /// digits in the far end's audio: <see cref="SipralDtmfDetection.Auto"/>
    /// on the calls that negotiated no telephone event, <c>Always</c> or
    /// <c>Off</c>; <see cref="Call.SetDtmfDetection"/> changes it for one
    /// call.
    ///
    /// <paramref name="signalling"/> is what SIP travels over: UDP (<c>0</c>)
    /// on a socket at <paramref name="bindHost"/>, or TCP/TLS on one
    /// connection to <paramref name="signallingServer"/> (<c>host:port</c>,
    /// 5061 for TLS by convention) shared by every account and call. Over TLS
    /// the certificate is checked against <paramref name="tlsServerName"/>
    /// (default: the server's host) with <paramref name="tlsTrust"/>
    /// (<c>docs/22-tls.md</c>); the check cannot be turned off.
    ///
    /// The first connection is made before this returns. When it fails or
    /// breaks, <see cref="SipralEventKind.TransportFailed"/> says why, and
    /// this class reconnects after 1 s, doubling up to 30 s. On reconnect
    /// every account moves to the new connection and registers again if it
    /// was registering. <see cref="Account.Register"/> while down is kept for
    /// then; a call placed meanwhile throws with
    /// <see cref="SipralStatus.TransportDown"/>.
    ///
    /// <paramref name="inviteLimit"/> is how fast one address may ring this
    /// stack: <see cref="SipralInviteLimit.Default"/> (ten at once, then one
    /// every 2 s, else 480) or <see cref="SipralInviteLimit.VoiceAgent"/> for
    /// a service taking a trunk's calls.
    ///
    /// <paramref name="streamFallback"/> covers a UDP request too large for a
    /// datagram, usually an authenticated INVITE offering two SRTP suites
    /// (RFC 3261 §18.1.1). On (the default), each
    /// <see cref="SipralEventKind.TransportWanted"/> opens a TCP connection to
    /// the named address and binds it; the held request and its call carry on
    /// over it. If that fails, or with <see langword="false"/>, the waiting
    /// call ends as unreachable with a SIP 513 cause naming size and limit,
    /// rather than hanging. <paramref name="streamServer"/> (<c>host:port</c>)
    /// redirects that connection, for a server whose TCP port differs from
    /// its UDP one.
    ///
    /// <paramref name="bindHost"/> is where the signalling socket binds and
    /// what it advertises. With <see langword="null"/> it listens on every
    /// interface and advertises the OS route toward each account's server,
    /// and media sockets without <c>mediaHost</c> the route toward the far
    /// end. A loopback address is never advertised to a remote peer
    /// (<see cref="SipralStatus.UnreachableAddress"/>).
    ///
    /// <paramref name="srtp"/> <see cref="SipralSrtp.BestEffort"/> offers SDES
    /// on plain <c>RTP/AVP</c>, for a PBX that answers <c>RTP/SAVP</c> with
    /// 488; the call is encrypted only if the answer takes a key.
    /// <paramref name="srtpSuites"/> are the default suites, most preferred
    /// first, by their RFC 4568 / RFC 7714 names.
    ///
    /// <paramref name="pathMtu"/> is the path MTU when known (<c>0</c>, or 576
    /// or more); RFC 3261 §18.1.1 moves a request to a stream within 200
    /// bytes of it. <paramref name="datagramWithoutStreamBytes"/> deviates
    /// from that section on purpose, for a UDP-only server: when no stream
    /// can be had, requests up to this size go over UDP anyway (<c>0</c> for
    /// never, at most 65 507), reported as <c>transport.kept.datagram</c>.
    ///
    /// <paramref name="pseudonymSalt"/> (16 bytes or more) keys the pseudonyms
    /// in the log and <see cref="State"/>, so traces of two runs compare. Keep
    /// it secret. <paramref name="diagnosticTrace"/> logs whole SIP messages
    /// at trace level, with credentials and keys removed.
    ///
    /// <paramref name="systemEchoCancellation"/> <see langword="false"/>
    /// opens devices without the platform's echo cancellation, gain control
    /// and noise suppression, e.g. for a headset;
    /// <see cref="SipralAudioSnapshot.SystemEchoCancellation"/> says what the
    /// platform did.
    ///
    /// <paramref name="heldAudio"/> is what a held party hears: silence for
    /// <see cref="SipralHeldAudio.Default"/> and
    /// <see cref="SipralHeldAudio.Silence"/> (even in application mode, where
    /// frames may be a microphone's), or the application's frames for
    /// <see cref="SipralHeldAudio.Application"/>.
    ///
    /// <paramref name="resolver"/> answers
    /// <see cref="SipralEventKind.LookupWanted"/> for accounts added with
    /// <c>serverUri</c>, one thread per lookup; defaults to
    /// <see cref="SipralDns.Platform"/>.</summary>
    public SipralStack(
        string? bindHost = null,
        int bindPort = 0,
        string? userAgent = null,
        string? codecs = null,
        uint frameMs = 0,
        bool? offerDtmf = null,
        SipralSrtp srtp = 0,
        SipralIce ice = 0,
        SipralNat nat = 0,
        string? stunServer = null,
        string? turnServer = null,
        string? turnUsername = null,
        string? turnPassword = null,
        bool? g729AnnexB = null,
        bool? referrals = null,
        bool? registrarKeepalive = null,
        ulong registrarKeepaliveMs = 0,
        SipralTransport turnTransport = 0,
        string? turnServerName = null,
        X509Certificate2Collection? turnTrustedCertificates = null,
        SipralAudio? audio = null,
        SipralAudioActivation audioActivation = SipralAudioActivation.Automatic,
        ulong audioProbeMs = 0,
        uint audioDeviceRateHz = 0,
        uint maxDialogs = 0,
        uint maxServerTransactions = 0,
        uint diagnosticDecisions = 0,
        uint diagnosticRecords = 0,
        IReadOnlyList<string>? stunFallbacks = null,
        ushort rtpPortMin = 0,
        ushort rtpPortMax = 0,
        SipralDtmfDetection dtmfDetection = SipralDtmfDetection.Auto,
        SipralTransport signalling = 0,
        string? signallingServer = null,
        string? tlsServerName = null,
        SipralTlsTrust? tlsTrust = null,
        SipralInviteLimit? inviteLimit = null,
        bool streamFallback = true,
        string? streamServer = null,
        IReadOnlyList<string>? srtpSuites = null,
        uint pathMtu = 0,
        uint datagramWithoutStreamBytes = 0,
        byte[]? pseudonymSalt = null,
        bool? diagnosticTrace = null,
        SipralResolver? resolver = null,
        bool? systemEchoCancellation = null,
        SipralHeldAudio heldAudio = SipralHeldAudio.Default)
    {
        RtpPorts = rtpPortMin == 0 && rtpPortMax == 0 ? null : (rtpPortMin, rtpPortMax);
        _chosenPort = bindPort;
        _streamFallback = streamFallback;
        _streamServer = streamServer;
        _nat = nat;
        _turn = turnServer is not null;
        _turnTransport = turnTransport;
        _turnServerName = turnServerName ?? (turnServer is null ? null : ParseAddress(turnServer).Host);
        _turnTrustedCertificates = turnTrustedCertificates;
        NativeLibraryLoader.EnsureRegistered();

        _resolver = resolver ?? SipralDns.Platform;
        var (firstLink, firstRefusal) = PrepareSignalling(signalling, bindHost, signallingServer, tlsServerName, tlsTrust);
        _routes = bindHost is null;
        _routeChosen = bindHost is not null || Streamed || streamServer is not null;
        if (Streamed)
        {
            BindAddress = firstLink?.Local ?? $"{bindHost ?? RouteHost(signallingServer)}:{bindPort}";
        }
        else
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _socket.Bind(new IPEndPoint(bindHost is null ? IPAddress.Any : IPAddress.Parse(bindHost), bindPort));
            _socket.Blocking = false;
            var bound = (IPEndPoint)_socket.LocalEndPoint!;
            BindAddress = bindHost is null ? $"{RouteHost(streamServer)}:{bound.Port}" : FormatAddress(bound);
        }

        // The native side calls through this delegate until
        // sipral_stack_destroy. The poll thread closes over `this`, so the
        // delegate stays rooted until Dispose joins that thread.
        _callback = OnEvent;
        _audioTransmit = OnAudioTransmit;
        AudioMode = audio ?? (HasFeature(global::Sipral.Sipral.FeatureAudioDevice) ? SipralAudio.Device : SipralAudio.Application);
        Audio = new SipralAudioEngine(this);

        var bindAddressBytes = Encoding.UTF8.GetBytes(BindAddress);
        var userAgentBytes = userAgent is null ? null : Encoding.UTF8.GetBytes(userAgent);
        var codecsBytes = codecs is null ? null : Encoding.UTF8.GetBytes(codecs);
        var entropy = RandomBytes(32);
        var mediaSeed = RandomBytes(32);
        var stunServerBytes = stunServer is null ? null : Encoding.UTF8.GetBytes(stunServer);
        var stunFallbacksBytes = stunFallbacks is null || stunFallbacks.Count == 0
            ? null
            : Encoding.UTF8.GetBytes(string.Join(",", stunFallbacks));
        var turnServerBytes = turnServer is null ? null : Encoding.UTF8.GetBytes(turnServer);
        var turnUsernameBytes = turnUsername is null ? null : Encoding.UTF8.GetBytes(turnUsername);
        var turnPasswordBytes = turnPassword is null ? null : Encoding.UTF8.GetBytes(turnPassword);
        var srtpSuitesBytes = srtpSuites is null || srtpSuites.Count == 0
            ? null
            : Encoding.UTF8.GetBytes(string.Join(",", srtpSuites));

        var stackHandle = 0ul;
        SipralStatus status;
        using (var bindPin = Pin(bindAddressBytes))
        using (var uaPin = Pin(userAgentBytes))
        using (var codecsPin = Pin(codecsBytes))
        using (var entropyPin = Pin(entropy))
        using (var seedPin = Pin(mediaSeed))
        using (var stunServerPin = Pin(stunServerBytes))
        using (var stunFallbacksPin = Pin(stunFallbacksBytes))
        using (var turnServerPin = Pin(turnServerBytes))
        using (var turnUsernamePin = Pin(turnUsernameBytes))
        using (var turnPasswordPin = Pin(turnPasswordBytes))
        using (var srtpSuitesPin = Pin(srtpSuitesBytes))
        using (var saltPin = Pin(pseudonymSalt))
        {
            var config = SipralStackConfig.Sized();
            config.EventCallback = Marshal.GetFunctionPointerForDelegate(_callback);
            config.EventUserData = IntPtr.Zero;
            config.Transport = (uint)_signalling;
            config.BindAddress = bindPin.Pointer;
            config.BindAddressLen = (nuint)bindAddressBytes.Length;
            config.UserAgent = uaPin.Pointer;
            config.UserAgentLen = (nuint)(userAgentBytes?.Length ?? 0);
            config.Entropy = entropyPin.Pointer;
            config.EntropyLen = 32;
            config.Codecs = codecsPin.Pointer;
            config.CodecsLen = (nuint)(codecsBytes?.Length ?? 0);
            config.FrameMs = frameMs;
            config.OfferDtmf = ToggleOf(offerDtmf);
            config.MediaClockUnixSeconds = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            config.MediaSeed = seedPin.Pointer;
            config.MediaSeedLen = 32;
            config.Srtp = (uint)srtp;
            config.Ice = (uint)ice;
            config.Nat = (uint)nat;
            config.StunServer = stunServerPin.Pointer;
            config.StunServerLen = (nuint)(stunServerBytes?.Length ?? 0);
            config.G729AnnexB = ToggleOf(g729AnnexB);
            config.TurnServer = turnServerPin.Pointer;
            config.TurnServerLen = (nuint)(turnServerBytes?.Length ?? 0);
            config.TurnUsername = turnUsernamePin.Pointer;
            config.TurnUsernameLen = (nuint)(turnUsernameBytes?.Length ?? 0);
            config.TurnPassword = turnPasswordPin.Pointer;
            config.TurnPasswordLen = (nuint)(turnPasswordBytes?.Length ?? 0);
            config.Referrals = ToggleOf(referrals);
            config.RegistrarKeepalive = ToggleOf(registrarKeepalive);
            config.RegistrarKeepaliveMs = registrarKeepaliveMs;
            config.TurnTransport = (uint)turnTransport;
            config.Audio = (uint)AudioMode;
            config.AudioActivation = (uint)audioActivation;
            if (AudioMode == SipralAudio.Device)
            {
                config.AudioTransmitCallback = Marshal.GetFunctionPointerForDelegate(_audioTransmit);
            }
            config.AudioProbeMs = audioProbeMs;
            config.AudioDeviceRateHz = audioDeviceRateHz;
            config.MaxDialogs = maxDialogs;
            config.MaxServerTransactions = maxServerTransactions;
            config.DiagnosticDecisions = diagnosticDecisions;
            config.DiagnosticRecords = diagnosticRecords;
            config.StunFallbacks = stunFallbacksPin.Pointer;
            config.StunFallbacksLen = (nuint)(stunFallbacksBytes?.Length ?? 0);
            config.RtpPortMin = rtpPortMin;
            config.RtpPortMax = rtpPortMax;
            config.DtmfDetection = (uint)dtmfDetection;
            config.SrtpSuites = srtpSuitesPin.Pointer;
            config.SrtpSuitesLen = (nuint)(srtpSuitesBytes?.Length ?? 0);
            config.PathMtu = pathMtu;
            config.DatagramWithoutStreamBytes = datagramWithoutStreamBytes;
            config.PseudonymSalt = saltPin.Pointer;
            config.PseudonymSaltLen = (nuint)(pseudonymSalt?.Length ?? 0);
            config.DiagnosticTrace = ToggleOf(diagnosticTrace);
            config.SystemEchoCancellation = ToggleOf(systemEchoCancellation);
            config.HeldAudio = (uint)heldAudio;

            status = NativeMethods.sipral_stack_create(config, out stackHandle);
        }
        if (status != SipralStatus.Ok)
        {
            // e.g. device mode with no backend here: free the socket
            _socket?.Dispose();
            firstLink?.Stream.Dispose();
            firstLink?.Client.Dispose();
        }
        SipralErrors.Check(status, "sipral_stack_create");

        _handle = new StackSafeHandle();
        _handle.SetValue(stackHandle);
        if (inviteLimit is { } limit)
        {
            SipralErrors.Check(NativeMethods.sipral_stack_invite_limit(stackHandle, limit.EveryMs, limit.Burst),
                "sipral_stack_invite_limit");
        }
        StartSignalling(firstLink, firstRefusal);

        _pollThread = new Thread(Run) { IsBackground = true, Name = "sipral-stack" };
        _pollThread.Start();
    }

    /// <summary>Milliseconds since this stack was created: the <c>now_ms</c>
    /// every entry point expects.</summary>
    public ulong NowMs => (ulong)_origin.ElapsedMilliseconds;

    /// <summary>The raw <c>sipral_handle_t</c>, for entry points this class
    /// does not wrap. Valid until the stack is disposed.</summary>
    public ulong Handle => _handle.Value;

    /// <summary><c>sipral_stack_suspending</c>: the operating system says
    /// this process stops shortly (an app moving to the background). Nothing
    /// is sent and nothing stays scheduled; calls are left as they are. The
    /// report counts what was standing (<c>docs/16-lifecycle.md</c>).</summary>
    public SipralSuspending Suspending() => global::Sipral.Sipral.StackSuspending(Handle, NowMs);

    /// <summary><c>sipral_stack_resumed</c>: the process is awake again, after
    /// an unknown time. Registrations and transports are proved again. Safe
    /// without a matching <see cref="Suspending"/>.</summary>
    public void Resumed() => global::Sipral.Sipral.StackResumed(Handle, NowMs);

    /// <summary>The RTP port range media sockets are bound in, or
    /// <see langword="null"/> when the operating system picks.</summary>
    public (ushort Min, ushort Max)? RtpPorts { get; }

    /// <summary>A non-blocking UDP socket for a call's media, bound at
    /// <paramref name="host"/>: at <paramref name="port"/> when named, else at
    /// an even port from the RTP range (one held by another process is given
    /// back and the next tried), else where the OS puts it. Throws with
    /// <see cref="SipralStatus.Exhausted"/> once every pair is taken.</summary>
    public Socket OpenMediaSocket(string host, int port = 0)
    {
        if (port != 0 || RtpPorts is not { } range)
        {
            var named = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            named.Bind(new IPEndPoint(IPAddress.Parse(host), port));
            named.Blocking = false;
            return named;
        }
        SocketException? failure = null;
        var attempts = Math.Max(1, (range.Max - range.Min + 1) / 2);
        for (var attempt = 0; attempt < attempts; attempt++)
        {
            var reserved = 0u;
            SipralErrors.Call(
                () => NativeMethods.sipral_stack_rtp_port_reserve(Handle, out reserved),
                "sipral_stack_rtp_port_reserve");
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.Bind(new IPEndPoint(IPAddress.Parse(host), (int)reserved));
            }
            catch (SocketException error)
            {
                socket.Dispose();
                GiveBackPort((int)reserved);
                failure = error;
                continue;
            }
            socket.Blocking = false;
            return socket;
        }
        throw failure!;
    }

    /// <summary><c>sipral_stack_rtp_port_release</c> for a port no call
    /// took, on a stack with a range. Best effort: a port a call did take
    /// comes back by itself when the call ends.</summary>
    internal void GiveBackPort(int port)
    {
        if (RtpPorts is null)
        {
            return;
        }
        try
        {
            SipralErrors.Call(
                () => NativeMethods.sipral_stack_rtp_port_release(Handle, (uint)port),
                "sipral_stack_rtp_port_release");
        }
        catch (SipralException)
        {
            // not reserved, so there is nothing to give back
        }
    }

    // Kept for the stack's life: a replaced callback may still be delivering
    // a batch after SetLog returned.
    private readonly List<SipralLogCallback> _logCallbacks = new();

    /// <summary>Send this stack's log to <paramref name="handler"/> at
    /// <paramref name="level"/> and louder, or turn it off with
    /// <see cref="SipralLogLevel.Off"/> or a <see langword="null"/> handler
    /// (<c>sipral_stack_log</c>). The handler runs on the thread that just
    /// called into the stack (usually the poll thread) and may call back into
    /// it. Lines are redacted: no user part, number, IP or credential. The
    /// last argument counts lines dropped by a flood before this one.</summary>
    public void SetLog(SipralLogLevel level, Action<SipralLogLevel, string, string, ulong>? handler)
    {
        if (handler is null || level == SipralLogLevel.Off)
        {
            SipralErrors.Call(
                () => NativeMethods.sipral_stack_log(Handle, (uint)SipralLogLevel.Off, IntPtr.Zero, IntPtr.Zero),
                "sipral_stack_log");
            return;
        }
        SipralLogCallback callback = (record, _) =>
        {
            var line = Marshal.PtrToStructure<SipralLogRecord>(record);
            handler(
                (SipralLogLevel)line.Level,
                Marshal.PtrToStringUTF8(line.Target, (int)line.TargetLen),
                Marshal.PtrToStringUTF8(line.Message, (int)line.MessageLen),
                line.Suppressed);
        };
        lock (_logCallbacks)
        {
            _logCallbacks.Add(callback);
        }
        SipralErrors.Call(
            () => NativeMethods.sipral_stack_log(Handle, (uint)level, Marshal.GetFunctionPointerForDelegate(callback), IntPtr.Zero),
            "sipral_stack_log");
    }

    /// <summary>The stack's state as redacted text for a crash report
    /// (<c>sipral_stack_state_text</c>). Safe from any thread; never
    /// waits.</summary>
    public string State()
    {
        var buffer = new sbyte[(int)global::Sipral.Sipral.StateTextMax];
        nuint length = 0;
        SipralErrors.Call(
            () => NativeMethods.sipral_stack_state_text(Handle, buffer, (nuint)buffer.Length, out length),
            "sipral_stack_state_text");
        var bytes = (byte[])(Array)buffer;
        return Encoding.UTF8.GetString(bytes, 0, (int)length - 1);
    }

    /// <summary>Send this stack's log to a <see cref="TraceSource"/>. Each
    /// line is prefixed with its target (<c>sip: …</c>), traced at the type
    /// <see cref="TraceEventTypeOf"/> gives, with the level's number as event
    /// id. Without <paramref name="level"/>, the source's current switch
    /// decides (<see cref="LogLevelFor"/>), so dropped lines are never
    /// formatted. For <c>ILogger</c>, use <see cref="SetLog"/>. Replaces
    /// whatever <see cref="SetLog"/> installed.</summary>
    public void LogTo(TraceSource source, SipralLogLevel? level = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        SetLog(level ?? LogLevelFor(source.Switch.Level), (line, target, message, suppressed) =>
        {
            var text = suppressed == 0
                ? $"{target}: {message}"
                : $"{target}: {message} ({suppressed} lines turned away before this one)";
            source.TraceEvent(TraceEventTypeOf(line), (int)line, text);
        });
    }

    /// <summary>The event type a line at <paramref name="level"/> is traced
    /// as by <see cref="LogTo"/>.</summary>
    public static TraceEventType TraceEventTypeOf(SipralLogLevel level) => level switch
    {
        SipralLogLevel.Error => TraceEventType.Error,
        SipralLogLevel.Warn => TraceEventType.Warning,
        SipralLogLevel.Info => TraceEventType.Information,
        _ => TraceEventType.Verbose,
    };

    /// <summary>The quietest stack level that still carries every line a
    /// switch at <paramref name="levels"/> lets through.</summary>
    public static SipralLogLevel LogLevelFor(SourceLevels levels) => levels switch
    {
        SourceLevels.All => SipralLogLevel.Trace,
        _ when levels.HasFlag(SourceLevels.Verbose) => SipralLogLevel.Debug,
        _ when levels.HasFlag(SourceLevels.Information) => SipralLogLevel.Info,
        _ when levels.HasFlag(SourceLevels.Warning) => SipralLogLevel.Warn,
        _ when levels.HasFlag(SourceLevels.Error) => SipralLogLevel.Error,
        _ => SipralLogLevel.Off,
    };

    /// <summary>This stack's health counters since it was created
    /// (<c>sipral_stack_counters</c>). Cheap enough to sample on a timer;
    /// every member only grows except
    /// <see cref="SipralCounters.ActiveCalls"/>.</summary>
    public SipralCounters Counters()
    {
        var counters = new SipralCounters { Size = (nuint)Marshal.SizeOf<SipralCounters>() };
        SipralErrors.Call(
            () => NativeMethods.sipral_stack_counters(Handle, ref counters),
            "sipral_stack_counters");
        return counters;
    }

    /// <summary>Ask these STUN servers from now on, in order of preference,
    /// each <c>host:port</c> (<c>sipral_stack_stun_servers</c>). Mapped
    /// sockets ask the new list at once (<see cref="SipralEventKind.StunServer"/>,
    /// <see cref="SipralEventKind.NatMapping"/>). On a stack created without
    /// STUN, this turns mapping on. An empty list turns it off: accounts
    /// register their own address again. With a TURN server an empty list
    /// throws with <see cref="SipralStatus.InvalidArgument"/>, as does an
    /// entry that is not <c>host:port</c>.</summary>
    public void SetStunServers(IReadOnlyList<string> servers)
    {
        ArgumentNullException.ThrowIfNull(servers);
        var listed = ToSBytes(string.Join(",", servers));
        SipralErrors.Call(
            () => NativeMethods.sipral_stack_stun_servers(Handle, listed, (nuint)listed.Length, NowMs),
            "sipral_stack_stun_servers");
        _nat = listed.Length == 0 ? SipralNat.Off : SipralNat.Stun;
    }

    /// <summary><c>sipral_stack_network_test</c>: test the network before a
    /// call and return the test's number; results arrive as
    /// <see cref="SipralEventKind.NetworkTest"/>. <paramref name="account"/>'s
    /// server is sent an <c>OPTIONS</c>. <paramref name="echoCall"/>, a call
    /// to an echo service, is measured for <paramref name="echoMs"/> (8000 by
    /// default) and then hung up by the test. A part silent past
    /// <paramref name="timeoutMs"/> (30000 by default) fails.</summary>
    public uint NetworkTest(Account? account = null, Call? echoCall = null, uint echoMs = 0, uint timeoutMs = 0)
    {
        var config = SipralNetworkTestConfig.Sized();
        config.Account = account?.Handle ?? 0;
        config.EchoCall = echoCall?.Handle ?? 0;
        config.EchoMs = echoMs;
        config.TimeoutMs = timeoutMs;
        uint test = 0;
        SipralErrors.Call(
            () => NativeMethods.sipral_stack_network_test(Handle, config, NowMs, out test),
            "sipral_stack_network_test");
        return test;
    }

    /// <summary><c>sipral_stack_stir</c>: verify incoming callers against
    /// <paramref name="anchors"/> (PEM or DER roots, RFC 8224), replacing any
    /// earlier setting. <paramref name="unixSeconds"/> is the wall clock
    /// PASSporTs are judged by (default: this machine's). A stack that only
    /// signs calls this too, without anchors, before adding accounts. A
    /// call's certificate is requested at
    /// <see cref="SipralVerificationStage.CertificateWanted"/> and supplied
    /// with <see cref="StirCertificate"/>.
    /// <paramref name="acceptServiceProviderCodes"/> lets a certificate naming
    /// a service provider code vouch for any caller, as in SHAKEN; otherwise
    /// it covers only the numbers it names.</summary>
    public void Stir(byte[]? anchors, ulong freshnessSeconds = 0, ulong certificateWaitMs = 0, ulong? unixSeconds = null, bool acceptServiceProviderCodes = false)
    {
        using var pin = new Interop.PinnedBytes(anchors is { Length: > 0 } ? anchors : null);
        var config = SipralStirConfig.Sized();
        if (anchors is { Length: > 0 })
        {
            config.Anchors = pin.Pointer;
            config.AnchorsLen = (nuint)anchors.Length;
        }
        config.FreshnessSeconds = freshnessSeconds;
        config.CertificateWaitMs = certificateWaitMs;
        config.UnixSeconds = unixSeconds ?? (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        config.AcceptServiceProviderCodes = acceptServiceProviderCodes ? (uint)SipralToggle.On : 0;
        SipralErrors.Call(() => NativeMethods.sipral_stack_stir(Handle, config, NowMs), "sipral_stack_stir");
    }

    /// <summary><c>sipral_call_stir_certificate</c>: the fetched chain (PEM or
    /// DER, signing certificate first), or <see langword="null"/> if it could
    /// not be had. <paramref name="call"/> is the handle the event named; the
    /// call is not announced yet. The verdict follows at
    /// <see cref="SipralVerificationStage.Verified"/>.</summary>
    public void StirCertificate(ulong call, byte[]? chain)
    {
        var bytes = chain is { Length: > 0 } ? chain : null;
        SipralErrors.Call(
            () => NativeMethods.sipral_call_stir_certificate(Handle, call, bytes!, (nuint)(bytes?.Length ?? 0), NowMs),
            "sipral_call_stir_certificate");
    }

    /// <summary><c>host:port</c>, as addresses cross the ABI.</summary>
    public static string FormatAddress(IPEndPoint endpoint) => $"{endpoint.Address}:{endpoint.Port}";

    /// <summary>The inverse of <see cref="FormatAddress"/>.</summary>
    public static (string Host, int Port) ParseAddress(string text)
    {
        var idx = text.LastIndexOf(':');
        return (text[..idx], int.Parse(text[(idx + 1)..]));
    }

    /// <summary><c>sipral_account_add</c>. Without <paramref name="registrar"/>
    /// the account never registers, and <paramref name="registrarAddress"/>
    /// is its outbound proxy.
    ///
    /// <paramref name="sessionTimer"/> (RFC 4028): the stack's default,
    /// <see cref="SipralSessionTimer.Off"/>, or
    /// <see cref="SipralSessionTimer.Interval"/> with
    /// <paramref name="sessionIntervalSeconds"/> of 90 or more.
    /// <paramref name="privacy"/> is the <c>Sipral.Privacy*</c> bits every
    /// placed call asks for (RFC 3323); <c>Sipral.PrivacyId</c> makes
    /// <c>From</c> anonymous. <paramref name="trustedPeers"/> (IP literals)
    /// are the only peers whose <c>P-Asserted-Identity</c> is believed and to
    /// whom this account asserts its own (RFC 3325);
    /// <see cref="SipralCallerIdentity.Trusted"/> says which applied.
    /// <paramref name="security"/>: SRTP and STIR/SHAKEN per account.
    ///
    /// <paramref name="serverUri"/> (e.g. <c>sips:example.com:5061</c>) is
    /// located by RFC 3263 instead of <paramref name="registrarAddress"/>;
    /// give exactly one. <see cref="SipralEventKind.Located"/> and
    /// <see cref="SipralEventKind.LocateFailed"/> report the lookup. REGISTER
    /// waits for it; a call placed before it without <c>destination</c>
    /// throws with <see cref="SipralStatus.WrongState"/>.
    /// <paramref name="serverNaptr"/> asks NAPTR before SRV (RFC 3263 §4.1).
    /// <paramref name="keepaliveMs"/> (1 000 to 120 000, <c>0</c> for never)
    /// keeps the flow open regardless of STUN. <paramref name="tlsPin"/> is
    /// the SHA-256 fingerprint of the one certificate trusted, for an
    /// application running its own TLS; see <see cref="Account.CheckCertificate"/>.
    ///
    /// <paramref name="streamProtocol"/> (TCP, TLS, WS or WSS) gives the account
    /// its own connection, beside UDP accounts in the same stack. This class
    /// opens it on <see cref="SipralEventKind.TransportWanted"/> regardless of
    /// <c>streamFallback</c>, and reopens it if it closes. TLS is checked
    /// against <paramref name="tlsPin"/> if set, else the stack's
    /// <c>tlsTrust</c>. Until open, placing a call throws with
    /// <see cref="SipralStatus.TransportDown"/>. UDP stacks only. WS/WSS run a
    /// WebSocket (RFC 7118) asking for <paramref name="websocketResource"/>
    /// (<c>/ws</c>) with <paramref name="websocketHost"/> as <c>Host</c> (the
    /// server's address).
    ///
    /// <paramref name="realms"/> are the realms the password answers (RFC
    /// 3261 §22.1). By default: the server's first challenge realm and every
    /// REGISTER challenge realm. An SBC challenging calls under its own realm
    /// needs both named. Other challenges go unanswered, reported as
    /// <see cref="SipralEventKind.ChallengeDeclined"/>.</summary>
    public Account AddAccount(
        string aor,
        string? registrarAddress = null,
        string? registrar = null,
        string? contact = null,
        string? displayName = null,
        string? authUser = null,
        string? authPassword = null,
        ulong expiresSeconds = 0,
        SipralSessionTimer sessionTimer = SipralSessionTimer.Default,
        ulong sessionIntervalSeconds = 0,
        uint privacy = 0,
        IEnumerable<string>? trustedPeers = null,
        AccountSecurity? security = null,
        string? serverUri = null,
        bool serverNaptr = false,
        ulong keepaliveMs = 0,
        string? tlsPin = null,
        SipralTransport streamProtocol = 0,
        IEnumerable<string>? realms = null,
        string? websocketHost = null,
        string? websocketResource = null)
    {
        if ((registrarAddress is null) == (serverUri is null))
        {
            throw new ArgumentException("an account names its server by registrarAddress or by serverUri, one of the two");
        }
        if (streamProtocol != 0
            && (streamProtocol is not (SipralTransport.Tcp or SipralTransport.Tls or SipralTransport.Ws
                    or SipralTransport.Wss) || Streamed))
        {
            throw new ArgumentException(
                "streamProtocol is Tcp, Tls, Ws or Wss, on a stack that signals over UDP", nameof(streamProtocol));
        }
        var advertised = contact is null && registrarAddress is not null && PicksAddress
            ? AdvertiseToward(registrarAddress)
            : null;
        var account = Account.Add(
            this, aor, registrarAddress, registrar, contact, displayName, authUser, authPassword, expiresSeconds,
            sessionTimer, sessionIntervalSeconds, privacy, trustedPeers, security,
            new AccountLocation(serverUri, serverNaptr, keepaliveMs, tlsPin, advertised, streamProtocol, realms,
                websocketHost, websocketResource));
        lock (_accounts)
        {
            _accounts.Add(account);
        }
        return account;
    }

    internal void ForgetAccount(Account account)
    {
        lock (_accounts)
        {
            _accounts.Remove(account);
        }
    }

    /// <summary>
    /// <c>sipral_call_place</c>. A media socket is opened first and offered
    /// as <c>media_address</c>. See <see cref="SipralCallOptions"/>.
    /// </summary>
    public Call PlaceCall(Account account, string target, string? mediaHost = null, int mediaPort = 0, string? destination = null, SipralSrtp srtp = 0, SipralIce ice = 0, SipralCallOptions? options = null)
    {
        mediaHost = MediaHostFor(mediaHost, account, destination);
        var mediaSocket = OpenMediaSocket(mediaHost, mediaPort);
        var mediaAddress = FormatAddress((IPEndPoint)mediaSocket.LocalEndPoint!);
        MapMediaSocket(mediaSocket, mediaAddress);
        var textSocket = options is { Text: true } ? OpenMediaSocket(mediaHost) : null;
        var textAddressBytes = textSocket is null ? null : Encoding.UTF8.GetBytes(FormatAddress((IPEndPoint)textSocket.LocalEndPoint!));

        var targetBytes = Encoding.UTF8.GetBytes(target);
        var mediaAddressBytes = Encoding.UTF8.GetBytes(mediaAddress);
        var destinationBytes = destination is null ? null : Encoding.UTF8.GetBytes(destination);
        var codecsBytes = options?.Codecs is { } codecs ? Encoding.UTF8.GetBytes(codecs) : null;

        ulong callHandle = 0;
        using (var targetPin = Pin(targetBytes))
        using (var mediaPin = Pin(mediaAddressBytes))
        using (var destPin = Pin(destinationBytes))
        using (var textPin = Pin(textAddressBytes))
        using (var codecsPin = Pin(codecsBytes))
        {
            var config = SipralCallConfig.Sized();
            config.Target = targetPin.Pointer;
            config.TargetLen = (nuint)targetBytes.Length;
            config.MediaAddress = mediaPin.Pointer;
            config.MediaAddressLen = (nuint)mediaAddressBytes.Length;
            config.Srtp = (uint)srtp;
            config.Ice = (uint)ice;
            if (destinationBytes is not null)
            {
                config.Destination = destPin.Pointer;
                config.DestinationLen = (nuint)destinationBytes.Length;
            }
            config.TextAddress = textPin.Pointer;
            config.TextAddressLen = (nuint)(textAddressBytes?.Length ?? 0);
            config.Feedback = (uint)(options is { Feedback: true } ? SipralToggle.On : SipralToggle.Default);
            config.Focus = options is { Focus: true } ? 1u : 0u;
            config.FollowRedirects = options is { FollowRedirects: true } ? 1u : 0u;
            config.Codecs = codecsPin.Pointer;
            config.CodecsLen = (nuint)(codecsBytes?.Length ?? 0);

            try
            {
                SipralErrors.Call(() => NativeMethods.sipral_call_place(Handle, account.Handle, config, out callHandle, NowMs), "sipral_call_place");
            }
            catch
            {
                ForgetMediaSocket(mediaAddress);
                mediaSocket.Dispose();
                if (textSocket is not null)
                {
                    CloseSocket(textSocket);
                }
                throw;
            }
        }

        var call = new Call(this, callHandle, mediaSocket, mediaAddress, textSocket);
        Track(call, mediaAddress);
        return call;
    }

    /// <summary>
    /// Answers an <see cref="SipralEventKind.IncomingCall"/> on a new media
    /// socket (<c>sipral_call_answer_media</c>, or
    /// <c>sipral_call_answer_with</c> when <paramref name="options"/> is
    /// given).
    /// </summary>
    public Call AnswerCall(SipralEventArgs args, string? mediaHost = null, int mediaPort = 0, SipralCallOptions? options = null)
    {
        mediaHost = MediaHostFor(mediaHost, AccountFor(args.Account), null);
        var mediaSocket = OpenMediaSocket(mediaHost, mediaPort);
        var mediaAddress = FormatAddress((IPEndPoint)mediaSocket.LocalEndPoint!);
        MapMediaSocket(mediaSocket, mediaAddress);
        var textSocket = options is { Text: true } ? OpenMediaSocket(mediaHost) : null;

        var call = new Call(this, args.Call, mediaSocket, mediaAddress, textSocket);
        Track(call, mediaAddress);
        try
        {
            if (options is null)
            {
                call.Answer();
            }
            else
            {
                call.AnswerWith(options);
            }
        }
        catch
        {
            ForgetCall(call.Handle);
            ForgetMediaSocket(mediaAddress);
            mediaSocket.Dispose();
            if (textSocket is not null)
            {
                CloseSocket(textSocket);
            }
            throw;
        }
        return call;
    }

    /// <summary>Closes an extra socket from <see cref="OpenMediaSocket"/>
    /// and returns its port to the RTP range.</summary>
    internal void CloseSocket(Socket socket)
    {
        int port;
        try
        {
            port = ((IPEndPoint)socket.LocalEndPoint!).Port;
        }
        catch (ObjectDisposedException)
        {
            return;
        }
        socket.Dispose();
        GiveBackPort(port);
    }

    /// <summary><c>sipral_call_reject</c> for an unanswered incoming
    /// call.</summary>
    public void RejectCall(SipralEventArgs args, uint code = 486)
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_reject(Handle, args.Call, code, NowMs), "sipral_call_reject");
    }

    /// <summary>Sends 180 Ringing for an unanswered incoming call
    /// (<c>sipral_call_ring</c>).</summary>
    public void RingCall(SipralEventArgs args)
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_ring(Handle, args.Call, null!, 0, NowMs), "sipral_call_ring");
    }

    /// <summary>
    /// Sends 183 Session Progress with early media on a new socket
    /// (<c>sipral_call_ring_media</c>). <see cref="SipralEventKind.MediaStarted"/>
    /// follows; what is sent on <see cref="Call.Media"/> is what the caller
    /// hears while waiting. Answer with the returned call's
    /// <see cref="Call.Answer"/>, not <see cref="AnswerCall"/>, which would
    /// open a second socket. An INVITE without an offer is
    /// <see cref="SipralStatus.WrongState"/>, with nothing sent.
    /// </summary>
    public Call RingCallWithMedia(SipralEventArgs args, string? mediaHost = null, int mediaPort = 0, SipralSrtp srtp = 0, string? codecs = null)
    {
        mediaHost = MediaHostFor(mediaHost, AccountFor(args.Account), null);
        var mediaSocket = OpenMediaSocket(mediaHost, mediaPort);
        var mediaAddress = FormatAddress((IPEndPoint)mediaSocket.LocalEndPoint!);
        MapMediaSocket(mediaSocket, mediaAddress);

        var mediaAddressBytes = Encoding.UTF8.GetBytes(mediaAddress);
        var codecsBytes = codecs is null ? null : Encoding.UTF8.GetBytes(codecs);
        var call = new Call(this, args.Call, mediaSocket, mediaAddress);
        Track(call, mediaAddress);
        using (var mediaPin = Pin(mediaAddressBytes))
        using (var codecsPin = Pin(codecsBytes))
        {
            var config = SipralCallConfig.Sized();
            config.MediaAddress = mediaPin.Pointer;
            config.MediaAddressLen = (nuint)mediaAddressBytes.Length;
            config.Srtp = (uint)srtp;
            config.Codecs = codecsPin.Pointer;
            config.CodecsLen = (nuint)(codecsBytes?.Length ?? 0);
            try
            {
                SipralErrors.Call(() => NativeMethods.sipral_call_ring_media(Handle, args.Call, config, NowMs), "sipral_call_ring_media");
            }
            catch
            {
                ForgetCall(call.Handle);
                ForgetMediaSocket(mediaAddress);
                mediaSocket.Dispose();
                throw;
            }
        }
        return call;
    }

    // Kept for the stack's life: a replaced callback may still be running.
    private readonly List<SipralScreenCallback> _screenCallbacks = new();

    /// <summary>
    /// Installs a screening policy (<c>sipral_stack_screen</c>), or removes
    /// it with <see langword="null"/>. Every INVITE reaches it before any
    /// effect, even before a call handle exists. Return
    /// <see cref="Sipral.ScreenAccept"/> (200) to accept, or a 400 to 699
    /// status to refuse; refused calls need no cleanup and are counted in
    /// <see cref="SipralCounters.ScreenedRefusedByPolicy"/>. It runs with the
    /// stack's lock held, so calling into the stack fails with
    /// <see cref="SipralStatus.Busy"/>. A policy that throws refuses the call.
    /// </summary>
    public void Screen(Func<SipralInvite, uint>? policy)
    {
        if (policy is null)
        {
            SipralErrors.Call(() => NativeMethods.sipral_stack_screen(Handle, IntPtr.Zero, IntPtr.Zero), "sipral_stack_screen");
            return;
        }
        SipralScreenCallback callback = (raw, _) =>
        {
            try
            {
                var request = Marshal.PtrToStructure<SipralScreenRequest>(raw);
                var source = request.Source == IntPtr.Zero
                    ? null
                    : Marshal.PtrToStringUTF8(request.Source, (int)request.SourceLen);
                var message = new byte[(int)request.MessageLen];
                Marshal.Copy(request.Message, message, 0, message.Length);
                return policy(new SipralInvite(source, message));
            }
            catch (Exception ex)
            {
                // an exception must not unwind into the native frame below
                Trace.TraceError($"Sipral: screening policy threw: {ex}");
                return 0;
            }
        };
        lock (_screenCallbacks)
        {
            _screenCallbacks.Add(callback);
        }
        SipralErrors.Call(
            () => NativeMethods.sipral_stack_screen(Handle, Marshal.GetFunctionPointerForDelegate(callback), IntPtr.Zero),
            "sipral_stack_screen");
    }

    /// <summary>
    /// Accepts a REFER and places the call it asks for
    /// (<c>sipral_call_accept_transfer</c>). <paramref name="args"/> is a
    /// <see cref="SipralEventKind.Referral"/> with a zero
    /// <see cref="SipralReferralEventInfo.StatusCode"/>, or a
    /// <see cref="SipralEventKind.TransferRequested"/>. The stack answers 202,
    /// reports progress to the sender, and returns the placed call. The
    /// sender can make this line dial anything, so this is always the
    /// application's decision.
    /// </summary>
    public Call AcceptReferral(SipralEventArgs args, string? mediaHost = null, int mediaPort = 0, SipralSrtp srtp = 0, SipralIce ice = 0)
    {
        mediaHost = MediaHostFor(mediaHost, AccountFor(args.Account), null);
        var mediaSocket = OpenMediaSocket(mediaHost, mediaPort);
        var mediaAddress = FormatAddress((IPEndPoint)mediaSocket.LocalEndPoint!);
        MapMediaSocket(mediaSocket, mediaAddress);

        var mediaAddressBytes = Encoding.UTF8.GetBytes(mediaAddress);
        ulong placed = 0;
        using (var mediaPin = Pin(mediaAddressBytes))
        {
            var config = SipralCallConfig.Sized();
            config.MediaAddress = mediaPin.Pointer;
            config.MediaAddressLen = (nuint)mediaAddressBytes.Length;
            config.Srtp = (uint)srtp;
            config.Ice = (uint)ice;
            try
            {
                SipralErrors.Call(() => NativeMethods.sipral_call_accept_transfer(Handle, args.Call, config, out placed, NowMs), "sipral_call_accept_transfer");
            }
            catch
            {
                ForgetMediaSocket(mediaAddress);
                mediaSocket.Dispose();
                throw;
            }
        }

        var call = new Call(this, placed, mediaSocket, mediaAddress);
        Track(call, mediaAddress);
        return call;
    }

    /// <summary>Accepts a <see cref="SipralEventKind.TransferRequested"/>
    /// with a call the application placed itself
    /// (<c>sipral_call_accept_transfer_placed</c>): 202, then NOTIFYs with
    /// <paramref name="placed"/>'s progress. The original call is
    /// untouched.</summary>
    public void AcceptTransferPlaced(SipralEventArgs args, Call placed)
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_accept_transfer_placed(Handle, args.Call, placed.Handle, NowMs), "sipral_call_accept_transfer_placed");
    }

    /// <summary>Refuses a REFER outside any dialog, or a
    /// <see cref="SipralEventKind.TransferRequested"/>, with
    /// <paramref name="code"/>, 300 to 699:
    /// <c>sipral_call_reject_transfer</c> on the referral's handle.</summary>
    public void RejectReferral(SipralEventArgs args, uint code = 603)
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_reject_transfer(Handle, args.Call, code, NowMs), "sipral_call_reject_transfer");
    }

    /// <summary>Redirects an unanswered incoming call
    /// (<c>sipral_call_redirect</c>) with a 3xx (302 by default) listing
    /// <paramref name="targets"/> in <c>Contact</c>. A
    /// <paramref name="reason"/> (RFC 5806, e.g. <c>user-busy</c>) adds a
    /// <c>Diversion</c> naming the called address.</summary>
    public void RedirectCall(SipralEventArgs args, IEnumerable<string> targets, uint statusCode = 302, string? reason = null)
    {
        var listed = ToSBytes(string.Join(", ", targets));
        var said = reason is null ? null : ToSBytes(reason);
        SipralErrors.Call(
            () => NativeMethods.sipral_call_redirect(
                Handle, args.Call, statusCode, listed, (nuint)listed.Length, said!, (nuint)(said?.Length ?? 0), NowMs),
            "sipral_call_redirect");
    }

    /// <summary>Every entry of one identity list from a call's INVITE
    /// (asserted parties, <c>Diversion</c>, <c>History-Info</c>,
    /// <c>Alert-Info</c>), by handle, for a call not yet answered.
    /// <see cref="Call.Identity"/> does the same for an answered one.</summary>
    public IReadOnlyList<string> CallIdentity(ulong call, SipralIdentityText which)
    {
        nuint count = 0;
        SipralErrors.Call(() => NativeMethods.sipral_call_identity_count(Handle, call, (uint)which, out count), "sipral_call_identity_count");
        var texts = new List<string>((int)count);
        for (nuint index = 0; index < count; index++)
        {
            var buffer = new sbyte[256];
            var status = NativeMethods.sipral_call_identity_text(Handle, call, index, (uint)which, buffer, (nuint)buffer.Length, out var needed);
            if (status == SipralStatus.BufferTooSmall)
            {
                buffer = new sbyte[(int)needed];
                status = NativeMethods.sipral_call_identity_text(Handle, call, index, (uint)which, buffer, (nuint)buffer.Length, out needed);
            }
            SipralErrors.Check(status, "sipral_call_identity_text");
            // `needed` counts the NUL the text is copied out with
            var bytes = new byte[Math.Max((int)needed - 1, 0)];
            Buffer.BlockCopy(buffer, 0, bytes, 0, bytes.Length);
            texts.Add(Encoding.UTF8.GetString(bytes));
        }
        return texts;
    }

    /// <summary>The network changed; <paramref name="host"/> is this
    /// machine's new address.
    ///
    /// The signalling socket is rebound at <paramref name="host"/> (UDP keeps
    /// its port if free, see <see cref="KeptSignallingPort"/>), the change is
    /// reported (<c>sipral_stack_network_changed</c>), and accounts without
    /// their own <c>contact</c> are rebound. On
    /// <see cref="SipralRecovery.Rebuild"/>, calls described at the old
    /// address get <see cref="SipralEventKind.CallAddressWanted"/>, answered
    /// with <see cref="Call.Readdress"/>. Accounts with an explicit
    /// <c>contact</c> are the application's to <see cref="Account.Rebind"/>.
    ///
    /// A stack without <c>bindHost</c> keeps its socket and port, and again
    /// advertises the route toward each account's server
    /// (<paramref name="host"/> only when no account names a server by
    /// address).</summary>
    public SipralRecovery MoveTo(string host, SipralLink link = SipralLink.Wired)
    {
        var previous = ParseAddress(BindAddress).Host;
        var picks = PicksAddress;
        if (Streamed)
        {
            MoveLink(host);
        }
        else if (picks)
        {
            AdvertiseAgain(host);
        }
        else
        {
            MoveSocket(host);
        }

        var before = ToSBytes(previous);
        var after = ToSBytes(host);
        uint recovery = 0;
        SipralErrors.Call(
            () => NativeMethods.sipral_stack_network_changed(
                Handle, (uint)link, before, (nuint)before.Length, null!, 0, 1,
                (uint)link, after, (nuint)after.Length, null!, 0, 1, NowMs, out recovery),
            "sipral_stack_network_changed");
        List<Account> accounts;
        lock (_accounts)
        {
            accounts = _accounts.ToList();
        }
        foreach (var account in accounts.Where(a => !a.ContactGiven))
        {
            if (picks && IsAddress(account.RegistrarAddress))
            {
                account.Readvertise(AdvertiseToward(account.RegistrarAddress));
            }
            else
            {
                account.Rebind();
            }
        }
        return (SipralRecovery)recovery;
    }

    private void MoveSocket(string host)
    {
        var socket = SignallingSocket(IPAddress.Parse(host));
        socket.Blocking = false;
        var bound = FormatAddress((IPEndPoint)socket.LocalEndPoint!);
        var local = ToSBytes(bound);
        try
        {
            SipralErrors.Call(
                () => NativeMethods.sipral_stack_transport_bind(
                    Handle, global::Sipral.Sipral.TransportMain, (uint)SipralTransport.Udp, local, (nuint)local.Length,
                    null!, 0, NowMs, out _),
                "sipral_stack_transport_bind");
        }
        catch
        {
            socket.Dispose();
            throw;
        }
        var old = _socket;
        _socket = socket;
        BindAddress = bound;
        old?.Dispose();
    }

    // Rebinds on the chosen port (or the current one), falling back to a
    // system port only if another socket holds it. The old socket may hold
    // the port itself, so it is closed before the second attempt.
    private Socket SignallingSocket(IPAddress host)
    {
        var inUse = (_socket?.LocalEndPoint as IPEndPoint)?.Port ?? 0;
        var wanted = _chosenPort != 0 ? _chosenPort : inUse;
        Socket? On(int port)
        {
            var made = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                made.Bind(new IPEndPoint(host, port));
                return made;
            }
            catch (SocketException)
            {
                made.Dispose();
                return null;
            }
        }
        var made = wanted == 0 ? null : On(wanted);
        // Close the old socket only if the new address exists here; a move to
        // one this machine lacks throws below with the old socket still open.
        if (made is null && wanted != 0 && inUse == wanted && On(0) is { } usable)
        {
            usable.Dispose();
            _socket?.Dispose();
            made = On(wanted);
        }
        KeptSignallingPort = made is not null || wanted == 0;
        if (made is null)
        {
            made = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            made.Bind(new IPEndPoint(host, 0));
        }
        return made;
    }

    /// <summary>Whether the last <see cref="MoveTo"/> kept the UDP signalling
    /// port. <c>false</c> when it was taken at the new address and
    /// <see cref="BindAddress"/> now names another; peers or firewall rules
    /// that know the old port must be told. <c>true</c> before any
    /// move.</summary>
    public bool KeptSignallingPort { get; private set; } = true;

    // 0 when the system chose.
    private readonly int _chosenPort;

    internal Call? CallFor(ulong handle) => _calls.TryGetValue(handle, out var call) ? call : null;

    internal void RegisterCall(Call call) => _calls[call.Handle] = call;

    // With TURN over a stream, the socket is remembered past the call: its
    // last farewell goes on that connection.
    private void Track(Call call, string mediaAddress)
    {
        RegisterCall(call);
        if (OverStream((uint)_turnTransport))
        {
            _turnSockets[call.Handle] = mediaAddress;
        }
    }

    internal void ForgetCall(ulong handle) => _calls.TryRemove(handle, out _);

    // The C callback, on the poll thread. ResolveNeeded is delivered but not
    // answered: the dialog keeps the flow its INVITE used, the only path
    // through a NAT. Answering with the far end's Contact would move the BYE
    // to an address nothing answers on. An application with a real lookup
    // answers through sipral_stack_resolved.
    private void OnEvent(IntPtr rawEvent, IntPtr _)
    {
        Deliver(SipralEventArgs.Decode(rawEvent));
    }

    private void Deliver(SipralEventArgs args)
    {
        // Call side effects (Call.Media, ended state) happen before any
        // reader sees the event, so a reader that looks up the call finds
        // it current.
        if (args.TurnStream is { } asked)
        {
            _turnAsked.Enqueue(asked);
        }
        NoteStreamWanted(args);
        NoteLocate(args);
        if (args.Kind is SipralEventKind.NatMapping or SipralEventKind.NatRelay)
        {
            var local = args.Nat?.Local ?? args.Relay?.Local;
            if (local is not null)
            {
                lock (_natLock)
                {
                    if (_natWaiters.TryGetValue(local, out var waiters))
                    {
                        (args.Kind == SipralEventKind.NatMapping ? waiters.Mapping : waiters.Relay).Set();
                    }
                }
            }
        }

        var call = args.Call != 0 ? CallFor(args.Call) : null;
        call?.Deliver(args);

        // We are inside sipral_stack_poll: an exception unwinding into the
        // native frame would take the whole process down. Log and go on.
        try
        {
            EventReceived?.Invoke(this, args);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.TraceError($"Sipral: SipralStack.EventReceived handler threw: {ex}");
        }
        _events.Writer.TryWrite(args);
    }

    // Device mode: one encoded packet, sent from the call's media socket or
    // its TURN connection. Runs on the engine's thread and must not call the
    // library (the engine is waiting on us) or throw into the native frame.
    internal void OnAudioTransmit(IntPtr raw, IntPtr userData)
    {
        try
        {
            var transmit = Marshal.PtrToStructure<SipralAudioTransmit>(raw);
            var call = CallFor(transmit.Call);
            if (call is null)
            {
                return;
            }
            var payload = new byte[(int)transmit.PayloadLen];
            Marshal.Copy(transmit.Payload, payload, 0, payload.Length);
            if (OverStream(transmit.Protocol))
            {
                WriteTurn(call.MediaAddress, payload, fromEngine: true);
                return;
            }
            var destination = Marshal.PtrToStringUTF8(transmit.Destination, (int)transmit.DestinationLen) ?? string.Empty;
            var (host, port) = ParseAddress(destination);
            call.MediaSocket.SendTo(payload, new IPEndPoint(IPAddress.Parse(host), port));
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or FormatException
                                       or ArgumentException)
        {
            // socket closed by a racing hangup or readdress: one lost packet
        }
    }

    private void DrainTransmit()
    {
        while (true)
        {
            var transmit = SipralTransmit.Sized();
            transmit.Data = _transmitData;
            transmit.Capacity = TransmitBytes;
            transmit.Destination = _transmitDestination;
            transmit.DestinationCapacity = AddressBytes;
            transmit.Source = IntPtr.Zero;
            transmit.SourceCapacity = 0;
            var status = NativeMethods.sipral_stack_poll_transmit(Handle, ref transmit);
            if (status != SipralStatus.Ok || transmit.Len == 0)
            {
                return;
            }
            var payload = new byte[(int)transmit.Len];
            Marshal.Copy(_transmitData, payload, 0, payload.Length);
            if (transmit.Transport >= FirstStream)
            {
                WriteSipStream(transmit.Transport, payload);
                continue;
            }
            var socket = _socket;
            if (socket is null)
            {
                // stream signalling: the one connection is the outbound proxy
                WriteLink(payload);
                continue;
            }
            var destination = Marshal.PtrToStringUTF8(_transmitDestination, (int)transmit.DestinationLen) ?? string.Empty;
            var (host, port) = ParseAddress(destination);
            try
            {
                socket.SendTo(payload, new IPEndPoint(IPAddress.Parse(host), port));
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                // Best effort: a throw here would stop polling for good
                // (e.g. a socket MoveTo just replaced).
            }
        }
    }

    // An ended call's RTCP BYE and TURN Refresh, sent from its media socket
    // to the address the stack names (under ICE, the chosen path); the last
    // media source is only the fallback.
    private void DrainFarewells()
    {
        while (true)
        {
            var packet = SipralMediaPacket.Sized();
            packet.Data = _farewellData;
            packet.Capacity = TransmitBytes;
            packet.Destination = _farewellDestination;
            packet.DestinationCapacity = AddressBytes;
            var status = NativeMethods.sipral_stack_poll_farewell(Handle, out var endedCall, ref packet);
            if (status != SipralStatus.Ok || packet.Len == 0)
            {
                return;
            }
            if (OverStream(packet.Protocol))
            {
                // the relay's connection outlives the call
                if (_turnSockets.TryGetValue(endedCall, out var local))
                {
                    var bytes = new byte[(int)packet.Len];
                    Marshal.Copy(_farewellData, bytes, 0, bytes.Length);
                    WriteTurn(local, bytes);
                }
                continue;
            }
            var media = CallFor(endedCall)?.Media;
            if (media is null)
            {
                continue;
            }
            var address = packet.DestinationLen > 0
                ? Marshal.PtrToStringUTF8(_farewellDestination, (int)packet.DestinationLen)
                : media.RemoteAddress;
            if (address is null)
            {
                continue;
            }
            var payload = new byte[(int)packet.Len];
            Marshal.Copy(_farewellData, payload, 0, payload.Length);
            media.SendTo(payload, address);
        }
    }

    // sipral_stack_nat_map, then the wait required before a call may be
    // described on the socket. No-op without STUN. Blocks the calling thread
    // (never the poll thread) until NatMapping, and NatRelay with TURN. The
    // stack answers within 5.5 s whatever the server does, so the 7 s
    // timeout only fires if the poll thread has stopped.
    internal void MapMediaSocket(Socket sock, string address, TimeSpan? timeout = null)
    {
        if (_nat != SipralNat.Stun)
        {
            return;
        }
        var wait = timeout ?? TimeSpan.FromSeconds(7);
        var waiters = (Mapping: new ManualResetEventSlim(false), Relay: new ManualResetEventSlim(false));
        lock (_natLock)
        {
            _stunSockets[address] = sock;
            _natWaiters[address] = waiters;
        }
        var localBytes = ToSBytes(address);
        try
        {
            SipralErrors.Call(
                () => NativeMethods.sipral_stack_nat_map(Handle, localBytes, (nuint)localBytes.Length, NowMs),
                "sipral_stack_nat_map");
        }
        catch
        {
            ReleaseStunSocket(address);
            throw;
        }
        if (!waiters.Mapping.Wait(wait))
        {
            ReleaseStunSocket(address);
            throw new TimeoutException($"no NAT mapping answer for {address} within {wait}");
        }
        // place/answer refuse the socket until its NAT_RELAY arrives,
        // allocated or not
        if (_turn && !waiters.Relay.Wait(wait))
        {
            ReleaseStunSocket(address);
            throw new TimeoutException($"no TURN allocation answer for {address} within {wait}");
        }
    }

    // Once MediaStarted hands the socket to CallMedia, or the call gives up.
    internal void ReleaseStunSocket(string address)
    {
        lock (_natLock)
        {
            _stunSockets.Remove(address);
            _natWaiters.Remove(address);
        }
    }

    // sipral_stack_nat_unmap for a mapped socket that will carry no call
    // (place/answer refused it, or Dispose). No-op for unmapped sockets.
    internal void ForgetMediaSocket(string address)
    {
        GiveBackPort(ParseAddress(address).Port);
        bool mapped;
        lock (_natLock)
        {
            mapped = _stunSockets.ContainsKey(address);
        }
        if (!mapped)
        {
            return;
        }
        var localBytes = ToSBytes(address);
        try
        {
            SipralErrors.Call(
                () => NativeMethods.sipral_stack_nat_unmap(Handle, localBytes, (nuint)localBytes.Length, NowMs),
                "sipral_stack_nat_unmap");
            // send the zero-lifetime Refresh while the socket is still open
            DrainStun();
        }
        catch (SipralException)
        {
            // best effort on the way out
        }
        ReleaseStunSocket(address);
    }

    // Each packet must leave from the socket transmit.Source names: sent from
    // another, it would silently learn the wrong socket's mapping.
    private void DrainStun()
    {
        while (true)
        {
            var transmit = SipralTransmit.Sized();
            transmit.Data = _stunData;
            transmit.Capacity = TransmitBytes;
            transmit.Destination = _stunDestination;
            transmit.DestinationCapacity = AddressBytes;
            transmit.Source = _stunSource;
            transmit.SourceCapacity = AddressBytes;
            var status = NativeMethods.sipral_stack_poll_stun(Handle, ref transmit);
            if (status != SipralStatus.Ok || transmit.Len == 0)
            {
                return;
            }
            var payload = new byte[(int)transmit.Len];
            Marshal.Copy(_stunData, payload, 0, payload.Length);
            var destination = Marshal.PtrToStringUTF8(_stunDestination, (int)transmit.DestinationLen) ?? string.Empty;
            var sourceText = Marshal.PtrToStringUTF8(_stunSource, (int)transmit.SourceLen) ?? string.Empty;
            if (OverStream(transmit.Protocol))
            {
                // on the TURN connection, never as a datagram
                WriteTurn(sourceText, payload);
                continue;
            }
            Socket? sock;
            lock (_natLock)
            {
                _stunSockets.TryGetValue(sourceText, out sock);
            }
            if (sock is null)
            {
                continue;
            }
            var (host, port) = ParseAddress(destination);
            try
            {
                sock.SendTo(payload, new IPEndPoint(IPAddress.Parse(host), port));
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
                // disposed by Call.Close on another thread after the lock
            }
        }
    }

    private void Run()
    {
        while (!_closed.IsSet)
        {
            List<Socket> stunSnapshot;
            lock (_natLock)
            {
                stunSnapshot = _stunSockets.Values.ToList();
            }
            // MoveTo may replace it; null over TCP/TLS, read elsewhere
            var signalling = _socket;
            var checkRead = new List<Socket>(stunSnapshot.Count + 1);
            if (signalling is not null)
            {
                checkRead.Add(signalling);
            }
            checkRead.AddRange(stunSnapshot);
            try
            {
                if (checkRead.Count == 0)
                {
                    _closed.Wait(50);
                }
                else
                {
                    Socket.Select(checkRead, null, null, 50_000);
                }
            }
            catch (SocketException)
            {
                checkRead.Clear();
            }
            catch (ObjectDisposedException)
            {
                // a media socket closed by another thread; the next pass
                // takes a fresh snapshot
                checkRead.Clear();
            }

            foreach (var sock in checkRead)
            {
                if (signalling is not null && ReferenceEquals(sock, signalling))
                {
                    try
                    {
                        EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                        var count = signalling.ReceiveFrom(_receiveBuffer, ref from);
                        var fromText = ToSBytes(Encoding.UTF8.GetBytes(FormatAddress((IPEndPoint)from)));
                        // a transport id, not a SipralTransport kind: the UDP
                        // socket is always the main transport
                        NativeMethods.sipral_stack_receive_datagram(
                            Handle, global::Sipral.Sipral.TransportMain, _receiveBuffer, (nuint)count,
                            fromText, (nuint)fromText.Length, null!, 0, NowMs);
                    }
                    catch (SocketException)
                    {
                    }
                    catch (ObjectDisposedException)
                    {
                        // MoveTo closed it after the select
                    }
                }
                else
                {
                    // Until the call's media handle exists, everything on a
                    // mapped socket goes to sipral_stack_receive_stun.
                    string? address;
                    lock (_natLock)
                    {
                        address = _stunSockets.FirstOrDefault(kv => ReferenceEquals(kv.Value, sock)).Key;
                    }
                    if (address is null)
                    {
                        continue;
                    }
                    try
                    {
                        EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                        var count = sock.ReceiveFrom(_stunReceiveBuffer, ref from);
                        var fromText = ToSBytes(Encoding.UTF8.GetBytes(FormatAddress((IPEndPoint)from)));
                        var toText = ToSBytes(address);
                        NativeMethods.sipral_stack_receive_stun(
                            Handle, _stunReceiveBuffer, (nuint)count,
                            fromText, (nuint)fromText.Length, toText, (nuint)toText.Length, NowMs);
                    }
                    catch (SocketException)
                    {
                    }
                    catch (ObjectDisposedException)
                    {
                        // closed by another thread after the select; its
                        // entries were released first, nothing to clean
                    }
                }
            }

            var result = SipralPollResult.Sized();
            var status = NativeMethods.sipral_stack_poll(Handle, NowMs, ref result);
            if (status != SipralStatus.Ok)
            {
                continue;
            }
            DrainTransmit();
            DrainStun();
            DrainFarewells();
            ActOnTurnStreams();
            ActOnStreamsWanted();
            ActOnMainLetGo();
            ActOnLookups();
            while (_turnLost.TryDequeue(out var lost))
            {
                LoseTurnStream(lost, tell: true);
            }
        }
    }

    internal static bool OverStream(uint protocol) =>
        protocol == (uint)SipralTransport.Tcp || protocol == (uint)SipralTransport.Tls;

    // Thread-safe. A failed connection is closed and the stack told (from
    // the poll thread when the write came from the audio engine).
    internal void WriteTurn(string local, byte[] payload, bool fromEngine = false)
    {
        if (!_turnStreams.TryGetValue(local, out var stream))
        {
            return;
        }
        try
        {
            lock (stream.WriteLock)
            {
                stream.Stream.Write(payload, 0, payload.Length);
                stream.Stream.Flush();
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or SocketException)
        {
            if (fromEngine)
            {
                _turnLost.Enqueue(local);
                return;
            }
            LoseTurnStream(local, tell: true);
        }
    }

    private void ActOnTurnStreams()
    {
        while (_turnAsked.TryDequeue(out var asked))
        {
            if (asked.Local is not { } local)
            {
                continue;
            }
            if (asked.State == SipralTurnStream.Open && asked.Server is { } server)
            {
                var thread = new Thread(() => OpenTurnStream(local, server, asked.Protocol))
                {
                    IsBackground = true,
                    Name = "sipral-turn",
                };
                thread.Start();
            }
            else if (asked.State == SipralTurnStream.Close)
            {
                foreach (var entry in _turnSockets)
                {
                    if (entry.Value == local)
                    {
                        _turnSockets.TryRemove(entry.Key, out _);
                    }
                }
                LoseTurnStream(local, tell: false);
            }
        }
    }

    private void OpenTurnStream(string local, string server, SipralTransport protocol)
    {
        TurnStream stream;
        try
        {
            var (host, port) = ParseAddress(server);
            var client = new TcpClient(AddressFamily.InterNetwork) { NoDelay = true };
            if (!client.ConnectAsync(IPAddress.Parse(host), port).Wait(TimeSpan.FromSeconds(5)))
            {
                client.Dispose();
                throw new IOException($"no connection to {server} in five seconds");
            }
            Stream carried = client.GetStream();
            if (protocol == SipralTransport.Tls)
            {
                var tls = new SslStream(carried, leaveInnerStreamOpen: false);
                var options = new SslClientAuthenticationOptions { TargetHost = _turnServerName };
                if (_turnTrustedCertificates is { Count: > 0 } roots)
                {
                    // SslStream's default; a custom policy would start from
                    // Online, and a private CA publishes no revocation list
                    var policy = new X509ChainPolicy
                    {
                        TrustMode = X509ChainTrustMode.CustomRootTrust,
                        RevocationMode = X509RevocationMode.NoCheck,
                    };
                    policy.CustomTrustStore.AddRange(roots);
                    options.CertificateChainPolicy = policy;
                }
                tls.AuthenticateAsClient(options);
                carried = tls;
            }
            stream = new TurnStream { Client = client, Stream = carried };
        }
        catch (Exception ex) when (ex is IOException or SocketException or AggregateException
                                       or System.Security.Authentication.AuthenticationException
                                       or FormatException)
        {
            SayTurn(local, closed: true);
            return;
        }
        if (_closed.IsSet)
        {
            stream.Stream.Dispose();
            stream.Client.Dispose();
            return;
        }
        _turnStreams[local] = stream;
        SayTurn(local, closed: false);
        var buffer = new byte[TransmitBytes];
        while (true)
        {
            int read;
            try
            {
                read = stream.Stream.Read(buffer, 0, buffer.Length);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or SocketException)
            {
                read = 0;
            }
            if (read == 0)
            {
                LoseTurnStream(local, tell: true);
                return;
            }
            if (!TurnReceived(local, buffer, read))
            {
                LoseTurnStream(local, tell: false);
                return;
            }
        }
    }

    private void SayTurn(string local, bool closed)
    {
        var localBytes = ToSBytes(local);
        try
        {
            SipralErrors.Call(
                () => closed
                    ? NativeMethods.sipral_stack_turn_closed(Handle, localBytes, (nuint)localBytes.Length, NowMs)
                    : NativeMethods.sipral_stack_turn_connected(Handle, localBytes, (nuint)localBytes.Length, NowMs),
                closed ? "sipral_stack_turn_closed" : "sipral_stack_turn_connected");
        }
        catch (Exception ex) when (ex is SipralException or ObjectDisposedException)
        {
            // the stack is going away
        }
    }

    // A stream that loses a byte never resyncs, so a busy stack is waited
    // for, not skipped. False when the stack found the stream broken.
    private bool TurnReceived(string local, byte[] buffer, int count)
    {
        var localBytes = ToSBytes(local);
        var bytes = buffer.AsSpan(0, count).ToArray();
        while (!_closed.IsSet)
        {
            var status = NativeMethods.sipral_stack_turn_receive(
                Handle, localBytes, (nuint)localBytes.Length, bytes, (nuint)bytes.Length, NowMs);
            if (status == SipralStatus.Busy)
            {
                Thread.Sleep(1);
                continue;
            }
            return status != SipralStatus.StreamBroken;
        }
        return true;
    }

    // tell: false when the stack itself closed it or found it broken.
    private void LoseTurnStream(string local, bool tell)
    {
        if (!_turnStreams.TryRemove(local, out var stream))
        {
            return;
        }
        lock (stream.WriteLock)
        {
            stream.Stream.Dispose();
            stream.Client.Dispose();
        }
        if (tell)
        {
            SayTurn(local, closed: true);
        }
    }

    /// <summary>
    /// Hangs up open calls, lets the poll thread send the BYEs and RTCP
    /// goodbyes, then destroys the stack. Closing media first would leave
    /// the farewells nowhere to go.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (var call in _calls.Values)
        {
            if (!call.Ended)
            {
                try
                {
                    call.Hangup();
                }
                catch (SipralException)
                {
                }
            }
        }
        if (!_calls.IsEmpty)
        {
            Thread.Sleep(200);
        }
        foreach (var call in _calls.Values)
        {
            call.Close();
        }

        // Sockets mapped but never used by a call: destroy sends nothing,
        // and a relay left allocated stays on the server until it expires.
        List<string> leftover;
        lock (_natLock)
        {
            leftover = _stunSockets.Keys.ToList();
        }
        foreach (var address in leftover)
        {
            ForgetMediaSocket(address);
        }

        _closed.Set();
        if (Thread.CurrentThread != _pollThread)
        {
            _pollThread.Join(TimeSpan.FromSeconds(5));
        }
        foreach (var local in _turnStreams.Keys.ToList())
        {
            LoseTurnStream(local, tell: false);
        }
        CloseSipStreams();
        _events.Writer.TryComplete();

        CloseLink();
        _handle.Dispose();
        _socket?.Dispose();
        Marshal.FreeHGlobal(_transmitData);
        Marshal.FreeHGlobal(_transmitDestination);
        Marshal.FreeHGlobal(_transmitSource);
        Marshal.FreeHGlobal(_farewellData);
        Marshal.FreeHGlobal(_farewellDestination);
        Marshal.FreeHGlobal(_stunData);
        Marshal.FreeHGlobal(_stunDestination);
        Marshal.FreeHGlobal(_stunSource);
    }

    private static uint ToggleOf(bool? value) => value switch
    {
        null => (uint)SipralToggle.Default,
        true => (uint)SipralToggle.On,
        false => (uint)SipralToggle.Off,
    };

    private static byte[] RandomBytes(int count)
    {
        var buffer = new byte[count];
        System.Security.Cryptography.RandomNumberGenerator.Fill(buffer);
        return buffer;
    }

    private static PinnedBytes Pin(byte[]? bytes) => new(bytes);
}
