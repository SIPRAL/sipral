// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Sipral.Interop;
using static Sipral.Interop.NativeText;

namespace Sipral;

/// <summary>
/// One <c>sipral_stack_create</c> handle, its UDP socket and the thread
/// that drains <c>sipral_stack_poll</c> and the transport queues around
/// it — the .NET counterpart of <c>bindings/python/sipral/stack.py</c>'s
/// <c>Stack</c>, written by hand against <see cref="NativeMethods"/> the
/// same way that file is written by hand against <c>_sipral_cffi.py</c>
/// (<c>docs/08-ffi.md</c>, "The shape").
///
/// Built and torn down like the handle it wraps: <see cref="Dispose"/>
/// calls <c>sipral_stack_destroy</c> exactly once, through
/// <see cref="StackSafeHandle"/>, which also gives a stack an application
/// never disposes a finalizer-backed release — a stack still bound to a
/// socket is a port nothing else can use until the collector gets around
/// to it, so <see cref="Dispose"/> is still the path to prefer.
/// </summary>
public sealed class SipralStack : IDisposable
{
    private const int TransmitBytes = 1 << 16;
    private const int AddressBytes = 128;

    private readonly StackSafeHandle _handle;
    private readonly Socket _socket;
    private readonly Stopwatch _origin = Stopwatch.StartNew();
    private readonly SipralEventCallback _callback;
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

    private readonly SipralNat _nat;
    private readonly bool _turn;
    private readonly object _natLock = new();

    /// <summary>Media sockets currently named with <c>sipral_stack_nat_map</c>,
    /// keyed by their own <c>host:port</c> text — from
    /// <see cref="MapMediaSocket"/> until either
    /// <see cref="SipralEventKind.MediaStarted"/> hands the socket to
    /// <see cref="CallMedia"/> (<see cref="ReleaseStunSocket"/>) or the
    /// call gives up on it (<see cref="ForgetMediaSocket"/>). Read and
    /// written from both the calling thread and the poll thread; <see
    /// cref="_natLock"/> covers this and <see cref="_natWaiters"/>.</summary>
    private readonly Dictionary<string, Socket> _stunSockets = new();

    /// <summary>Per socket, one wait handle for
    /// <see cref="SipralEventKind.NatMapping"/> and one for
    /// <see cref="SipralEventKind.NatRelay"/> — a stack built with
    /// <c>turnServer</c> waits out both before a call may be placed or
    /// answered on the socket, a stack without it only the first.</summary>
    private readonly Dictionary<string, (ManualResetEventSlim Mapping, ManualResetEventSlim Relay)> _natWaiters = new();

    private int _disposed;

    /// <summary>The address this stack listens on, <c>host:port</c>.</summary>
    public string BindAddress { get; }

    /// <summary>
    /// Every event this stack raises, in order — the
    /// <see cref="IAsyncEnumerable{T}"/> reader an application <c>await
    /// foreach</c>s. Backed by an unbounded <see cref="Channel{T}"/> that
    /// the poll thread is the only writer of; reading it never blocks
    /// that thread.
    /// </summary>
    public IAsyncEnumerable<SipralEventArgs> Events => _events.Reader.ReadAllAsync();

    /// <summary>
    /// Fired synchronously, on the poll thread, for every event this
    /// stack raises — the same thread <c>docs/08-ffi.md</c> promises the
    /// event callback runs on ("called from inside `sipral_stack_poll`,
    /// on the thread that polled"), so a handler that itself calls back
    /// into this stack is the re-entry that ABI section says is allowed.
    /// Most applications want <see cref="Events"/> instead; this exists
    /// for the caller that wants the ordinary C# event pattern and is
    /// prepared to keep its own handler quick, the way any handler on a
    /// library's own thread should be.
    /// </summary>
    public event EventHandler<SipralEventArgs>? EventReceived;

    /// <summary><c>sipral_stack_create</c>: binds the UDP socket and
    /// starts the poll thread, which raises
    /// <see cref="SipralEventKind.Started"/> on its first pass.
    ///
    /// <paramref name="ice"/> and <paramref name="nat"/> are
    /// <c>0</c> for this build's own default (everything off — exactly
    /// today's behaviour) or a <see cref="SipralIce"/>/<see
    /// cref="SipralNat"/> value; <paramref name="nat"/> set to
    /// <see cref="SipralNat.Stun"/> needs <paramref name="stunServer"/>
    /// as <c>host:port</c>, and <paramref name="turnServer"/> rides on it
    /// with <paramref name="turnUsername"/>/<paramref name="turnPassword"/>
    /// (`docs/06-nat.md`, `docs/08-ffi.md` "Behind a NAT"). Neither
    /// credential is written to any log, event or exception this package
    /// raises.</summary>
    public SipralStack(
        string bindHost = "127.0.0.1",
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
        bool? g729AnnexB = null)
    {
        _nat = nat;
        _turn = turnServer is not null;
        NativeLibraryLoader.EnsureRegistered();

        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _socket.Bind(new IPEndPoint(IPAddress.Parse(bindHost), bindPort));
        _socket.Blocking = false;
        BindAddress = FormatAddress((IPEndPoint)_socket.LocalEndPoint!);

        // Kept alive on this instance for as long as the stack lives: the
        // native library calls through the function pointer derived from
        // it until `sipral_stack_destroy`, and the generated
        // `SipralEventCallback` delegate's own doc comment is explicit
        // that the caller keeps it alive rather than reaching for
        // `UnmanagedCallersOnly` — which needs a static target and would
        // cost a `GCHandle`-keyed dispatch table to reach back to this
        // instance for no benefit over a plain kept-alive delegate here.
        // What actually keeps it reachable is not this field alone but
        // the poll thread started at the end of this constructor: its
        // `ThreadStart` closes over `this`, so the whole object graph —
        // this field included — stays a GC root for as long as that
        // thread runs, which is exactly until `Dispose` joins it.
        // `SipralTests.EventCallbackSurvivesGc` forces a collection while
        // a call is in flight to prove it.
        _callback = OnEvent;

        var bindAddressBytes = Encoding.UTF8.GetBytes(BindAddress);
        var userAgentBytes = userAgent is null ? null : Encoding.UTF8.GetBytes(userAgent);
        var codecsBytes = codecs is null ? null : Encoding.UTF8.GetBytes(codecs);
        var entropy = RandomBytes(32);
        var mediaSeed = RandomBytes(32);
        var stunServerBytes = stunServer is null ? null : Encoding.UTF8.GetBytes(stunServer);
        var turnServerBytes = turnServer is null ? null : Encoding.UTF8.GetBytes(turnServer);
        var turnUsernameBytes = turnUsername is null ? null : Encoding.UTF8.GetBytes(turnUsername);
        var turnPasswordBytes = turnPassword is null ? null : Encoding.UTF8.GetBytes(turnPassword);

        var stackHandle = 0ul;
        SipralStatus status;
        using (var bindPin = Pin(bindAddressBytes))
        using (var uaPin = Pin(userAgentBytes))
        using (var codecsPin = Pin(codecsBytes))
        using (var entropyPin = Pin(entropy))
        using (var seedPin = Pin(mediaSeed))
        using (var stunServerPin = Pin(stunServerBytes))
        using (var turnServerPin = Pin(turnServerBytes))
        using (var turnUsernamePin = Pin(turnUsernameBytes))
        using (var turnPasswordPin = Pin(turnPasswordBytes))
        {
            var config = SipralStackConfig.Sized();
            config.EventCallback = Marshal.GetFunctionPointerForDelegate(_callback);
            config.EventUserData = IntPtr.Zero;
            config.Transport = (uint)SipralTransport.Udp;
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

            status = NativeMethods.sipral_stack_create(config, out stackHandle);
        }
        SipralErrors.Check(status, "sipral_stack_create");

        _handle = new StackSafeHandle();
        _handle.SetValue(stackHandle);

        _pollThread = new Thread(Run) { IsBackground = true, Name = "sipral-stack" };
        _pollThread.Start();
    }

    /// <summary>Elapsed milliseconds since this stack was created — the
    /// figure every entry point below expects <c>now_ms</c> to be
    /// (<c>sipral_stack_create</c> fixes its own origin at the same
    /// moment).</summary>
    public ulong NowMs => (ulong)_origin.ElapsedMilliseconds;

    internal ulong Handle => _handle.Value;

    /// <summary><c>host:port</c>, the text shape every address crosses
    /// this ABI as.</summary>
    public static string FormatAddress(IPEndPoint endpoint) => $"{endpoint.Address}:{endpoint.Port}";

    /// <summary>The inverse of <see cref="FormatAddress"/>.</summary>
    public static (string Host, int Port) ParseAddress(string text)
    {
        var idx = text.LastIndexOf(':');
        return (text[..idx], int.Parse(text[(idx + 1)..]));
    }

    // -- accounts and calls --------------------------------------------

    /// <summary><c>sipral_account_add</c>. See <see cref="Account"/>.
    /// <paramref name="registrar"/> left out makes an account that never
    /// registers (<c>docs/08-ffi.md</c>, "An account with no registrar
    /// never registers"), with <paramref name="registrarAddress"/> as the
    /// outbound proxy every request it places still goes to.</summary>
    public Account AddAccount(
        string aor,
        string registrarAddress,
        string? registrar = null,
        string? contact = null,
        string? displayName = null,
        string? authUser = null,
        string? authPassword = null,
        ulong expiresSeconds = 0)
    {
        return Account.Add(this, aor, registrarAddress, registrar, contact, displayName, authUser, authPassword, expiresSeconds);
    }

    /// <summary>
    /// <c>sipral_call_place</c>, with this stack running the call's audio:
    /// a media socket is opened before the INVITE goes out, and its
    /// <c>host:port</c> is offered as <c>media_address</c>.
    /// </summary>
    public Call PlaceCall(Account account, string target, string mediaHost = "127.0.0.1", int mediaPort = 0, string? destination = null, SipralSrtp srtp = 0, SipralIce ice = 0)
    {
        var mediaSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        mediaSocket.Bind(new IPEndPoint(IPAddress.Parse(mediaHost), mediaPort));
        mediaSocket.Blocking = false;
        var mediaAddress = FormatAddress((IPEndPoint)mediaSocket.LocalEndPoint!);
        MapMediaSocket(mediaSocket, mediaAddress);

        var targetBytes = Encoding.UTF8.GetBytes(target);
        var mediaAddressBytes = Encoding.UTF8.GetBytes(mediaAddress);
        var destinationBytes = destination is null ? null : Encoding.UTF8.GetBytes(destination);

        ulong callHandle = 0;
        using (var targetPin = Pin(targetBytes))
        using (var mediaPin = Pin(mediaAddressBytes))
        using (var destPin = Pin(destinationBytes))
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

            try
            {
                SipralErrors.Call(() => NativeMethods.sipral_call_place(Handle, account.Handle, config, out callHandle, NowMs), "sipral_call_place");
            }
            catch
            {
                ForgetMediaSocket(mediaAddress);
                mediaSocket.Dispose();
                throw;
            }
        }

        var call = new Call(this, callHandle, mediaSocket, mediaAddress);
        _calls[call.Handle] = call;
        return call;
    }

    /// <summary>
    /// Opens a media socket for an incoming call and answers it there,
    /// through <c>sipral_call_answer_media</c>. <paramref name="args"/>
    /// is the <see cref="SipralEventKind.IncomingCall"/> event a listener
    /// read off <see cref="Events"/>.
    /// </summary>
    public Call AnswerCall(SipralEventArgs args, string mediaHost = "127.0.0.1", int mediaPort = 0)
    {
        var mediaSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        mediaSocket.Bind(new IPEndPoint(IPAddress.Parse(mediaHost), mediaPort));
        mediaSocket.Blocking = false;
        var mediaAddress = FormatAddress((IPEndPoint)mediaSocket.LocalEndPoint!);
        MapMediaSocket(mediaSocket, mediaAddress);

        var call = new Call(this, args.Call, mediaSocket, mediaAddress);
        RegisterCall(call);
        try
        {
            call.Answer();
        }
        catch
        {
            ForgetCall(call.Handle);
            ForgetMediaSocket(mediaAddress);
            mediaSocket.Dispose();
            throw;
        }
        return call;
    }

    /// <summary><c>sipral_call_reject</c> for an incoming call nothing has
    /// answered, so no <see cref="Call"/> — and no media socket — was
    /// ever needed.</summary>
    public void RejectCall(SipralEventArgs args, uint code = 486)
    {
        SipralErrors.Call(() => NativeMethods.sipral_call_reject(Handle, args.Call, code, NowMs), "sipral_call_reject");
    }

    internal Call? CallFor(ulong handle) => _calls.TryGetValue(handle, out var call) ? call : null;

    internal void RegisterCall(Call call) => _calls[call.Handle] = call;

    internal void ForgetCall(ulong handle) => _calls.TryRemove(handle, out _);

    // -- the poll thread --------------------------------------------------

    /// <summary>
    /// The C callback, on the poll thread. <see cref="SipralEventKind.ResolveNeeded"/>
    /// is delivered and not answered here. A dialog keeps the flow its
    /// INVITE went out on — the registrar or outbound proxy the account
    /// names, the only path that survives a NAT — and the event only says
    /// that the far end's <c>Contact</c> names some other address. This
    /// package has no resolver to answer it with, and answering with that
    /// <c>Contact</c> as a literal address moves the rest of the call onto
    /// it: behind a registrar reached through a port mapping or a NAT, the
    /// BYE then goes to an address nothing answers on. An application with
    /// a real lookup answers the event itself, through
    /// <c>sipral_stack_resolved</c>.
    /// </summary>
    private void OnEvent(IntPtr rawEvent, IntPtr _)
    {
        Deliver(SipralEventArgs.Decode(rawEvent));
    }

    private void Deliver(SipralEventArgs args)
    {
        // The call's own side effects (minting `Call.Media`, marking it
        // ended) happen before `args` reaches any reader, the same
        // ordering `bindings/python/sipral/stack.py`'s own `_deliver`
        // keeps and for the same reason: a consumer of `Events` may look
        // up `CallFor(args.Call)` the moment it wakes and read state that
        // must already be current.
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

        // `EventReceived` runs synchronously on this thread, which is the
        // one the native side is inside `sipral_stack_poll` on: what a
        // handler throws must not unwind back into that native frame, the
        // same "the callback does not unwind" contract `docs/08-ffi.md`
        // states by name for the Kotlin listener, and for the same
        // reason — undefined behaviour at best, and in practice the CLR's
        // own fatal-exception handling for a reverse P/Invoke, which takes
        // the whole process down over one subscriber's bug, every other
        // stack and call included. Caught here, at the one place this
        // thread crosses back into native code, exactly the way that
        // Kotlin section says a thrown listener "goes to the uncaught
        // exception handler of the thread it runs on ... never anywhere
        // else in the application" — this poll thread's own handler is
        // this catch, which lets it keep polling rather than let the whole
        // application go down with it.
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
            var destination = Marshal.PtrToStringUTF8(_transmitDestination, (int)transmit.DestinationLen) ?? string.Empty;
            var (host, port) = ParseAddress(destination);
            try
            {
                _socket.SendTo(payload, new IPEndPoint(IPAddress.Parse(host), port));
            }
            catch (SocketException)
            {
                // Best effort, like the poll thread's Python counterpart:
                // nothing here may throw, or this stack would never poll
                // again.
            }
        }
    }

    /// <summary><c>sipral_stack_poll_farewell</c>: what a call that just
    /// ended still owes -- its RTCP BYE, and with a TURN server the
    /// Refresh that gives its relay back -- sent through that call's own
    /// media socket to the address the stack names. Under ICE that is the
    /// path ICE chose or the TURN server, not necessarily the last address
    /// media came from, which is only the fallback for a packet that names
    /// none.</summary>
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

    // -- STUN/TURN on a media socket, before it has a call's media handle -

    /// <summary><c>sipral_stack_nat_map</c>, and the wait its own doc
    /// comment requires before a call may be described on <paramref
    /// name="sock"/>.
    ///
    /// A no-op when this stack was not built with <c>nat:
    /// SipralNat.Stun</c>: exactly today's behaviour for every other
    /// stack. Otherwise <paramref name="sock"/> is tracked in <see
    /// cref="_stunSockets"/> under <paramref name="address"/> —
    /// <see cref="Run"/> then hands what arrives on it to
    /// <c>sipral_stack_receive_stun</c> instead of treating it as
    /// ordinary media, and <see cref="DrainStun"/> sends what
    /// <c>sipral_stack_poll_stun</c> hands out for it — and this call
    /// blocks the *calling* thread, never the poll thread, until <see
    /// cref="SipralEventKind.NatMapping"/> names this socket (and, with
    /// this stack's own <c>turnServer</c> set, until its <see
    /// cref="SipralEventKind.NatRelay"/> too). <c>docs/06-nat.md</c> and
    /// <c>docs/08-ffi.md</c> ("Behind a NAT") put the first within five
    /// and a half seconds whatever the server does; <paramref
    /// name="timeout"/> leaves comfortable room over that before raising
    /// <see cref="TimeoutException"/>, which should not happen unless the
    /// poll thread itself has stopped.</summary>
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
        // `turnServer` rides the same socket: `sipral_call_place` and
        // `sipral_call_answer_media` both refuse a socket named here until
        // its `SIPRAL_EVENT_KIND_NAT_RELAY` has arrived too, allocated or
        // not (`docs/08-ffi.md`, "Behind a NAT").
        if (_turn && !waiters.Relay.Wait(wait))
        {
            ReleaseStunSocket(address);
            throw new TimeoutException($"no TURN allocation answer for {address} within {wait}");
        }
    }

    /// <summary>Stops treating <paramref name="address"/> as a
    /// pre-media-handle STUN/TURN socket: called once <see
    /// cref="SipralEventKind.MediaStarted"/> hands it to <see
    /// cref="CallMedia"/> (which reads it from then on) or once a call
    /// gives up on it before that ever happens.</summary>
    internal void ReleaseStunSocket(string address)
    {
        lock (_natLock)
        {
            _stunSockets.Remove(address);
            _natWaiters.Remove(address);
        }
    }

    /// <summary><c>sipral_stack_nat_unmap</c> for a media socket named
    /// with <c>sipral_stack_nat_map</c> that will carry no call after
    /// all — <c>sipral_call_place</c> or <c>sipral_call_answer_media</c>
    /// refused it, or <see cref="Dispose"/> is tearing the stack down
    /// with it still named. A no-op for a socket this stack never
    /// mapped (no <c>nat: SipralNat.Stun</c>, or the socket already
    /// reached <see cref="SipralEventKind.MediaStarted"/> and belongs to
    /// <see cref="CallMedia"/> now).</summary>
    internal void ForgetMediaSocket(string address)
    {
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
            // A relayed socket owes the server a Refresh with a lifetime
            // of zero, waiting in `sipral_stack_poll_stun` now
            // (`docs/08-ffi.md`, "sipral_stack_nat_unmap"); one drain
            // sends it from the socket while it is still tracked and
            // still open.
            DrainStun();
        }
        catch (SipralException)
        {
            // Best effort on the way out, like the poll thread's Python
            // counterpart.
        }
        ReleaseStunSocket(address);
    }

    /// <summary><c>sipral_stack_poll_stun</c>, until nothing is left to
    /// send. <c>transmit.Source</c> names which media socket to send
    /// from — exactly the point of this queue being separate from
    /// <see cref="DrainTransmit"/>'s: a STUN request for one socket sent
    /// from another would teach the server the wrong socket's mapping,
    /// silently (<c>docs/08-ffi.md</c>, "Three entry points rather than a
    /// second use of the two signalling ones").</summary>
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
                // `sock` was still `_stunSockets[sourceText]` at the lock
                // above, but `Call.Close`/`ForgetMediaSocket` on another
                // thread can remove it from that dictionary and dispose
                // it right after this thread let go of `_natLock` — the
                // same race the `Run` loop's own catches guard against,
                // one step later.
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
            var checkRead = new List<Socket>(stunSnapshot.Count + 1) { _socket };
            checkRead.AddRange(stunSnapshot);
            try
            {
                Socket.Select(checkRead, null, null, 50_000);
            }
            catch (SocketException)
            {
                checkRead.Clear();
            }
            catch (ObjectDisposedException)
            {
                // A media socket in `stunSnapshot` was disposed by
                // another thread — `Call.Close`/`ForgetMediaSocket`
                // race with this select the way
                // `bindings/python/sipral/stack.py`'s own `_run` can
                // race a socket's `close()` too, caught there as an
                // `OSError` on the next `recvfrom` instead. This poll
                // just skips the sockets it cannot trust this pass;
                // the next one reads `_stunSockets` fresh.
                checkRead.Clear();
            }

            foreach (var sock in checkRead)
            {
                if (ReferenceEquals(sock, _socket))
                {
                    try
                    {
                        EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                        var count = _socket.ReceiveFrom(_receiveBuffer, ref from);
                        var fromText = ToSBytes(Encoding.UTF8.GetBytes(FormatAddress((IPEndPoint)from)));
                        // `transport` here is a transport *id* (Sipral.TransportMain,
                        // i.e. 0, for the one this stack was created with, or a
                        // further one sipral_stack_transport_bind minted) — not a
                        // SipralTransport *kind*. This stack never binds a second
                        // transport, so every datagram it reads off its one UDP
                        // socket belongs to the main one.
                        NativeMethods.sipral_stack_receive_datagram(
                            Handle, global::Sipral.Sipral.TransportMain, _receiveBuffer, (nuint)count,
                            fromText, (nuint)fromText.Length, null!, 0, NowMs);
                    }
                    catch (SocketException)
                    {
                    }
                }
                else
                {
                    // A media socket `MapMediaSocket` named, still
                    // waiting for its own mapping/relay or already
                    // described but with no media handle yet: everything
                    // arriving on it still goes to
                    // `sipral_stack_receive_stun` (`docs/08-ffi.md`,
                    // "Behind a NAT" — "Until the call's media handle
                    // exists, everything arriving on its socket still
                    // goes to sipral_stack_receive_stun") until
                    // `Call.Deliver` releases it on
                    // `SIPRAL_EVENT_KIND_MEDIA_STARTED`.
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
                        // `sock` was still in `checkRead` because
                        // `Socket.Select` found it ready before this loop
                        // began, but `Call.Close`/`SipralStack.Dispose` can
                        // dispose the very same media socket from an
                        // application thread with no lock between that
                        // return and this `ReceiveFrom` — the same race
                        // the `ObjectDisposedException` catch around
                        // `Socket.Select` above guards, one step later.
                        // `_stunSockets`/`_natWaiters` are already cleared
                        // for it by then (`ReleaseStunSocket` runs before
                        // the socket is disposed), so there is nothing
                        // left here to clean up.
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
        }
    }

    /// <summary>
    /// Hangs up whatever calls are still open, gives the poll thread one
    /// more round to send the BYEs that queues and the RTCP goodbyes
    /// <see cref="DrainFarewells"/> then owes, and only then destroys the
    /// stack — the same ordering
    /// <c>bindings/python/sipral/stack.py</c>'s own <c>close</c> uses and
    /// for the same reason: closing each call's media first would forget
    /// it and close its socket before that farewell has anywhere left to
    /// go.
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

        // Every media socket still named with `sipral_stack_nat_map` and
        // never reached by a call's own media handle —
        // `sipral_stack_destroy` sends nothing, and a relay left
        // allocated stays on the server until its lifetime runs out
        // (`docs/08-ffi.md`, "sipral_stack_nat_unmap"). Each call above
        // already did this for a socket it still owned; this catches one
        // mapped and then abandoned before any call was ever placed on it.
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
        _events.Writer.TryComplete();

        _handle.Dispose();
        _socket.Dispose();
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
