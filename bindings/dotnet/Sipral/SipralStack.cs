// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
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
    private readonly byte[] _receiveBuffer = new byte[TransmitBytes];

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
    /// <see cref="SipralEventKind.Started"/> on its first pass.</summary>
    public SipralStack(
        string bindHost = "127.0.0.1",
        int bindPort = 0,
        string? userAgent = null,
        string? codecs = null,
        uint frameMs = 0,
        bool? offerDtmf = null,
        SipralSrtp srtp = 0)
    {
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

        var stackHandle = 0ul;
        SipralStatus status;
        using (var bindPin = Pin(bindAddressBytes))
        using (var uaPin = Pin(userAgentBytes))
        using (var codecsPin = Pin(codecsBytes))
        using (var entropyPin = Pin(entropy))
        using (var seedPin = Pin(mediaSeed))
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
    public Call PlaceCall(Account account, string target, string mediaHost = "127.0.0.1", int mediaPort = 0, string? destination = null, SipralSrtp srtp = 0)
    {
        var mediaSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        mediaSocket.Bind(new IPEndPoint(IPAddress.Parse(mediaHost), mediaPort));
        mediaSocket.Blocking = false;
        var mediaAddress = FormatAddress((IPEndPoint)mediaSocket.LocalEndPoint!);

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
            if (destinationBytes is not null)
            {
                config.Destination = destPin.Pointer;
                config.DestinationLen = (nuint)destinationBytes.Length;
            }

            SipralErrors.Call(() => NativeMethods.sipral_call_place(Handle, account.Handle, config, out callHandle, NowMs), "sipral_call_place");
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

        var call = new Call(this, args.Call, mediaSocket, mediaAddress);
        RegisterCall(call);
        call.Answer();
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

    private void OnEvent(IntPtr rawEvent, IntPtr _)
    {
        var args = SipralEventArgs.Decode(rawEvent);
        if (args.Kind == SipralEventKind.ResolveNeeded)
        {
            Resolve(args);
        }
        Deliver(args);
    }

    /// <summary>
    /// Answers <see cref="SipralEventKind.ResolveNeeded"/> with the host
    /// as given, treated as a literal address: this package wires no DNS
    /// resolver of its own, the same choice
    /// <c>bindings/python/sipral/stack.py</c> makes and for the same
    /// reason — <c>docs/08-ffi.md</c> leaves RFC 3263 lookup to the
    /// caller on purpose, and it is exactly right for the numeric
    /// <c>host:port</c> targets <see cref="PlaceCall"/> and two loopback
    /// stacks calling each other direct are built around.
    /// </summary>
    private void Resolve(SipralEventArgs args)
    {
        var resolve = args.Resolve;
        if (resolve is null || string.IsNullOrEmpty(resolve.Host))
        {
            return;
        }
        var port = resolve.Port == 0 ? 5060 : resolve.Port;
        var protocol = resolve.Protocol == 0 ? SipralTransport.Udp : resolve.Protocol;
        var address = ToSBytes(Encoding.UTF8.GetBytes($"{resolve.Host}:{port}"));
        NativeMethods.sipral_stack_resolved(Handle, resolve.Dialog, address, (nuint)address.Length, (uint)protocol);
    }

    private void Deliver(SipralEventArgs args)
    {
        // The call's own side effects (minting `Call.Media`, marking it
        // ended) happen before `args` reaches any reader, the same
        // ordering `bindings/python/sipral/stack.py`'s own `_deliver`
        // keeps and for the same reason: a consumer of `Events` may look
        // up `CallFor(args.Call)` the moment it wakes and read state that
        // must already be current.
        var call = args.Call != 0 ? CallFor(args.Call) : null;
        call?.Deliver(args);

        EventReceived?.Invoke(this, args);
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

    /// <summary><c>sipral_stack_poll_farewell</c>: the RTCP BYE a call
    /// that just ended still owes, sent through that call's own media
    /// socket and to the last address it was actually heard from.</summary>
    private void DrainFarewells()
    {
        while (true)
        {
            var packet = SipralMediaPacket.Sized();
            packet.Data = _farewellData;
            packet.Capacity = TransmitBytes;
            packet.Destination = IntPtr.Zero;
            packet.DestinationCapacity = 0;
            var status = NativeMethods.sipral_stack_poll_farewell(Handle, out var endedCall, ref packet);
            if (status != SipralStatus.Ok || packet.Len == 0)
            {
                return;
            }
            var media = CallFor(endedCall)?.Media;
            var remoteAddress = media?.RemoteAddress;
            if (media is null || remoteAddress is null)
            {
                continue;
            }
            var payload = new byte[(int)packet.Len];
            Marshal.Copy(_farewellData, payload, 0, payload.Length);
            media.SendTo(payload, remoteAddress);
        }
    }

    private void Run()
    {
        while (!_closed.IsSet)
        {
            if (_socket.Poll(50_000, SelectMode.SelectRead))
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

            var result = SipralPollResult.Sized();
            var status = NativeMethods.sipral_stack_poll(Handle, NowMs, ref result);
            if (status != SipralStatus.Ok)
            {
                continue;
            }
            DrainTransmit();
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
