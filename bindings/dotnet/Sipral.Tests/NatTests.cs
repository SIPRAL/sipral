// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// <c>nat: SipralNat.Stun</c> and <c>stunServer</c> on <see
/// cref="SipralStack"/> — the .NET counterpart of
/// <c>bindings/python/tests/test_nat.py</c>, whose own docstring explains
/// what each test proves and why a unit test stops where it does for
/// TURN. <see cref="FakeStunServer"/> is the same RFC 5389 Section 15.2
/// responder that file's <c>_FakeStunServer</c> is.
/// </summary>
public sealed class NatTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(8);

    /// <summary>A UDP socket that answers every STUN Binding request it
    /// reads with the same made-up public address.
    ///
    /// Without <paramref name="credential"/>, every other message — a TURN
    /// Allocate among them — is recorded in <see cref="OtherRequests"/> and
    /// never answered, the way <c>AllocateRequestLeavesForTheConfiguredServer</c>
    /// needs it. With one, it is a real, if fake, TURN server too: an
    /// unauthenticated Allocate (RFC 8656 Section 7) gets the mandatory 401
    /// with a REALM and a NONCE, a signed one is checked against the
    /// long-term key and answered with a relay on <see cref="RelayHost"/>,
    /// and a Refresh — among them the one with a lifetime of zero that
    /// gives an allocation back — is recorded in <see cref="Requests"/> the
    /// same way every request is, signed or not, answered or not
    /// (<c>bindings/swift/Tests/SipralTests/NatTests.swift</c>'s own
    /// <c>FakeStunServer</c> and <c>bindings/kotlin/.../NatCheck.kt</c>'s).</summary>
    internal sealed class FakeStunServer : IDisposable
    {
        private const ushort BindingRequest = 0x0001;
        private const ushort BindingSuccess = 0x0101;
        private const ushort XorMappedAddress = 0x0020;
        private const ushort XorRelayedAddress = 0x0016;
        private const ushort ErrorCode = 0x0009;
        private const ushort RealmAttr = 0x0014;
        private const ushort NonceAttr = 0x0015;
        private const ushort UsernameAttr = 0x0006;
        private const ushort MessageIntegrity = 0x0008;
        private const ushort LifetimeAttr = 0x000D;
        private const ushort AllocateRequest = 0x0003;
        private const ushort AllocateSuccess = 0x0103;
        private const ushort AllocateError = 0x0113;
        private const ushort RefreshRequest = 0x0004;
        private const uint MagicCookie = 0x2112A442;
        public const string Realm = "sipral.test";
        public const string Nonce = "0123456789abcdef";
        public const string RelayHost = "198.51.100.9";

        private readonly Socket _socket;
        private readonly CancellationTokenSource _stop = new();
        private readonly Thread _thread;
        private readonly (string username, string password)? _credential;
        public readonly string PublicHost;
        public readonly ushort PublicPort;
        public string Address { get; }
        public List<byte[]> OtherRequests { get; } = new();
        public List<(ushort Method, Dictionary<ushort, byte[]> Attributes)> Requests { get; } = new();
        public bool? SignedAllocateVerified { get; private set; }
        private readonly object _lock = new();

        public FakeStunServer(string publicHost, ushort publicPort, (string username, string password)? credential = null)
        {
            PublicHost = publicHost;
            PublicPort = publicPort;
            _credential = credential;
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _socket.ReceiveTimeout = 50;
            Address = $"127.0.0.1:{((IPEndPoint)_socket.LocalEndPoint!).Port}";
            _thread = new Thread(Run) { IsBackground = true };
            _thread.Start();
        }

        private void Run()
        {
            var buffer = new byte[2048];
            while (!_stop.IsCancellationRequested)
            {
                EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                int count;
                try
                {
                    count = _socket.ReceiveFrom(buffer, ref from);
                }
                catch (SocketException)
                {
                    continue;
                }
                if (count < 20)
                {
                    continue;
                }
                var data = new byte[count];
                Array.Copy(buffer, data, count);
                var cookieBytes = BitConverter.GetBytes(MagicCookie);
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(cookieBytes);
                }
                if (data[4] != cookieBytes[0] || data[5] != cookieBytes[1] || data[6] != cookieBytes[2] || data[7] != cookieBytes[3])
                {
                    continue;
                }
                var msgType = (ushort)((data[0] << 8) | data[1]);
                var transactionId = new byte[12];
                Array.Copy(data, 8, transactionId, 0, 12);
                var attributes = ParseAttributes(data);
                var method = (ushort)((msgType & 0x000F) | ((msgType & 0x00E0) >> 1) | ((msgType & 0x3E00) >> 2));
                lock (_lock)
                {
                    Requests.Add((method, attributes));
                }
                if (msgType == BindingRequest)
                {
                    var response = BuildResponse(transactionId, PublicHost, PublicPort);
                    _socket.SendTo(response, from);
                    continue;
                }
                if (method == AllocateRequest && _credential is not null)
                {
                    var answer = AnswerAllocate(data, transactionId, attributes, (IPEndPoint)from);
                    if (answer is not null)
                    {
                        _socket.SendTo(answer, from);
                    }
                    continue;
                }
                lock (_lock)
                {
                    OtherRequests.Add(data);
                }
            }
        }

        internal static Dictionary<ushort, byte[]> ParseAttributes(byte[] data)
        {
            var attributes = new Dictionary<ushort, byte[]>();
            var offset = 20;
            while (offset + 4 <= data.Length)
            {
                var attribute = (ushort)((data[offset] << 8) | data[offset + 1]);
                var length = (data[offset + 2] << 8) | data[offset + 3];
                if (offset + 4 + length > data.Length)
                {
                    break;
                }
                var value = new byte[length];
                Array.Copy(data, offset + 4, value, 0, length);
                attributes[attribute] = value;
                offset += 4 + (length + 3) / 4 * 4;
            }
            return attributes;
        }

        private byte[]? AnswerAllocate(byte[] data, byte[] transactionId, Dictionary<ushort, byte[]> attributes, IPEndPoint from)
        {
            var (username, password) = _credential!.Value;
            if (!attributes.TryGetValue(UsernameAttr, out var given))
            {
                return BuildMessage(AllocateError, transactionId, new[]
                {
                    (ErrorCode, new byte[] { 0, 0, 4, 1 }.Concat(Encoding.UTF8.GetBytes("Unauthorized")).ToArray()),
                    (RealmAttr, Encoding.UTF8.GetBytes(Realm)),
                    (NonceAttr, Encoding.UTF8.GetBytes(Nonce)),
                });
            }
            var key = LongTermKey(username, Realm, password);
            var verified = Encoding.UTF8.GetString(given) == username && IntegrityHolds(data, key);
            SignedAllocateVerified = verified;
            if (!verified)
            {
                return BuildMessage(AllocateError, transactionId, new[]
                {
                    (ErrorCode, new byte[] { 0, 0, 4, 1 }.Concat(Encoding.UTF8.GetBytes("Unauthorized")).ToArray()),
                });
            }
            var port = (ushort)from.Port;
            var relayed = XorAddress(RelayHost, Moved(port, 20000));
            var mapped = XorAddress(PublicHost, Moved(port, 10000));
            return Signed(AllocateSuccess, transactionId, new[]
            {
                (XorRelayedAddress, relayed),
                (XorMappedAddress, mapped),
                (LifetimeAttr, new byte[] { 0, 0, 0x02, 0x58 }),
            }, key);
        }

        private static ushort Moved(ushort port, int distance) => (ushort)(port > 40000 ? port - distance : port + distance);

        internal static byte[] XorAddress(string host, ushort port)
        {
            var cookie = CookieBytes();
            var ipBytes = IPAddress.Parse(host).GetAddressBytes();
            var xport = (ushort)(port ^ (MagicCookie >> 16));
            var xaddr = new byte[4];
            for (var i = 0; i < 4; i++)
            {
                xaddr[i] = (byte)(ipBytes[i] ^ cookie[i]);
            }
            var value = new byte[8];
            value[0] = 0;
            value[1] = 0x01;
            value[2] = (byte)(xport >> 8);
            value[3] = (byte)xport;
            Array.Copy(xaddr, 0, value, 4, 4);
            return value;
        }

        private static byte[] CookieBytes()
        {
            var cookie = BitConverter.GetBytes(MagicCookie);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(cookie);
            }
            return cookie;
        }

        internal static byte[] BuildMessage(ushort type, byte[] transactionId, (ushort attribute, byte[] value)[] attributes)
        {
            var body = new List<byte>();
            foreach (var (attribute, value) in attributes)
            {
                body.Add((byte)(attribute >> 8));
                body.Add((byte)attribute);
                body.Add((byte)(value.Length >> 8));
                body.Add((byte)value.Length);
                body.AddRange(value);
                var padding = (4 - value.Length % 4) % 4;
                for (var i = 0; i < padding; i++)
                {
                    body.Add(0);
                }
            }
            var message = new List<byte>
            {
                (byte)(type >> 8), (byte)type, (byte)(body.Count >> 8), (byte)body.Count,
            };
            message.AddRange(CookieBytes());
            message.AddRange(transactionId);
            message.AddRange(body);
            return message.ToArray();
        }

        /// <summary>RFC 8489 Section 9.2.2: MD5 of <c>username:realm:password</c>.</summary>
        internal static byte[] LongTermKey(string username, string realm, string password) =>
            MD5.HashData(Encoding.UTF8.GetBytes($"{username}:{realm}:{password}"));

        private static byte[] Hmac(byte[] data, byte[] key)
        {
            using var hmac = new HMACSHA1(key);
            return hmac.ComputeHash(data);
        }

        /// <summary>RFC 8489 Section 14.5: the HMAC covers the message up to
        /// the attribute, with the header's length counting up to the
        /// attribute's end.</summary>
        internal static bool IntegrityHolds(byte[] message, byte[] key)
        {
            var offset = 20;
            while (offset + 4 <= message.Length)
            {
                var attribute = (ushort)((message[offset] << 8) | message[offset + 1]);
                var length = (message[offset + 2] << 8) | message[offset + 3];
                if (attribute == MessageIntegrity && length == 20 && offset + 24 <= message.Length)
                {
                    var covered = new byte[offset];
                    Array.Copy(message, covered, offset);
                    var counted = offset + 24 - 20;
                    covered[2] = (byte)(counted >> 8);
                    covered[3] = (byte)counted;
                    var expected = new byte[20];
                    Array.Copy(message, offset + 4, expected, 0, 20);
                    return Hmac(covered, key).AsSpan().SequenceEqual(expected);
                }
                offset += 4 + (length + 3) / 4 * 4;
            }
            return false;
        }

        internal static byte[] Signed(ushort type, byte[] transactionId, (ushort attribute, byte[] value)[] attributes, byte[] key)
        {
            var unsigned = BuildMessage(type, transactionId, attributes);
            var counted = unsigned.Length - 20 + 24;
            unsigned[2] = (byte)(counted >> 8);
            unsigned[3] = (byte)counted;
            var signature = Hmac(unsigned, key);
            var signed = new byte[unsigned.Length + 4 + signature.Length];
            Array.Copy(unsigned, signed, unsigned.Length);
            signed[unsigned.Length] = 0x00;
            signed[unsigned.Length + 1] = 0x08;
            signed[unsigned.Length + 2] = 0x00;
            signed[unsigned.Length + 3] = 0x14;
            Array.Copy(signature, 0, signed, unsigned.Length + 4, signature.Length);
            return signed;
        }

        private static byte[] BuildResponse(byte[] transactionId, string host, ushort port) =>
            BuildMessage(BindingSuccess, transactionId, new[] { (XorMappedAddress, XorAddress(host, port)) });

        public List<byte[]> SnapshotOtherRequests()
        {
            lock (_lock)
            {
                return new List<byte[]>(OtherRequests);
            }
        }

        public List<(ushort Method, Dictionary<ushort, byte[]> Attributes)> SnapshotRequests()
        {
            lock (_lock)
            {
                return new List<(ushort, Dictionary<ushort, byte[]>)>(Requests);
            }
        }

        public void Dispose()
        {
            _stop.Cancel();
            _thread.Join(TimeSpan.FromSeconds(2));
            _socket.Dispose();
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

    [Fact]
    public async Task SignallingSocketLearnsTheMappingOnItsOwn()
    {
        using var server = new FakeStunServer("203.0.113.7", 40000);
        using var alice = new SipralStack(audio: SipralAudio.Application, nat: SipralNat.Stun, stunServer: server.Address);

        var evt = await FirstMatchingAsync(alice.Events, e => e.Kind == SipralEventKind.NatMapping, Timeout);
        Assert.NotNull(evt.Nat);
        Assert.True(evt.Nat!.Signalling);
        Assert.Equal("203.0.113.7:40000", evt.Nat.Mapped);
    }

    /// <summary><c>stunFallbacks</c>: the first server named never answers,
    /// and the signalling socket is asked of the next one once five and a
    /// half seconds have gone by, with <see cref="SipralEventKind.StunServer"/>
    /// saying so.</summary>
    [Fact]
    public async Task ASilentFirstServerHandsTheSocketToTheNext()
    {
        using var silent = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        silent.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var silentAddress = $"127.0.0.1:{((IPEndPoint)silent.LocalEndPoint!).Port}";
        using var server = new FakeStunServer("203.0.113.7", 40010);
        using var alice = new SipralStack(
            audio: SipralAudio.Application, nat: SipralNat.Stun, stunServer: silentAddress,
            stunFallbacks: new[] { server.Address });

        var changed = await FirstMatchingAsync(alice.Events, e => e.Kind == SipralEventKind.StunServer,
            TimeSpan.FromSeconds(10));
        Assert.NotNull(changed.StunServer);
        Assert.Equal(SipralStunServerState.Changed, changed.StunServer!.State);
        Assert.Equal(silentAddress, changed.StunServer.Previous);
        Assert.Equal(server.Address, changed.StunServer.Server);
        var mapped = await FirstMatchingAsync(alice.Events, e => e.Kind == SipralEventKind.NatMapping, Timeout);
        Assert.Equal("203.0.113.7:40010", mapped.Nat!.Mapped);
    }

    /// <summary>An account the STUN answer showed behind a NAT keeps its
    /// registrar's flow open: a double CRLF, alone in a datagram, reaches
    /// the registrar every <c>registrarKeepaliveMs</c>, and none does with
    /// the keep-alive off (`docs/06-nat.md`, "Refresh").</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AnAccountBehindTheNatKeepsItsRegistrarsFlowOpen(bool keepalive)
    {
        using var server = new FakeStunServer("203.0.113.7", 40000);
        using var registrar = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        registrar.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        registrar.ReceiveTimeout = 100;
        using var alice = new SipralStack(
            audio: SipralAudio.Application,nat: SipralNat.Stun,
            stunServer: server.Address,
            registrarKeepalive: keepalive,
            registrarKeepaliveMs: keepalive ? 1000ul : 0ul);

        await FirstMatchingAsync(alice.Events, e => e.Kind == SipralEventKind.NatMapping, Timeout);
        var registrarAddress = $"127.0.0.1:{((IPEndPoint)registrar.LocalEndPoint!).Port}";
        var account = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress, registrar: "sip:sipral.invalid");
        account.Register();

        var pings = 0;
        var buffer = new byte[2048];
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(4);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var read = registrar.Receive(buffer);
                if (read == 4 && Encoding.ASCII.GetString(buffer, 0, read) == "\r\n\r\n")
                {
                    pings++;
                }
            }
            catch (SocketException)
            {
            }
        }
        if (keepalive)
        {
            Assert.True(pings >= 2, $"{pings} keep-alives reached the registrar in four seconds");
        }
        else
        {
            Assert.Equal(0, pings);
        }
    }

    /// <summary><see cref="SipralStack.SetStunServers"/> on a stack created
    /// with nobody to ask: the signalling socket is mapped at once, a call
    /// placed afterwards is offered at the address the server handed out,
    /// and an entry that is not an address is refused.</summary>
    [Fact]
    public async Task AListNamedLaterMapsTheSignallingAndTheCalls()
    {
        using var server = new FakeStunServer("203.0.113.7", 40020);
        using var alice = new SipralStack(audio: SipralAudio.Application);
        using var bob = new SipralStack(audio: SipralAudio.Application);

        alice.SetStunServers(new[] { server.Address });
        var mapped = await FirstMatchingAsync(alice.Events, e => e.Kind == SipralEventKind.NatMapping, Timeout);
        Assert.Equal("203.0.113.7:40020", mapped.Nat!.Mapped);

        var aliceAccount = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);
        var aliceCall = alice.PlaceCall(aliceAccount, $"sip:bob@{bob.BindAddress}");
        try
        {
            var incoming = await FirstMatchingAsync(bob.Events, e => e.Kind == SipralEventKind.IncomingCall, Timeout);
            var message = Encoding.UTF8.GetString(incoming.Message ?? Array.Empty<byte>());
            Assert.Contains("c=IN IP4 203.0.113.7", message);
        }
        finally
        {
            aliceCall.Close();
        }

        alice.SetStunServers(Array.Empty<string>());
        var refused = Assert.Throws<SipralException>(() => alice.SetStunServers(new[] { "not an address" }));
        Assert.Equal(SipralStatus.InvalidArgument, refused.Status);
    }

    [Fact]
    public async Task CallOffersTheMappedMediaAddress()
    {
        using var server = new FakeStunServer("203.0.113.7", 40000);
        using var alice = new SipralStack(audio: SipralAudio.Application, nat: SipralNat.Stun, stunServer: server.Address);
        using var bob = new SipralStack(audio: SipralAudio.Application);

        var aliceAccount = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);

        var aliceCall = alice.PlaceCall(aliceAccount, $"sip:bob@{bob.BindAddress}");
        try
        {
            // sipral_call_event_t's LocalSdp/RemoteSdp are only ever set
            // on SessionChanged (a hold, a re-INVITE — neither happens
            // here); the offer itself is read the way any SIP listener
            // would, off the raw INVITE SipralEventKind.IncomingCall
            // attaches as Message.
            var incoming = await FirstMatchingAsync(bob.Events, e => e.Kind == SipralEventKind.IncomingCall, Timeout);
            var message = Encoding.UTF8.GetString(incoming.Message ?? Array.Empty<byte>());
            Assert.Contains("c=IN IP4 203.0.113.7", message);
            Assert.Contains("203.0.113.7:40000", message);
        }
        finally
        {
            aliceCall.Close();
        }
    }

    [Fact]
    public async Task AllocateRequestLeavesForTheConfiguredServer()
    {
        using var server = new FakeStunServer("203.0.113.8", 40001);
        using var alice = new SipralStack(
            audio: SipralAudio.Application,nat: SipralNat.Stun, stunServer: server.Address,
            turnServer: server.Address, turnUsername: "labuser", turnPassword: "labpass");

        // sipral_call_place refuses a socket named with
        // sipral_stack_nat_map until both its NAT_MAPPING and NAT_RELAY
        // have answered, and this fake server never answers the
        // Allocate its own NAT_RELAY would need — so this reaches
        // SipralStack.MapMediaSocket directly, on a thread of its own,
        // with a short timeout. What it proves is that the Allocate
        // left, not that a call could be placed on the socket.
        var mediaSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        mediaSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var mediaAddress = SipralStack.FormatAddress((IPEndPoint)mediaSocket.LocalEndPoint!);

        Exception? caught = null;
        var thread = new Thread(() =>
        {
            try
            {
                alice.MapMediaSocket(mediaSocket, mediaAddress, TimeSpan.FromSeconds(2));
            }
            catch (Exception ex)
            {
                caught = ex;
            }
        });
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(5)), "MapMediaSocket did not return");
        Assert.IsType<TimeoutException>(caught);

        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
        while (server.SnapshotOtherRequests().Count == 0 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(50);
        }
        var requests = server.SnapshotOtherRequests();
        Assert.True(requests.Count > 0, "no Allocate request reached the server");
        var msgType = (ushort)((requests[0][0] << 8) | requests[0][1]);
        Assert.Equal(0x0003, msgType); // Allocate request (RFC 8656 Section 5)

        mediaSocket.Dispose();
        alice.Dispose();
    }

    /// <summary>Task 8.5.5, <c>intern/rapoarte/2026-09-25-nat-layers.json</c>
    /// (<c>natmobile.review.findings[1]</c>): <c>SipralStack.DrainFarewells</c>
    /// must send what <c>sipral_stack_poll_farewell</c> hands out to the
    /// destination it names -- the TURN server, for the Refresh with a
    /// lifetime of zero that gives a relay back
    /// (<c>crates/sipral/src/relay.rs</c>, "gives it back when the call
    /// ends") -- and only fall back to the last address media was heard
    /// from when it names none.
    ///
    /// <c>relay.rs</c> also says: "A call whose peer does no ICE never uses
    /// it, and gives it back the same way" -- so this needs nothing more
    /// than a call that reaches <c>bob</c>, an ordinary stack with no NAT
    /// handling of its own, and is then closed. Were the destination
    /// ignored in favour of the far end's own address, as it once was,
    /// this fake TURN server would never see the Refresh at all.</summary>
    [Fact]
    public async Task TurnAllocationIsGivenBackWhenTheCallEnds()
    {
        var host = RoutableAddress();
        if (host is null)
        {
            return; // no routable address on this machine for ICE to gather a host candidate from
        }
        const string password = "turn-secret-42";
        using var server = new FakeStunServer("203.0.113.9", 40002, ("alice-turn", password));
        // codecs: "PCMU" keeps the offer short -- three ICE candidates
        // (host, server-reflexive, relayed) on top of every codec this
        // build has by default clears RFC 3261 Section 18.1.1's
        // 1300-byte line, and this loopback pair has no stream transport
        // open to fall back to.
        var alice = new SipralStack(
            audio: SipralAudio.Application,bindHost: host, nat: SipralNat.Stun, ice: SipralIce.Offered, codecs: "PCMU",
            stunServer: server.Address, turnServer: server.Address,
            turnUsername: "alice-turn", turnPassword: password);
        using var bob = new SipralStack(audio: SipralAudio.Application, bindHost: host, codecs: "PCMU");
        try
        {
            var aliceAccount = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
            bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);

            var aliceCall = alice.PlaceCall(aliceAccount, $"sip:bob@{bob.BindAddress}", mediaHost: host);

            var relayEvent = await FirstMatchingAsync(alice.Events, e => e.Kind == SipralEventKind.NatRelay, Timeout);
            Assert.Equal(SipralNatRelay.Allocated, relayEvent.Relay!.Outcome);

            var incoming = await FirstMatchingAsync(bob.Events, e => e.Kind == SipralEventKind.IncomingCall, Timeout);
            var bobCall = bob.AnswerCall(incoming, mediaHost: host);

            // The session has to actually open -- and the relay actually
            // become the call's -- before there is anything for a
            // farewell to give back.
            using var cts = new CancellationTokenSource(Timeout);
            Assert.NotNull(await aliceCall.WaitForMediaAsync(cts.Token));

            // SipralStack.Dispose, not Call.Close: hanging up and
            // forgetting the call right here would race the poll
            // thread's own drain of the farewell it leaves behind
            // (Dispose's own doc comment). Dispose hangs up, gives the
            // poll thread a round to drain both queues while the call is
            // still tracked, and only then forgets it.
            alice.Dispose();
            bobCall.Close();

            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            (ushort Method, Dictionary<ushort, byte[]> Attributes)? refresh = null;
            while (refresh is null && DateTime.UtcNow < deadline)
            {
                refresh = server.SnapshotRequests().FirstOrDefault(r => r.Method == 0x0004);
                if (refresh?.Attributes is null)
                {
                    refresh = null;
                    await Task.Delay(50);
                }
            }
            Assert.True(
                refresh is not null,
                $"the TURN server never saw the Refresh that gives the relay back -- " +
                $"the farewell went somewhere other than {server.Address}");
            Assert.True(refresh!.Value.Attributes.TryGetValue(0x000D, out var lifetime));
            Assert.Equal(new byte[] { 0, 0, 0, 0 }, lifetime);
        }
        finally
        {
            alice.Dispose();
        }
    }

    [Fact]
    public async Task TwoStacksTalkThroughIceOnARoutableAddress()
    {
        var host = RoutableAddress();
        if (host is null)
        {
            return; // no routable address on this machine to gather a host candidate from
        }

        using var alice = new SipralStack(audio: SipralAudio.Application, bindHost: host, ice: SipralIce.Required);
        using var bob = new SipralStack(audio: SipralAudio.Application, bindHost: host, ice: SipralIce.Required);

        var aliceAccount = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);

        var aliceCall = alice.PlaceCall(aliceAccount, $"sip:bob@{bob.BindAddress}", mediaHost: host, ice: SipralIce.Required);
        var incoming = await FirstMatchingAsync(bob.Events, e => e.Kind == SipralEventKind.IncomingCall, Timeout);
        var bobCall = bob.AnswerCall(incoming, mediaHost: host);

        try
        {
            using var cts = new CancellationTokenSource(Timeout);
            Assert.NotNull(await aliceCall.WaitForMediaAsync(cts.Token));
            Assert.NotNull(await bobCall.WaitForMediaAsync(cts.Token));

            // MediaPathChosen is the agent's own nomination, on each side;
            // reaching it, rather than MediaFailed, is what tells this
            // from a call ICE never got to run on.
            await FirstMatchingAsync(aliceCall.Events, e => e.Kind == SipralEventKind.MediaPathChosen, Timeout);
            await FirstMatchingAsync(bobCall.Events, e => e.Kind == SipralEventKind.MediaPathChosen, Timeout);

            Assert.Equal(SipralCallState.Confirmed, aliceCall.State);
            Assert.Equal(SipralCallState.Confirmed, bobCall.State);
            Assert.True(aliceCall.Media!.Info().Sending);
            Assert.True(bobCall.Media!.Info().Receiving);

            // D5's path half: the one pair that carries the call, named
            var paths = aliceCall.Media!.PathCandidates();
            var chosen = paths.Where(p => p.Kind == SipralPathKind.Pair && p.Outcome == SipralPathOutcome.Selected).ToList();
            Assert.Single(chosen);
            Assert.Equal(SipralCandidateKind.Host, chosen[0].LocalKind);
            Assert.True(chosen[0].Priority > 0);
            Assert.False(string.IsNullOrEmpty(chosen[0].Remote));

            // and a restart this end starts checks again under new
            // credentials until a second path is chosen (RFC 8445 §9)
            aliceCall.RestartIce();
            await FirstMatchingAsync(aliceCall.Events, e => e.Kind == SipralEventKind.MediaPathChosen, Timeout);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    /// <summary>This host's own address on whatever interface its
    /// default route uses, or <see langword="null"/> on a machine with
    /// none to find. RFC 8445 Section 5.1.1.1 rules loopback out as a
    /// host candidate, so ICE needs an address that is not
    /// <c>127.0.0.1</c> even though both stacks stay on this one
    /// machine. <see cref="Socket.Connect(string, int)"/> on a UDP
    /// socket asks the kernel to pick a source address for a
    /// destination without ever sending a packet.</summary>
    internal static string? RoutableAddress()
    {
        try
        {
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            probe.Connect("203.0.113.1", 80); // RFC 5737 TEST-NET-3: never dialled
            return ((IPEndPoint)probe.LocalEndPoint!).Address.ToString();
        }
        catch (SocketException)
        {
            return null;
        }
    }
}
