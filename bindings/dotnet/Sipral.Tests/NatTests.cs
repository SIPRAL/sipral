// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
/// STUN, TURN and ICE through <see cref="SipralStack"/>, against a fake
/// RFC 5389 §15.2 responder.
/// </summary>
public sealed class NatTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(8);

    /// <summary>Answers every STUN Binding request with the same made-up
    /// public address.
    ///
    /// Without <paramref name="credential"/>, other messages (a TURN
    /// Allocate) are recorded in <see cref="OtherRequests"/> and never
    /// answered. With one, it also acts as TURN: an unsigned Allocate gets
    /// 401 with REALM and NONCE (RFC 8656 §7), a signed one a relay on
    /// <see cref="RelayHost"/>. Every request, Refreshes included, is
    /// recorded in <see cref="Requests"/>.</summary>
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
                    Answer(response, from);
                    continue;
                }
                if (method == AllocateRequest && _credential is not null)
                {
                    var answer = AnswerAllocate(data, transactionId, attributes, (IPEndPoint)from);
                    if (answer is not null)
                    {
                        Answer(answer, from);
                    }
                    continue;
                }
                lock (_lock)
                {
                    OtherRequests.Add(data);
                }
            }
        }

        // On this server's own thread: an exception here would end the test
        // process, not the test. A peer whose address went away -- the
        // interface lost it, EADDRNOTAVAIL -- gets no answer, and the test
        // waiting for one fails on its own.
        private void Answer(byte[] reply, EndPoint to)
        {
            try
            {
                _socket.SendTo(reply, to);
            }
            catch (SocketException)
            {
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

    /// <summary>A silent first STUN server is replaced by the next after
    /// 5.5 s, reported by <see cref="SipralEventKind.StunServer"/>.</summary>
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

    /// <summary>Behind a NAT, a lone double CRLF reaches the registrar
    /// every <c>registrarKeepaliveMs</c>, and none with the keep-alive
    /// off.</summary>
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
    /// without STUN maps at once, later calls offer the mapped address, and
    /// a non-address entry is refused.</summary>
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
            // the SDP fields are only set on SessionChanged; read the offer
            // from the raw INVITE
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

        // This fake never answers the Allocate, so no call could be placed;
        // MapMediaSocket is driven directly to prove the Allocate left.
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

    /// <summary>An ended call gives its TURN relay back: the zero-lifetime
    /// Refresh goes to the destination the farewell names (the TURN server),
    /// not to the far end's media address. A peer without ICE is enough,
    /// since the relay is allocated and released either way.</summary>
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
        // PCMU only: three candidates plus every codec would pass 1300
        // bytes (RFC 3261 §18.1.1), with no stream to fall back to here
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

            // the relay must belong to the call before it can be given back
            using var cts = new CancellationTokenSource(Timeout);
            Assert.NotNull(await aliceCall.WaitForMediaAsync(cts.Token));

            // Dispose, not Call.Close: closing here would race the poll
            // thread's drain of the farewell
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

            // MediaPathChosen, not MediaFailed: ICE actually ran
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

            // a restart checks again under new credentials (RFC 8445 §9)
            aliceCall.RestartIce();
            await FirstMatchingAsync(aliceCall.Events, e => e.Kind == SipralEventKind.MediaPathChosen, Timeout);
        }
        finally
        {
            aliceCall.Close();
            bobCall.Close();
        }
    }

    /// <summary>This host's address on its default route, or
    /// <see langword="null"/>. ICE excludes loopback candidates (RFC 8445
    /// §5.1.1.1), so even two local stacks need a real address.
    ///
    /// A connected socket's local address is the route's, but on macOS
    /// under load about one connect in a thousand reports 0.0.0.0 instead
    /// (the library's own route lookup asks again for the same reason): a
    /// stack bound there offers ICE nothing usable and the call is refused.
    /// That answer is no answer, and the route is asked again.</summary>
    internal static string? RoutableAddress()
    {
        for (var attempt = 0; attempt < 20; attempt++)
        {
            try
            {
                using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                probe.Connect("203.0.113.1", 80); // RFC 5737 TEST-NET-3: never dialled
                var local = ((IPEndPoint)probe.LocalEndPoint!).Address;
                if (!local.Equals(IPAddress.Any))
                {
                    return local.ToString();
                }
            }
            catch (SocketException)
            {
                return null;
            }
        }
        return null;
    }
}
