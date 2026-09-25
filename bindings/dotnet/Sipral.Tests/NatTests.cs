// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
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

    private sealed class FakeStunServer : IDisposable
    {
        private const ushort BindingRequest = 0x0001;
        private const ushort BindingSuccess = 0x0101;
        private const ushort XorMappedAddress = 0x0020;
        private const uint MagicCookie = 0x2112A442;

        private readonly Socket _socket;
        private readonly CancellationTokenSource _stop = new();
        private readonly Thread _thread;
        public readonly string PublicHost;
        public readonly ushort PublicPort;
        public string Address { get; }
        public List<byte[]> OtherRequests { get; } = new();
        private readonly object _lock = new();

        public FakeStunServer(string publicHost, ushort publicPort)
        {
            PublicHost = publicHost;
            PublicPort = publicPort;
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
                var msgType = (ushort)((buffer[0] << 8) | buffer[1]);
                var transactionId = new byte[12];
                Array.Copy(buffer, 8, transactionId, 0, 12);
                if (msgType == BindingRequest)
                {
                    var response = BuildResponse(transactionId, PublicHost, PublicPort);
                    _socket.SendTo(response, from);
                }
                else
                {
                    var copy = new byte[count];
                    Array.Copy(buffer, copy, count);
                    lock (_lock)
                    {
                        OtherRequests.Add(copy);
                    }
                }
            }
        }

        private static byte[] BuildResponse(byte[] transactionId, string host, ushort port)
        {
            var cookie = BitConverter.GetBytes(MagicCookie);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(cookie);
            }
            var ipBytes = IPAddress.Parse(host).GetAddressBytes();
            var xport = (ushort)(port ^ (MagicCookie >> 16));
            var xaddr = new byte[4];
            for (var i = 0; i < 4; i++)
            {
                xaddr[i] = (byte)(ipBytes[i] ^ cookie[i]);
            }
            var attrValue = new byte[8];
            attrValue[0] = 0;
            attrValue[1] = 0x01;
            attrValue[2] = (byte)(xport >> 8);
            attrValue[3] = (byte)xport;
            Array.Copy(xaddr, 0, attrValue, 4, 4);

            var body = new byte[4 + attrValue.Length];
            body[0] = (byte)(XorMappedAddress >> 8);
            body[1] = (byte)XorMappedAddress;
            body[2] = (byte)(attrValue.Length >> 8);
            body[3] = (byte)attrValue.Length;
            Array.Copy(attrValue, 0, body, 4, attrValue.Length);

            var header = new byte[20];
            header[0] = (byte)(BindingSuccess >> 8);
            header[1] = unchecked((byte)BindingSuccess);
            header[2] = (byte)(body.Length >> 8);
            header[3] = (byte)body.Length;
            Array.Copy(cookie, 0, header, 4, 4);
            Array.Copy(transactionId, 0, header, 8, 12);

            var message = new byte[header.Length + body.Length];
            Array.Copy(header, message, header.Length);
            Array.Copy(body, 0, message, header.Length, body.Length);
            return message;
        }

        public List<byte[]> SnapshotOtherRequests()
        {
            lock (_lock)
            {
                return new List<byte[]>(OtherRequests);
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
        using var alice = new SipralStack(nat: SipralNat.Stun, stunServer: server.Address);

        var evt = await FirstMatchingAsync(alice.Events, e => e.Kind == SipralEventKind.NatMapping, Timeout);
        Assert.NotNull(evt.Nat);
        Assert.True(evt.Nat!.Signalling);
        Assert.Equal("203.0.113.7:40000", evt.Nat.Mapped);
    }

    [Fact]
    public async Task CallOffersTheMappedMediaAddress()
    {
        using var server = new FakeStunServer("203.0.113.7", 40000);
        using var alice = new SipralStack(nat: SipralNat.Stun, stunServer: server.Address);
        using var bob = new SipralStack();

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
            nat: SipralNat.Stun, stunServer: server.Address,
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

    [Fact]
    public async Task TwoStacksTalkThroughIceOnARoutableAddress()
    {
        var host = RoutableAddress();
        if (host is null)
        {
            return; // no routable address on this machine to gather a host candidate from
        }

        using var alice = new SipralStack(bindHost: host, ice: SipralIce.Required);
        using var bob = new SipralStack(bindHost: host, ice: SipralIce.Required);

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
    private static string? RoutableAddress()
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
