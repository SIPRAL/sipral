// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// <c>turnTransport</c> on <see cref="SipralStack"/>: the relay made over a
/// TCP or TLS connection the stack opens itself, for a network that lets no
/// UDP through to the TURN server (RFC 8656 §3.1) — the .NET counterpart of
/// <c>bindings/python/tests/test_turn_stream.py</c>. The mapping of the
/// media socket is still asked over UDP, of <see cref="NatTests.FakeStunServer"/>:
/// it is the socket's own.
/// </summary>
public sealed class TurnStreamTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
    private const string ServerName = "turn.sipral.test";

    /// <summary>A TURN server on a TCP port of this machine's loopback, over
    /// TLS when given a certificate, and on nothing else: no datagram reaches
    /// it. What arrives is framed as RFC 8656 §12.5 and RFC 8489 §6.2.2 say,
    /// and every request is recorded with the connection it came on,
    /// counting from one; an unauthenticated Allocate gets the 401, a signed
    /// one a relay, and every other signed request its success.</summary>
    private sealed class FakeTurnOverStream : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly (string Username, string Password) _credential;
        private readonly X509Certificate2? _certificate;
        private readonly object _lock = new();
        private readonly List<(int Connection, ushort Method, Dictionary<ushort, byte[]> Attributes)> _requests = new();
        private readonly List<int> _closed = new();
        private int _connections;

        public FakeTurnOverStream((string, string) credential, X509Certificate2? certificate = null)
        {
            _credential = credential;
            _certificate = certificate;
            _listener.Start();
            new Thread(Accept) { IsBackground = true }.Start();
        }

        public string Address => $"127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}";

        public List<int> Allocations
        {
            get
            {
                lock (_lock)
                {
                    return _requests.Where(r => r.Method == 0x0003 && r.Attributes.ContainsKey(0x0006))
                        .Select(r => r.Connection).ToList();
                }
            }
        }

        public List<(int Connection, byte[]? Lifetime)> Refreshes
        {
            get
            {
                lock (_lock)
                {
                    return _requests.Where(r => r.Method == 0x0004 && r.Attributes.ContainsKey(0x0006))
                        .Select(r => (r.Connection, r.Attributes.GetValueOrDefault((ushort)0x000D))).ToList();
                }
            }
        }

        public List<int> Closed
        {
            get
            {
                lock (_lock)
                {
                    return new List<int>(_closed);
                }
            }
        }

        private void Accept()
        {
            while (true)
            {
                TcpClient client;
                try
                {
                    client = _listener.AcceptTcpClient();
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
                {
                    return;
                }
                var number = Interlocked.Increment(ref _connections);
                new Thread(() => Serve(client, number)) { IsBackground = true }.Start();
            }
        }

        private void Serve(TcpClient client, int number)
        {
            Stream stream = client.GetStream();
            try
            {
                if (_certificate is not null)
                {
                    var tls = new SslStream(stream);
                    tls.AuthenticateAsServer(_certificate);
                    stream = tls;
                }
                var held = new List<byte>();
                var buffer = new byte[4096];
                while (true)
                {
                    var read = stream.Read(buffer, 0, buffer.Length);
                    if (read == 0)
                    {
                        break;
                    }
                    held.AddRange(buffer.AsSpan(0, read).ToArray());
                    while (Frame(held) is { } frame)
                    {
                        if (Answer(frame, number) is { } answer)
                        {
                            stream.Write(answer);
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or System.Security.Authentication.AuthenticationException
                                           or ObjectDisposedException)
            {
            }
            lock (_lock)
            {
                _closed.Add(number);
            }
            client.Dispose();
        }

        private static byte[]? Frame(List<byte> held)
        {
            if (held.Count < 4)
            {
                return null;
            }
            var length = (held[2] << 8) | held[3];
            int whole, kept;
            if (held[0] < 4)
            {
                whole = kept = 20 + length;
            }
            else
            {
                kept = 4 + length;
                whole = (kept + 3) / 4 * 4;
            }
            if (held.Count < whole)
            {
                return null;
            }
            var frame = held.GetRange(0, kept).ToArray();
            held.RemoveRange(0, whole);
            return frame;
        }

        private byte[]? Answer(byte[] frame, int number)
        {
            if (frame[0] >= 4)
            {
                return null;
            }
            var type = (ushort)((frame[0] << 8) | frame[1]);
            if ((type & 0x0110) != 0)
            {
                return null;
            }
            var method = (ushort)((type & 0x000F) | ((type & 0x00E0) >> 1) | ((type & 0x3E00) >> 2));
            var attributes = NatTests.FakeStunServer.ParseAttributes(frame);
            lock (_lock)
            {
                _requests.Add((number, method, attributes));
            }
            var transaction = frame[8..20];
            if (!attributes.ContainsKey(0x0006))
            {
                return NatTests.FakeStunServer.BuildMessage((ushort)(type | 0x0110), transaction, new[]
                {
                    ((ushort)0x0009, new byte[] { 0, 0, 4, 1 }.Concat(Encoding.ASCII.GetBytes("Unauthorized")).ToArray()),
                    ((ushort)0x0014, Encoding.ASCII.GetBytes(NatTests.FakeStunServer.Realm)),
                    ((ushort)0x0015, Encoding.ASCII.GetBytes(NatTests.FakeStunServer.Nonce)),
                });
            }
            var key = NatTests.FakeStunServer.LongTermKey(_credential.Username, NatTests.FakeStunServer.Realm, _credential.Password);
            if (!NatTests.FakeStunServer.IntegrityHolds(frame, key))
            {
                return null;
            }
            return method switch
            {
                0x0003 => NatTests.FakeStunServer.Signed(0x0103, transaction, new[]
                {
                    ((ushort)0x0016, NatTests.FakeStunServer.XorAddress("198.51.100.49", (ushort)(50000 + number))),
                    ((ushort)0x0020, NatTests.FakeStunServer.XorAddress("203.0.113.49", (ushort)(41000 + number))),
                    ((ushort)0x000D, new byte[] { 0, 0, 0x02, 0x58 }),
                }, key),
                0x0004 => NatTests.FakeStunServer.Signed((ushort)(type | 0x0100), transaction, new[]
                {
                    ((ushort)0x000D, attributes.GetValueOrDefault((ushort)0x000D) ?? new byte[] { 0, 0, 0x02, 0x58 }),
                }, key),
                _ => NatTests.FakeStunServer.Signed((ushort)(type | 0x0100), transaction,
                    Array.Empty<(ushort, byte[])>(), key),
            };
        }

        public void Dispose() => _listener.Stop();
    }

    /// <summary>A key and a certificate for <see cref="ServerName"/>, made
    /// here, with <c>extendedKeyUsage=serverAuth</c> as every platform's TLS
    /// asks of a server's.</summary>
    private static X509Certificate2 SelfSigned()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={ServerName}", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(ServerName);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, critical: false));
        using var made = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        return new X509Certificate2(made.Export(X509ContentType.Pfx));
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

    private static async Task UntilAsync(Func<bool> done)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (!done() && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }
    }

    /// <summary>Alice behind <paramref name="server"/>, reached as the
    /// arguments say, calls Bob, who answers: what her relay event said,
    /// with the call's media running. The call is closed and forgotten
    /// afterwards with both stacks still running.</summary>
    private static async Task<SipralNatRelayEventInfo> CallThroughAsync(
        string host, NatTests.FakeStunServer stun, FakeTurnOverStream server, SipralTransport transport,
        X509Certificate2Collection? trusted, Func<SipralNatRelayEventInfo, Task> afterward)
    {
        using var alice = new SipralStack(
            audio: SipralAudio.Application,bindHost: host, nat: SipralNat.Stun, ice: SipralIce.Offered, codecs: "PCMU",
            stunServer: stun.Address, turnServer: server.Address,
            turnUsername: "alice-turn", turnPassword: "turn-secret-7",
            turnTransport: transport, turnServerName: ServerName, turnTrustedCertificates: trusted);
        using var bob = new SipralStack(audio: SipralAudio.Application, bindHost: host, codecs: "PCMU");
        var aliceAccount = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);
        var aliceEvents = alice.Events;
        var relayTask = FirstMatchingAsync(aliceEvents, e => e.Kind == SipralEventKind.NatRelay, Timeout);
        var aliceCall = await Task.Run(() => alice.PlaceCall(aliceAccount, $"sip:bob@{bob.BindAddress}", mediaHost: host));
        var relay = (await relayTask).Relay!;
        var incoming = await FirstMatchingAsync(bob.Events, e => e.Kind == SipralEventKind.IncomingCall, Timeout);
        var bobCall = bob.AnswerCall(incoming, mediaHost: host);
        using (var cts = new CancellationTokenSource(Timeout))
        {
            Assert.NotNull(await aliceCall.WaitForMediaAsync(cts.Token));
        }
        aliceCall.Close();
        bobCall.Close();
        await afterward(relay);
        return relay;
    }

    [Fact]
    public async Task ARelayOverTcpIsMadeAndGivenBackOnItsConnection()
    {
        var host = NatTests.RoutableAddress();
        if (host is null)
        {
            return; // no routable address on this machine for ICE to gather a host candidate from
        }
        using var stun = new NatTests.FakeStunServer("203.0.113.47", 40047);
        using var server = new FakeTurnOverStream(("alice-turn", "turn-secret-7"));
        await CallThroughAsync(host, stun, server, SipralTransport.Tcp, null, async relay =>
        {
            Assert.Equal(SipralNatRelay.Allocated, relay.Outcome);
            Assert.True(string.IsNullOrEmpty(relay.Mapped), "the connection's own mapping says nothing about the socket");
            Assert.Equal(new[] { 1 }, server.Allocations);
            Assert.DoesNotContain(stun.SnapshotRequests(), r => r.Method == 0x0003);
            await UntilAsync(() => server.Refreshes.Any(r => r.Lifetime is [0, 0, 0, 0]));
            Assert.Equal(new[] { 1 }, server.Refreshes.Where(r => r.Lifetime is [0, 0, 0, 0]).Select(r => r.Connection));
            await UntilAsync(() => server.Closed.Contains(1));
            Assert.Contains(1, server.Closed);
        });
    }

    [Fact]
    public async Task ARelayOverTlsIsMadeWithTheRootsItWasToldToTrustAndRefusedWithout()
    {
        var host = NatTests.RoutableAddress();
        if (host is null)
        {
            return; // no routable address on this machine for ICE to gather a host candidate from
        }
        using var certificate = SelfSigned();
        using (var stun = new NatTests.FakeStunServer("203.0.113.48", 40048))
        using (var server = new FakeTurnOverStream(("alice-turn", "turn-secret-7"), certificate))
        {
            var roots = new X509Certificate2Collection { new X509Certificate2(certificate.Export(X509ContentType.Cert)) };
            await CallThroughAsync(host, stun, server, SipralTransport.Tls, roots, relay =>
            {
                Assert.Equal(SipralNatRelay.Allocated, relay.Outcome);
                Assert.Equal(new[] { 1 }, server.Allocations);
                return Task.CompletedTask;
            });
        }
        using (var stun = new NatTests.FakeStunServer("203.0.113.48", 40049))
        using (var server = new FakeTurnOverStream(("alice-turn", "turn-secret-7"), certificate))
        {
            await CallThroughAsync(host, stun, server, SipralTransport.Tls, null, relay =>
            {
                Assert.Equal(SipralNatRelay.Failed, relay.Outcome);
                Assert.Contains("connection", relay.Reason ?? string.Empty);
                Assert.Empty(server.Allocations);
                return Task.CompletedTask;
            });
        }
    }
}
