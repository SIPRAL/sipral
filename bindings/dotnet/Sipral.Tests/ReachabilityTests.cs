// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Concurrent;
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
/// Where a stack is reached and where its server is, through
/// <see cref="SipralStack"/>: the address advertised when the application
/// names none, a server named by a URI and located by RFC 3263 — with this
/// layer's own SRV query read against a DNS server on loopback — the
/// account's keep-alive, a certificate trusted by its fingerprint, and the
/// diagnostic trace. The .NET counterpart of
/// <c>bindings/python/tests/test_reachability.py</c>.
/// </summary>
public sealed class ReachabilityTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static string? Header(string name, string message) =>
        message.Split("\r\n")
            .FirstOrDefault(line => line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
            ?.Split(':', 2)[1].Trim();

    /// <summary>A registrar on a loopback UDP port: every REGISTER is
    /// answered 200, and every datagram is kept as text, keep-alives
    /// included.</summary>
    internal sealed class Registrar : IDisposable
    {
        private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly ConcurrentQueue<string> _received = new();
        private readonly Thread _thread;
        private volatile bool _stopped;

        public Registrar()
        {
            _udp.Client.ReceiveTimeout = 50;
            Port = ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;
            _thread = new Thread(Serve) { IsBackground = true };
            _thread.Start();
        }

        public int Port { get; }
        public string Address => $"127.0.0.1:{Port}";
        public List<string> Received => _received.ToList();
        public List<string> Registers => Received.Where(m => m.StartsWith("REGISTER ", StringComparison.Ordinal)).ToList();

        private void Serve()
        {
            while (!_stopped)
            {
                IPEndPoint? from = null;
                byte[] data;
                try
                {
                    data = _udp.Receive(ref from);
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                {
                    continue;
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                {
                    return;
                }
                var message = Encoding.UTF8.GetString(data);
                _received.Enqueue(message);
                if (!message.StartsWith("REGISTER ", StringComparison.Ordinal))
                {
                    continue;
                }
                var lines = new List<string> { "SIP/2.0 200 OK" };
                foreach (var name in new[] { "Via", "From", "To", "Call-ID", "CSeq" })
                {
                    var value = Header(name, message);
                    lines.Add(name == "To" ? $"To: {value};tag=registrar" : $"{name}: {value}");
                }
                lines.Add($"Contact: {Header("Contact", message)};expires=3600");
                lines.Add("Content-Length: 0");
                _udp.Send(Encoding.UTF8.GetBytes(string.Join("\r\n", lines) + "\r\n\r\n"), from!);
            }
        }

        public void Dispose()
        {
            _stopped = true;
            _thread.Join();
            _udp.Dispose();
        }
    }

    /// <summary>A DNS server on a loopback UDP port that answers one SRV
    /// question with one record whose target is written as a compression
    /// pointer back into the question (RFC 1035 §4.1.4), and anything else
    /// with NXDOMAIN.</summary>
    private sealed class DnsServer : IDisposable
    {
        private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly Thread _thread;
        private volatile bool _stopped;

        public DnsServer()
        {
            _udp.Client.ReceiveTimeout = 50;
            EndPoint = (IPEndPoint)_udp.Client.LocalEndPoint!;
            _thread = new Thread(Serve) { IsBackground = true };
            _thread.Start();
        }

        public IPEndPoint EndPoint { get; }

        private void Serve()
        {
            while (!_stopped)
            {
                IPEndPoint? from = null;
                byte[] query;
                try
                {
                    query = _udp.Receive(ref from);
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                {
                    continue;
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                {
                    return;
                }
                var questionEnd = Array.IndexOf(query, (byte)0, 12) + 5;
                var name = Encoding.ASCII.GetString(query, 12, questionEnd - 17);
                var reply = new List<byte>(query[..questionEnd]);
                reply[2] = 0x81;
                reply[3] = 0x80;
                if (name.Contains("_sip") && name.Contains("pbx"))
                {
                    reply[7] = 1;
                    // the answer's name points at the question's, and its
                    // target at the question's "pbx.sipral.test" after the
                    // two leading labels
                    reply.AddRange(new byte[] { 0xC0, 12, 0, 33, 0, 1, 0, 0, 1, 44, 0, 8, 0, 10, 0, 60, 0x13, 0xC4, 0xC0, 12 + 5 + 5 });
                }
                else
                {
                    reply[3] = 0x83;
                }
                _udp.Send(reply.ToArray(), reply.Count, from!);
            }
        }

        public void Dispose()
        {
            _stopped = true;
            _thread.Join();
            _udp.Dispose();
        }
    }

    private static SipralStack Stack(SipralResolver? resolver = null, SipralSrtp srtp = 0) =>
        new(audio: SipralAudio.Application, resolver: resolver, srtp: srtp);

    private static async Task<SipralEventArgs> NextEvent(SipralStack stack, SipralEventKind kind)
    {
        using var cancel = new CancellationTokenSource(Timeout);
        await foreach (var args in stack.Events.WithCancellation(cancel.Token))
        {
            if (args.Kind == kind)
            {
                return args;
            }
        }
        throw new TimeoutException($"no {kind}");
    }

    private static async Task Registered(Account account)
    {
        for (var i = 0; i < 200 && account.RegistrationState() != SipralRegistrationState.Registered; i++)
        {
            await Task.Delay(25);
        }
        Assert.Equal(SipralRegistrationState.Registered, account.RegistrationState());
    }

    private static async Task<bool> Until(Func<bool> what, double seconds = 5)
    {
        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        while (!what() && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }
        return what();
    }

    // -- the address a stack advertises --------------------------------

    [Fact]
    public void TheAddressOfAWildcardSocketIsTheRouteTowardThePeer()
    {
        Assert.Equal("127.0.0.1:5060", SipralStack.AdvertisedAddress("0.0.0.0:5060", "127.0.0.1:5070"));
        var refused = Assert.Throws<SipralException>(() => SipralStack.AdvertisedAddress("127.0.0.1:5060", "192.0.2.1:5060"));
        Assert.Equal(SipralStatus.UnreachableAddress, refused.Status);
        Assert.Equal("127.0.0.1", SipralStack.RouteHost("pbx.example.com:5060"));
    }

    [Fact]
    public async Task AnAccountOnLoopbackRegistersFromLoopback()
    {
        using var registrar = new Registrar();
        using var stack = Stack();
        var account = stack.AddAccount("sip:alice@example.com", registrar.Address, registrar: "sip:example.com");
        account.Register();
        await Registered(account);
        Assert.Contains($"@127.0.0.1:{SipralStack.ParseAddress(stack.BindAddress).Port}", Header("Contact", registrar.Registers[0]));
    }

    [Fact]
    public void AnAccountOnTheNetworkIsReachedAtTheRouteTowardItsServer()
    {
        const string remote = "192.0.2.1:5060";
        var route = SipralStack.RouteHost(remote);
        if (route == "127.0.0.1")
        {
            return;
        }
        using var stack = Stack();
        var account = stack.AddAccount("sip:alice@example.com", remote, registrar: "sip:example.com");
        Assert.Equal($"{route}:{SipralStack.ParseAddress(stack.BindAddress).Port}", account.Advertised);
        Assert.Equal(account.Advertised, stack.BindAddress);
    }

    [Fact]
    public void ALoopbackContactTowardARegistrarElsewhereIsRefusedWithNothingSent()
    {
        using var stack = new SipralStack(bindHost: "127.0.0.1", audio: SipralAudio.Application);
        var account = stack.AddAccount("sip:alice@example.com", "192.0.2.1:5060", registrar: "sip:example.com");
        var refused = Assert.Throws<SipralException>(() => account.Register());
        Assert.Equal(SipralStatus.UnreachableAddress, refused.Status);
        Assert.Equal(5u, (uint)SipralRegistrationFailure.UnreachableContact);
    }

    [Fact]
    public async Task ACallBetweenTwoStacksThatNamedNothingCarriesMediaOnLoopback()
    {
        using var alice = Stack();
        using var bob = Stack();
        var toBob = alice.AddAccount("sip:alice@example.com", bob.BindAddress);
        bob.AddAccount("sip:bob@example.com", alice.BindAddress);
        var call = alice.PlaceCall(toBob, "sip:bob@example.com");
        Assert.StartsWith("127.0.0.1:", call.MediaAddress);
        var answered = bob.AnswerCall(await NextEvent(bob, SipralEventKind.IncomingCall));
        Assert.StartsWith("127.0.0.1:", answered.MediaAddress);
        call.Close();
        answered.Close();
    }

    // -- a server named by a URI -----------------------------------------

    [Fact]
    public async Task AHostWithAPortIsAskedForItsAddressesAndRegisteredWith()
    {
        using var registrar = new Registrar();
        using var stack = Stack();
        var account = stack.AddAccount("sip:alice@example.com", registrar: "sip:example.com",
            serverUri: $"sip:localhost:{registrar.Port}");
        account.Register();
        var located = await NextEvent(stack, SipralEventKind.Located);
        Assert.Contains($"127.0.0.1:{registrar.Port}", located.Locate!.Targets!.Split(','));
        await Registered(account);
        Assert.Single(registrar.Registers);
    }

    [Fact]
    public async Task AnSrvAnswerNamesTheHostAndPortTheRequestsGoTo()
    {
        using var registrar = new Registrar();
        var asked = new ConcurrentQueue<string>();
        using var stack = Stack((name, record) =>
        {
            asked.Enqueue($"{record} {name}");
            return (record, name) switch
            {
                (SipralDnsRecordType.Srv, "_sip._udp.pbx.sipral.test") =>
                    new SipralLookup(SipralDnsAnswer.Records, new[] { $"300 10 60 {registrar.Port} host.sipral.test" }),
                (SipralDnsRecordType.A, "host.sipral.test") =>
                    new SipralLookup(SipralDnsAnswer.Records, new[] { "300 127.0.0.1" }),
                _ => SipralLookup.Nothing,
            };
        });
        var account = stack.AddAccount("sip:alice@pbx.sipral.test", registrar: "sip:pbx.sipral.test",
            serverUri: "sip:pbx.sipral.test");
        account.Register();
        var located = await NextEvent(stack, SipralEventKind.Located);
        Assert.Equal($"127.0.0.1:{registrar.Port}", located.Locate!.Targets!.Split(',')[0]);
        await Registered(account);
        Assert.Equal($"127.0.0.1:{registrar.Port}", account.RegistrarAddress);
        Assert.Contains("Srv _sip._udp.pbx.sipral.test", asked);
    }

    [Fact]
    public async Task ANameWithNoAddressIsALocateFailureThatSaysWhy()
    {
        using var stack = Stack((_, _) => SipralLookup.Nothing);
        var account = stack.AddAccount("sip:alice@example.com", registrar: "sip:example.com",
            serverUri: "sip:nowhere.sipral.test");
        account.Register();
        var failed = await NextEvent(stack, SipralEventKind.LocateFailed);
        Assert.Equal(SipralLocateFailure.NotFound, failed.Locate!.Failure);
        Assert.True(failed.Locate.RetryInMs > 0);
    }

    [Fact]
    public void ThisLayersSrvQueryReadsACompressedAnswerAndANameThatDoesNotExist()
    {
        using var dns = new DnsServer();
        var found = SipralDns.Query("_sip._udp.pbx.sipral.test", SipralDnsRecordType.Srv, new[] { dns.EndPoint });
        Assert.Equal(SipralDnsAnswer.Records, found.Answer);
        Assert.Equal("300 10 60 5060 pbx.sipral.test", Assert.Single(found.Records));
        var missing = SipralDns.Query("_sip._udp.nowhere.sipral.test", SipralDnsRecordType.Srv, new[] { dns.EndPoint });
        Assert.Equal(SipralDnsAnswer.Nothing, missing.Answer);
    }

    [Fact]
    public void ThePlatformLookupFindsLocalhost()
    {
        var found = SipralDns.Addresses("localhost", AddressFamily.InterNetwork);
        Assert.Equal(SipralDnsAnswer.Records, found.Answer);
        Assert.Contains("60 127.0.0.1", found.Records);
    }

    [Fact]
    public void ExactlyOneOfTheTwoNamesTheServer()
    {
        using var stack = Stack();
        Assert.Throws<ArgumentException>(() => stack.AddAccount("sip:alice@example.com"));
        Assert.Throws<ArgumentException>(
            () => stack.AddAccount("sip:alice@example.com", "127.0.0.1:5060", serverUri: "sip:a.test"));
    }

    // -- the account's keep-alive --------------------------------------------

    [Fact]
    public async Task ADoubleCrlfGoesToTheRegistrarAtTheInterval()
    {
        using var registrar = new Registrar();
        using var stack = Stack();
        var account = stack.AddAccount("sip:alice@example.com", registrar.Address, registrar: "sip:example.com",
            keepaliveMs: 1000);
        account.Register();
        await Registered(account);
        Assert.True(await Until(() => registrar.Received.Contains("\r\n\r\n"), 3));
    }

    [Fact]
    public void AnIntervalUnderASecondIsRefused()
    {
        using var stack = Stack();
        var refused = Assert.Throws<SipralException>(
            () => stack.AddAccount("sip:alice@example.com", "127.0.0.1:5060", keepaliveMs: 999));
        Assert.Equal(SipralStatus.InvalidArgument, refused.Status);
    }

    // -- a certificate trusted by its fingerprint -------------------------

    [Fact]
    public void TheAccountsPinDecidesOnTheCertificateAServerPresented()
    {
        var certificate = Encoding.UTF8.GetBytes("the DER bytes of a leaf");
        var pin = "SHA256=" + string.Join(":", SHA256.HashData(certificate).Select(b => b.ToString("X2")));
        using var stack = Stack();
        var pinned = stack.AddAccount("sip:alice@example.com", "127.0.0.1:5060", tlsPin: pin);
        var verdict = pinned.CheckCertificate(certificate);
        Assert.NotNull(verdict);
        Assert.False(verdict!.Expired);
        var refused = Assert.Throws<SipralException>(
            () => pinned.CheckCertificate(Encoding.UTF8.GetBytes("another certificate")));
        Assert.Equal(SipralStatus.CertificateRefused, refused.Status);
        var unpinned = stack.AddAccount("sip:bob@example.com", "127.0.0.1:5060");
        Assert.Null(unpinned.CheckCertificate(certificate));
        Assert.Throws<SipralException>(() => stack.AddAccount("sip:carol@example.com", "127.0.0.1:5060", tlsPin: "00"));
    }

    // -- the stack's new options -------------------------------------------

    [Fact]
    public void ASuiteTheLibraryDoesNotRunAndAShortSaltAreRefused()
    {
        var suite = Assert.Throws<SipralException>(
            () => new SipralStack(audio: SipralAudio.Application, srtpSuites: new[] { "NOT_A_SUITE" }));
        Assert.Equal(SipralStatus.InvalidArgument, suite.Status);
        var salt = Assert.Throws<SipralException>(
            () => new SipralStack(audio: SipralAudio.Application, pseudonymSalt: Encoding.UTF8.GetBytes("short")));
        Assert.Equal(SipralStatus.InvalidArgument, salt.Status);
        using var stack = new SipralStack(audio: SipralAudio.Application, srtp: SipralSrtp.BestEffort,
            srtpSuites: new[] { "AES_CM_128_HMAC_SHA1_80" }, pseudonymSalt: Enumerable.Range(0, 16).Select(i => (byte)i).ToArray());
    }

    [Fact]
    public async Task TheTraceWritesWholeMessagesOnlyWhileTheDiagnosticTraceIsOn()
    {
        using var registrar = new Registrar();
        using var stack = Stack();
        var written = new ConcurrentQueue<string>();
        stack.SetLog(SipralLogLevel.Trace, (_, _, message, _) => written.Enqueue(message));
        var account = stack.AddAccount("sip:alice@example.com", registrar.Address, registrar: "sip:example.com");
        account.Register();
        await Registered(account);
        bool Whole() => written.Any(line => line.Contains("sip:alice@example.com"));
        Assert.False(Whole(), "pseudonymised");
        stack.SetDiagnosticTrace(true);
        account.Register();
        Assert.True(await Until(Whole), "a whole REGISTER, the AOR as it went on the wire");
    }

    [Fact]
    public async Task BestEffortOffersKeysOnPlainRtp()
    {
        using var alice = Stack(srtp: SipralSrtp.BestEffort);
        using var bob = Stack();
        var toBob = alice.AddAccount("sip:alice@example.com", bob.BindAddress);
        bob.AddAccount("sip:bob@example.com", alice.BindAddress);
        var call = alice.PlaceCall(toBob, "sip:bob@example.com");
        var incoming = await NextEvent(bob, SipralEventKind.IncomingCall);
        var offer = Encoding.UTF8.GetString(incoming.Message ?? Array.Empty<byte>());
        Assert.Contains("RTP/AVP", offer);
        Assert.DoesNotContain("RTP/SAVP", offer);
        Assert.Contains("a=crypto:", offer);
        call.Close();
    }
}
