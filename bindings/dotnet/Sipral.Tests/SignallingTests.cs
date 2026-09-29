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
/// SIP over TCP and TLS through <see cref="SipralStack"/>'s
/// <c>signalling</c> — the .NET counterpart of
/// <c>bindings/python/tests/test_signalling.py</c>. The registrar is this
/// test's own, on loopback, and its certificates are made here, one of them
/// expired before the run began: a stack registers over the one connection
/// it opened; a certificate refused for each reason
/// <see cref="SipralTlsFailure"/> names arrives as
/// <see cref="SipralEventKind.TransportFailed"/> carrying that reason; a
/// registrar that closes the connection is connected to again and the
/// account registers again on the new one; and the INVITE rate floor's
/// voice-agent preset lets through a burst the default answers 480.
/// </summary>
public sealed class SignallingTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
    private const string ServerName = "registrar.sipral.test";

    private static string? Header(string name, string message) =>
        message.Split("\r\n")
            .FirstOrDefault(line => line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
            ?.Split(':', 2)[1].Trim();

    private static X509Certificate2 Certificate(DateTimeOffset from, DateTimeOffset until)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={ServerName}", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(ServerName);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, critical: false));
        using var made = request.CreateSelfSigned(from, until);
        return new X509Certificate2(made.Export(X509ContentType.Pfx));
    }

    private static X509Certificate2 Good() => Certificate(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));

    /// <summary>A registrar on a TCP port of this machine's loopback, over
    /// TLS when given a certificate, answering every REGISTER 200, or one
    /// that answers a TLS client in plain text.</summary>
    private sealed class Registrar : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly X509Certificate2? _certificate;
        private readonly bool _plainToTls;
        private readonly object _lock = new();
        private readonly List<(int Connection, string Message)> _requests = new();
        private readonly List<TcpClient> _open = new();
        private int _connections;

        public Registrar(X509Certificate2? certificate = null, bool plainToTls = false)
        {
            _certificate = certificate;
            _plainToTls = plainToTls;
            _listener.Start();
            new Thread(Accept) { IsBackground = true }.Start();
        }

        public string Address => $"127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}";

        public List<(int Connection, string Message)> Registers()
        {
            lock (_lock)
            {
                return _requests.Where(r => r.Message.StartsWith("REGISTER ", StringComparison.Ordinal)).ToList();
            }
        }

        /// <summary>Closes every connection from this end, the way a
        /// registrar that restarted does.</summary>
        public void Drop()
        {
            List<TcpClient> open;
            lock (_lock)
            {
                open = new List<TcpClient>(_open);
                _open.Clear();
            }
            foreach (var client in open)
            {
                client.Dispose();
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
                if (_plainToTls)
                {
                    stream.Read(new byte[4096], 0, 4096);
                    stream.Write(Encoding.UTF8.GetBytes("SIP/2.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n"));
                    client.Dispose();
                    return;
                }
                if (_certificate is not null)
                {
                    var tls = new SslStream(stream);
                    tls.AuthenticateAsServer(_certificate);
                    stream = tls;
                }
                lock (_lock)
                {
                    _open.Add(client);
                }
                var held = string.Empty;
                var buffer = new byte[65536];
                while (true)
                {
                    var read = stream.Read(buffer, 0, buffer.Length);
                    if (read == 0)
                    {
                        break;
                    }
                    held += Encoding.UTF8.GetString(buffer, 0, read);
                    while (held.IndexOf("\r\n\r\n", StringComparison.Ordinal) is var end and >= 0)
                    {
                        var head = held[..end];
                        var length = int.Parse(Header("Content-Length", head) ?? "0");
                        if (held.Length < end + 4 + length)
                        {
                            break;
                        }
                        var message = held[..(end + 4 + length)];
                        held = held[(end + 4 + length)..];
                        lock (_lock)
                        {
                            _requests.Add((number, message));
                        }
                        if (message.StartsWith("REGISTER ", StringComparison.Ordinal))
                        {
                            stream.Write(Encoding.UTF8.GetBytes(Ok(message)));
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or System.Security.Authentication.AuthenticationException
                                           or ObjectDisposedException or InvalidOperationException)
            {
            }
            client.Dispose();
        }

        private static string Ok(string request)
        {
            var lines = new List<string> { "SIP/2.0 200 OK" };
            foreach (var name in new[] { "Via", "From", "To", "Call-ID", "CSeq" })
            {
                var value = Header(name, request);
                lines.Add(name == "To" ? $"To: {value};tag=registrar" : $"{name}: {value}");
            }
            lines.Add($"Contact: {Header("Contact", request)};expires=3600");
            lines.Add("Content-Length: 0");
            return string.Join("\r\n", lines) + "\r\n\r\n";
        }

        public void Dispose()
        {
            _listener.Stop();
            Drop();
        }
    }

    private static async Task<SipralEventArgs> NextEvent(SipralStack stack, SipralEventKind kind, TimeSpan? within = null)
    {
        using var cancel = new CancellationTokenSource(within ?? Timeout);
        await foreach (var args in stack.Events.WithCancellation(cancel.Token))
        {
            if (args.Kind == kind)
            {
                return args;
            }
        }
        throw new TimeoutException($"no {kind}");
    }

    private static async Task Registered(SipralStack stack)
    {
        while (true)
        {
            var args = await NextEvent(stack, SipralEventKind.RegistrationChanged);
            if (args.Registration?.State == SipralRegistrationState.Registered)
            {
                return;
            }
        }
    }

    private static SipralStack Over(string server, SipralTransport signalling = SipralTransport.Tls,
        string? name = ServerName, SipralTlsTrust? trust = null) =>
        new(audio: SipralAudio.Application, signalling: signalling, signallingServer: server,
            tlsServerName: name, tlsTrust: trust);

    [Fact]
    public async Task ARegistrarWhoseAuthorityIsPinnedRegistersTheAccountOverTls()
    {
        using var certificate = Good();
        using var registrar = new Registrar(certificate);
        using var stack = Over(registrar.Address, trust: SipralTlsTrust.OnlyAuthority(certificate));
        Assert.True(stack.Connected);
        var account = stack.AddAccount($"sip:alice@{ServerName}", registrar.Address, registrar: $"sip:{ServerName}");
        account.Register();
        await Registered(stack);
        var (connection, register) = Assert.Single(registrar.Registers());
        Assert.Equal(1, connection);
        Assert.StartsWith("SIP/2.0/TLS ", Header("Via", register));
        Assert.Contains(";transport=tls", Header("Contact", register));
        Assert.Contains(stack.BindAddress, Header("Contact", register));
    }

    /// <summary>A certificate a private authority signed, trusted with that
    /// authority as the only one: no revocation list is published for it,
    /// and none is asked for, as <see cref="SslStream"/> asks for none by
    /// default.</summary>
    [Fact]
    public async Task ACertificateAPinnedAuthoritySignedIsTrustedWithNoRevocationListToAsk()
    {
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var authorityRequest = new CertificateRequest("CN=Sipral test authority", authorityKey, HashAlgorithmName.SHA256);
        authorityRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        authorityRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        // one instant for both: a leaf may not outlive its issuer, and a
        // second clock read can land past the authority's own end
        var now = DateTimeOffset.UtcNow;
        using var authority = authorityRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(1));
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest($"CN={ServerName}", leafKey, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(ServerName);
        leafRequest.CertificateExtensions.Add(names.Build());
        leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, critical: false));
        using var signed = leafRequest.Create(authority, now.AddMinutes(-5), now.AddDays(1),
            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        using var withKey = signed.CopyWithPrivateKey(leafKey);
        using var leaf = new X509Certificate2(withKey.Export(X509ContentType.Pfx));
        using var trusted = new X509Certificate2(authority.Export(X509ContentType.Cert));
        using var registrar = new Registrar(leaf);
        using var stack = Over(registrar.Address, trust: SipralTlsTrust.OnlyAuthority(trusted));
        Assert.True(stack.Connected);
        var account = stack.AddAccount($"sip:alice@{ServerName}", registrar.Address, registrar: $"sip:{ServerName}");
        account.Register();
        await Registered(stack);
    }

    private static async Task<SipralTransportFailedEventInfo> Refused(SipralStack stack)
    {
        var args = await NextEvent(stack, SipralEventKind.TransportFailed);
        Assert.False(stack.Connected);
        var failed = Assert.IsType<SipralTransportFailedEventInfo>(args.TransportFailed);
        Assert.Equal(SipralTransport.Tls, failed.Protocol);
        return failed;
    }

    [Fact]
    public async Task ACertificateNoTrustedAuthoritySignedIsUntrusted()
    {
        using var certificate = Good();
        using var registrar = new Registrar(certificate);
        using var stack = Over(registrar.Address);
        var failed = await Refused(stack);
        Assert.Equal(SipralTlsFailure.Untrusted, failed.Tls);
        Assert.False(string.IsNullOrEmpty(failed.Detail));
        var account = stack.AddAccount($"sip:alice@{ServerName}", registrar.Address, registrar: $"sip:{ServerName}");
        account.Register();
        Assert.True(account.WantsRegistration);
        Assert.Empty(registrar.Registers());
    }

    [Fact]
    public async Task ACertificateForAnotherNameIsANameMismatch()
    {
        using var certificate = Good();
        using var registrar = new Registrar(certificate);
        using var stack = Over(registrar.Address, name: "other.sipral.test",
            trust: SipralTlsTrust.OnlyAuthority(certificate));
        Assert.Equal(SipralTlsFailure.NameMismatch, (await Refused(stack)).Tls);
    }

    /// <summary>With a private authority beside the platform's, a certificate
    /// it signed registers, and one it signed for another name is a name
    /// mismatch: the platform's own chain error does not hide the name.</summary>
    [Fact]
    public async Task APrivateAuthorityBesideThePlatformsTrustsItsOwnAndStillChecksTheName()
    {
        using var certificate = Good();
        using (var registrar = new Registrar(certificate))
        using (var stack = Over(registrar.Address, trust: SipralTlsTrust.PrivateAuthority(certificate)))
        {
            Assert.True(stack.Connected);
            var account = stack.AddAccount($"sip:alice@{ServerName}", registrar.Address, registrar: $"sip:{ServerName}");
            account.Register();
            await Registered(stack);
        }
        using (var registrar = new Registrar(certificate))
        using (var stack = Over(registrar.Address, name: "other.sipral.test",
            trust: SipralTlsTrust.PrivateAuthority(certificate)))
        {
            Assert.Equal(SipralTlsFailure.NameMismatch, (await Refused(stack)).Tls);
        }
    }

    [Fact]
    public async Task AnExpiredCertificateIsExpired()
    {
        using var certificate = Certificate(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2020, 1, 2, 0, 0, 0, TimeSpan.Zero));
        using var registrar = new Registrar(certificate);
        using var stack = Over(registrar.Address, trust: SipralTlsTrust.OnlyAuthority(certificate));
        Assert.Equal(SipralTlsFailure.Expired, (await Refused(stack)).Tls);
    }

    [Fact]
    public async Task AServerThatDoesNotSpeakTlsRefusesTheHandshake()
    {
        using var registrar = new Registrar(plainToTls: true);
        using var stack = Over(registrar.Address);
        Assert.Equal(SipralTlsFailure.HandshakeRefused, (await Refused(stack)).Tls);
    }

    [Fact]
    public async Task NobodyListeningIsARefusedConnectionAndNoTlsReason()
    {
        var nobody = new TcpListener(IPAddress.Loopback, 0);
        nobody.Start();
        var address = $"127.0.0.1:{((IPEndPoint)nobody.LocalEndpoint).Port}";
        nobody.Stop();
        using var stack = Over(address);
        var failed = await Refused(stack);
        Assert.Equal(SipralTransportError.ConnectionRefused, failed.Error);
        Assert.Equal(SipralTlsFailure.None, failed.Tls);
    }

    [Fact]
    public async Task TheAccountRegistersAgainOnTheNewConnection()
    {
        using var registrar = new Registrar();
        using var stack = Over(registrar.Address, SipralTransport.Tcp, name: null);
        var account = stack.AddAccount("sip:alice@sipral.invalid", registrar.Address, registrar: "sip:sipral.invalid");
        account.Register();
        await Registered(stack);
        var first = stack.BindAddress;

        registrar.Drop();
        var lost = await NextEvent(stack, SipralEventKind.TransportFailed);
        Assert.Equal(SipralTransportError.Closed, lost.TransportFailed!.Error);
        Assert.Equal(SipralTransport.Tcp, lost.TransportFailed.Protocol);
        var deadline = DateTime.UtcNow + Timeout;
        while (!registrar.Registers().Any(r => r.Connection == 2) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(50);
        }
        var again = registrar.Registers().Where(r => r.Connection == 2).Select(r => r.Message).FirstOrDefault();
        Assert.NotNull(again);
        Assert.NotEqual(first, stack.BindAddress);
        Assert.Contains(stack.BindAddress, Header("Contact", again!));
        Assert.Contains(";transport=tcp", Header("Contact", again!));
    }

    /// <summary>Twenty INVITEs from one address at once: how many were
    /// answered 480, each counted once however often its refusal is sent
    /// again for want of an ACK.</summary>
    private static async Task<int> Rush(SipralInviteLimit? limit)
    {
        using var stack = new SipralStack(audio: SipralAudio.Application, inviteLimit: limit);
        stack.AddAccount("sip:bob@sipral.invalid", "127.0.0.1:9");
        using var caller = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var here = $"127.0.0.1:{((IPEndPoint)caller.Client.LocalEndPoint!).Port}";
        var (host, port) = SipralStack.ParseAddress(stack.BindAddress);
        for (var n = 0; n < 20; n++)
        {
            var invite =
                $"INVITE sip:bob@{stack.BindAddress} SIP/2.0\r\n" +
                $"Via: SIP/2.0/UDP {here};branch=z9hG4bK-rush-{n}\r\n" +
                "Max-Forwards: 70\r\n" +
                $"From: <sip:trunk@{here}>;tag=rush{n}\r\n" +
                $"To: <sip:bob@{stack.BindAddress}>\r\n" +
                $"Call-ID: rush-{n}@trunk\r\n" +
                "CSeq: 1 INVITE\r\n" +
                $"Contact: <sip:trunk@{here}>\r\n" +
                "Content-Length: 0\r\n\r\n";
            var bytes = Encoding.UTF8.GetBytes(invite);
            caller.Send(bytes, bytes.Length, new IPEndPoint(IPAddress.Parse(host), port));
        }
        var refused = new HashSet<string>();
        var until = DateTime.UtcNow + TimeSpan.FromSeconds(2);
        while (DateTime.UtcNow < until)
        {
            using var wait = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            try
            {
                var got = await caller.ReceiveAsync(wait.Token);
                var text = Encoding.UTF8.GetString(got.Buffer);
                if (text.StartsWith("SIP/2.0 480 ", StringComparison.Ordinal))
                {
                    refused.Add(Header("Call-ID", text) ?? string.Empty);
                }
            }
            catch (OperationCanceledException)
            {
            }
        }
        return refused.Count;
    }

    [Fact]
    public async Task TheDefaultAnswersARush480AndTheVoiceAgentPresetTakesIt()
    {
        Assert.Equal(10, await Rush(null));
        Assert.Equal(0, await Rush(SipralInviteLimit.VoiceAgent));
        Assert.Equal(new SipralInviteLimit(10, 2000), SipralInviteLimit.Default);
        Assert.Equal(128u, SipralInviteLimit.VoiceAgent.Burst);
    }
}
