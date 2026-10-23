// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// A client certificate on SIP over TLS (<c>docs/22-tls.md</c>, "A client
/// certificate"), against a registrar whose TLS is OpenSSL's own
/// <c>s_server</c> requiring one: the TLS library PBXs run, so the alerts
/// the layer reads are the ones a PBX sends, which an in-process
/// <c>SslStream</c> server on macOS never sends. Every certificate is made
/// here, for the run.
/// </summary>
public sealed class ClientCertificateTests : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);
    private const string ServerName = SignallingTests.ServerName;
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    private readonly string _directory = Directory.CreateTempSubdirectory("sipral-client-cert-").FullName;
    private readonly Issuer _authority = new("Sipral test client authority");
    private readonly Issuer _stranger = new("Sipral test stranger authority");

    public void Dispose()
    {
        _authority.Dispose();
        _stranger.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    /// <summary>A certificate authority made for the run.</summary>
    private sealed class Issuer : IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public Issuer(string name)
        {
            var request = new CertificateRequest($"CN={name}", _key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            Certificate = request.CreateSelfSigned(Now.AddDays(-30), Now.AddDays(30));
        }

        public X509Certificate2 Certificate { get; }

        /// <summary>A leaf it signs: the certificate with its key, and both as
        /// PEM text.</summary>
        public (X509Certificate2 WithKey, string CertificatePem, string KeyPem) Issue(
            string name, string usage, DateTimeOffset from, DateTimeOffset until)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName(name);
            request.CertificateExtensions.Add(names.Build());
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(usage) }, critical: false));
            using var signed = request.Create(Certificate, from, until, RandomNumberGenerator.GetBytes(8));
            using var paired = signed.CopyWithPrivateKey(key);
            return (X509CertificateLoader.LoadPkcs12(paired.Export(X509ContentType.Pfx), null),
                signed.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem());
        }

        public void Dispose()
        {
            Certificate.Dispose();
            _key.Dispose();
        }
    }

    private const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuth = "1.3.6.1.5.5.7.3.2";

    private (X509Certificate2 WithKey, string CertificatePem, string KeyPem) Client(Issuer issuer, string name) =>
        issuer.Issue(name, ClientAuth, Now.AddMinutes(-5), Now.AddDays(1));

    private string Write(string name, string text)
    {
        var path = Path.Combine(_directory, name);
        File.WriteAllText(path, text);
        return path;
    }

    /// <summary>
    /// A registrar behind <c>openssl s_server</c>, which requires a client
    /// certificate the test authority signed (<c>-Verify 1
    /// -verify_return_error</c>) and relays the plain text: each REGISTER it
    /// prints is answered 200 on its input.
    /// </summary>
    private sealed class OpensslRegistrar : IDisposable
    {
        private readonly Process _server;
        private readonly StringBuilder _said = new();
        private readonly object _lock = new();
        private readonly List<string> _registers = new();

        public OpensslRegistrar(ClientCertificateTests test, params string[] extra)
        {
            var (certificatePem, keyPem) = (test._serverCertificatePem, test._serverKeyPem);
            var openssl = Openssl();
            var libre = Run(openssl, "version").StartsWith("LibreSSL", StringComparison.Ordinal);
            for (var attempt = 0; ; attempt++)
            {
                Port = FreePort();
                var arguments = new List<string>
                {
                    "s_server", "-accept", libre ? $"{Port}" : $"127.0.0.1:{Port}",
                    "-cert", test.Write("server.pem", certificatePem), "-key", test.Write("server.key", keyPem),
                    "-CAfile", test.Write("authority.pem", test._authority.Certificate.ExportCertificatePem()),
                    "-Verify", "1", "-verify_return_error", "-quiet",
                };
                arguments.AddRange(extra);
                var start = new ProcessStartInfo(openssl)
                {
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                arguments.ForEach(start.ArgumentList.Add);
                _server = Process.Start(start)!;
                new Thread(ReadErrors) { IsBackground = true }.Start();
                new Thread(Relay) { IsBackground = true }.Start();
                if (Listening())
                {
                    return;
                }
                Stop();
                if (attempt == 2)
                {
                    throw new InvalidOperationException($"openssl s_server never listened: {Said}");
                }
            }
        }

        public int Port { get; private set; }

        public string Address => $"127.0.0.1:{Port}";

        /// <summary>What s_server wrote about its connections.</summary>
        public string Said
        {
            get
            {
                lock (_lock)
                {
                    return _said.ToString();
                }
            }
        }

        public List<string> Registers()
        {
            lock (_lock)
            {
                return _registers.ToList();
            }
        }

        // Taken when a socket of our own can no longer bind its port.
        private bool Listening()
        {
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
            while (DateTime.UtcNow < deadline && !_server.HasExited)
            {
                using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    probe.Bind(new IPEndPoint(IPAddress.Loopback, Port));
                }
                catch (SocketException)
                {
                    return true;
                }
                probe.Close();
                Thread.Sleep(50);
            }
            return false;
        }

        private void ReadErrors()
        {
            try
            {
                while (_server.StandardError.ReadLine() is { } line)
                {
                    lock (_lock)
                    {
                        _said.AppendLine(line);
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
            {
            }
        }

        private void Relay()
        {
            var held = string.Empty;
            var buffer = new byte[65536];
            try
            {
                var output = _server.StandardOutput.BaseStream;
                int read;
                while ((read = output.Read(buffer, 0, buffer.Length)) > 0)
                {
                    held += Encoding.UTF8.GetString(buffer, 0, read);
                    while (held.IndexOf("\r\n\r\n", StringComparison.Ordinal) is var end and >= 0)
                    {
                        var message = held[..(end + 4)];
                        held = held[(end + 4)..];
                        if (!message.StartsWith("REGISTER ", StringComparison.Ordinal))
                        {
                            continue;
                        }
                        lock (_lock)
                        {
                            _registers.Add(message);
                        }
                        var answer = Encoding.UTF8.GetBytes(SignallingTests.Registrar.Ok(message));
                        _server.StandardInput.BaseStream.Write(answer);
                        _server.StandardInput.BaseStream.Flush();
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
            {
            }
        }

        private void Stop()
        {
            try
            {
                _server.Kill();
                _server.WaitForExit(5000);
            }
            catch (InvalidOperationException)
            {
            }
            _server.Dispose();
        }

        public void Dispose() => Stop();
    }

    private readonly string _serverCertificatePem;
    private readonly string _serverKeyPem;

    public ClientCertificateTests()
    {
        var (server, certificatePem, keyPem) =
            _authority.Issue(ServerName, ServerAuth, Now.AddMinutes(-5), Now.AddDays(1));
        server.Dispose();
        (_serverCertificatePem, _serverKeyPem) = (certificatePem, keyPem);
    }

    private static string Openssl()
    {
        var found = new[] { "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl" }
            .FirstOrDefault(File.Exists);
        return found ?? throw new InvalidOperationException(
            "the client certificate tests run `openssl s_server` as the registrar's TLS; install OpenSSL");
    }

    private static string Run(string program, params string[] arguments)
    {
        var start = new ProcessStartInfo(program) { RedirectStandardOutput = true };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }
        using var process = Process.Start(start)!;
        var said = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return said;
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private SipralStack Over(string server, SipralClientCertificate? mine) =>
        new(audio: SipralAudio.Application, signalling: SipralTransport.Tls, signallingServer: server,
            tlsServerName: ServerName, tlsTrust: SipralTlsTrust.OnlyAuthority(_authority.Certificate),
            tlsClientCertificate: mine);

    // The first transport failure. The main connection is bound before it
    // fails or not at all, and speaks TLS either way; an account's own
    // connection refused in its handshake was never bound, and names no
    // protocol.
    private static async Task<SipralTransportFailedEventInfo> Failed(SipralStack stack, bool main = true)
    {
        using var cancel = new CancellationTokenSource(Timeout);
        await foreach (var args in stack.Events.WithCancellation(cancel.Token))
        {
            if (args.TransportFailed is { } failed)
            {
                if (main)
                {
                    Assert.Equal(SipralTransport.Tls, failed.Protocol);
                }
                return failed;
            }
        }
        throw new TimeoutException("no TransportFailed");
    }

    private static async Task Registered(SipralStack stack)
    {
        using var cancel = new CancellationTokenSource(Timeout);
        await foreach (var args in stack.Events.WithCancellation(cancel.Token))
        {
            Assert.Null(args.TransportFailed);
            if (args.Registration?.State == SipralRegistrationState.Registered)
            {
                return;
            }
        }
        throw new TimeoutException("never registered");
    }

    private async Task PresentedAndRegistered(OpensslRegistrar registrar, SipralClientCertificate mine)
    {
        using var stack = Over(registrar.Address, mine);
        Assert.True(stack.Connected, registrar.Said);
        var account = stack.AddAccount($"sip:alice@{ServerName}", registrar.Address, registrar: $"sip:{ServerName}");
        account.Register();
        await Registered(stack);
        var register = Assert.Single(registrar.Registers());
        Assert.StartsWith("SIP/2.0/TLS ", SignallingTests.Header("Via", register));
        // s_server's verify callback names the certificate it was given
        Assert.Matches(new Regex("depth=0 CN ?= ?sipral-client"), registrar.Said);
    }

    /// <summary>The certificate the server's authority signed is presented,
    /// accepted, and the account registers on that connection.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("-tls1_2")]
    public async Task ACertificateTheServersAuthoritySignedRegisters(string protocol)
    {
        var mine = Client(_authority, "sipral-client");
        using var registrar = new OpensslRegistrar(this, protocol.Length == 0 ? Array.Empty<string>() : new[] { protocol });
        await PresentedAndRegistered(registrar, new SipralClientCertificate(mine.WithKey));
    }

    /// <summary>The same certificate from PEM files, as a Linux service or
    /// the lab agent holds it.</summary>
    [Fact]
    public async Task ACertificateFromPemFilesRegisters()
    {
        var mine = Client(_authority, "sipral-client");
        var chain = Write("client.pem", mine.CertificatePem + "\n" + _authority.Certificate.ExportCertificatePem() + "\n");
        var key = Write("client.key", mine.KeyPem);
        var loaded = SipralClientCertificate.FromPemFiles(chain, key);
        Assert.True(loaded.Certificate.HasPrivateKey);
        Assert.Single(loaded.Intermediates);
        using var registrar = new OpensslRegistrar(this);
        await PresentedAndRegistered(registrar, loaded);
    }

    /// <summary>Without a certificate, a server that requires one is
    /// <see cref="SipralTlsFailure.ClientCertificateRequired"/>: in TLS 1.2
    /// the handshake fails after the server asked; in TLS 1.3 the server says
    /// so after the handshake, and the first read carries it.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("-tls1_2")]
    public async Task WithoutACertificateAServerThatRequiresOneSaysSo(string protocol)
    {
        using var registrar = new OpensslRegistrar(this, protocol.Length == 0 ? Array.Empty<string>() : new[] { protocol });
        using var stack = Over(registrar.Address, null);
        var account = stack.AddAccount($"sip:alice@{ServerName}", registrar.Address, registrar: $"sip:{ServerName}");
        account.Register();
        var failed = await Failed(stack);
        Assert.Equal(SipralTlsFailure.ClientCertificateRequired, failed.Tls);
        Assert.Equal(SipralTransportError.ConnectionReset, failed.Error);
        Assert.Contains("requires a client certificate", failed.Detail);
        Assert.Empty(registrar.Registers());
    }

    /// <summary>A certificate another authority signed is
    /// <see cref="SipralTlsFailure.ClientCertificateRefused"/>.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("-tls1_2")]
    public async Task ACertificateTheServerDoesNotTrustIsRefused(string protocol)
    {
        var mine = Client(_stranger, "sipral-stranger");
        using var registrar = new OpensslRegistrar(this, protocol.Length == 0 ? Array.Empty<string>() : new[] { protocol });
        using var stack = Over(registrar.Address, new SipralClientCertificate(mine.WithKey));
        var account = stack.AddAccount($"sip:alice@{ServerName}", registrar.Address, registrar: $"sip:{ServerName}");
        account.Register();
        var failed = await Failed(stack);
        Assert.Equal(SipralTlsFailure.ClientCertificateRefused, failed.Tls);
        Assert.Contains("refused the client certificate", failed.Detail);
        Assert.Empty(registrar.Registers());
    }

    /// <summary>
    /// TLS 1.3 judges the certificate one round trip after this end's
    /// handshake has ended. A REGISTER written in between reaches a server
    /// that then closes with it unread, its TCP stack resets the connection,
    /// and the alert would be lost; the layer waits for the verdict before
    /// the stack writes, so a registration asked for at once still reads the
    /// reason. SslStream on macOS has no TLS 1.3, and there the verdict is
    /// part of the handshake, as the theories above show; this runs where
    /// TLS 1.3 is (Linux, Windows).
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ARegistrationAskedAtOnceOverTls13StillReadsTheVerdict(bool presented)
    {
        if (OperatingSystem.IsMacOS())
        {
            return;
        }
        var mine = presented ? new SipralClientCertificate(Client(_stranger, "sipral-stranger").WithKey) : null;
        using var registrar = new OpensslRegistrar(this, "-tls1_3");
        using var stack = Over(registrar.Address, mine);
        var account = stack.AddAccount($"sip:alice@{ServerName}", registrar.Address, registrar: $"sip:{ServerName}");
        account.Register();
        var failed = await Failed(stack);
        Assert.Equal(presented ? SipralTlsFailure.ClientCertificateRefused : SipralTlsFailure.ClientCertificateRequired,
            failed.Tls);
        Assert.Empty(registrar.Registers());
    }

    /// <summary>A server that listens and must not be reached.</summary>
    private sealed class Untouched : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);

        public Untouched() => _listener.Start();

        public string Address => $"127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}";

        public bool Reached => _listener.Pending();

        public void Dispose() => _listener.Stop();
    }

    /// <summary>An expired certificate, or one not valid yet, is
    /// <see cref="SipralTlsFailure.ClientCertificateExpired"/>, read from its
    /// dates before any connection is made.</summary>
    [Fact]
    public async Task ACertificateOutOfItsDatesIsExpiredAndNothingIsConnected()
    {
        var expired = _authority.Issue("sipral-client", ClientAuth, Now.AddDays(-20), Now.AddDays(-10));
        var early = _authority.Issue("sipral-client", ClientAuth, Now.AddDays(5), Now.AddDays(10));
        foreach (var (mine, words) in new[] { (expired, "expired on"), (early, "not valid until") })
        {
            using var server = new Untouched();
            using var stack = Over(server.Address, new SipralClientCertificate(mine.WithKey));
            Assert.False(stack.Connected);
            var failed = await Failed(stack);
            Assert.Equal(SipralTlsFailure.ClientCertificateExpired, failed.Tls);
            Assert.Equal(SipralTransportError.Other, failed.Error);
            Assert.Contains(words, failed.Detail);
            Assert.False(server.Reached);
        }
    }

    /// <summary>A certificate whose private key is not there is
    /// <see cref="SipralTlsFailure.ClientKeyUnavailable"/>, with nothing
    /// connected.</summary>
    [Fact]
    public async Task ACertificateWithoutItsKeyIsKeyUnavailableAndNothingIsConnected()
    {
        var mine = Client(_authority, "sipral-client");
        using var bare = X509CertificateLoader.LoadCertificate(mine.WithKey.RawData);
        using var server = new Untouched();
        using var stack = Over(server.Address, new SipralClientCertificate(bare));
        var failed = await Failed(stack);
        Assert.Equal(SipralTlsFailure.ClientKeyUnavailable, failed.Tls);
        Assert.Contains("no private key", failed.Detail);
        Assert.False(server.Reached);
    }

    /// <summary>An account's own TLS connection presents the account's
    /// certificate, and registers with it beside the stack's UDP.</summary>
    [Fact]
    public async Task AnAccountsOwnConnectionPresentsTheAccountsCertificate()
    {
        var mine = Client(_authority, "sipral-client");
        using var registrar = new OpensslRegistrar(this);
        using var stack = new SipralStack(bindHost: "127.0.0.1", audio: SipralAudio.Application,
            tlsServerName: ServerName, tlsTrust: SipralTlsTrust.OnlyAuthority(_authority.Certificate));
        var account = stack.AddAccount($"sip:alice@{ServerName}", registrar.Address, registrar: $"sip:{ServerName}",
            streamProtocol: SipralTransport.Tls, tlsClientCertificate: new SipralClientCertificate(mine.WithKey));
        account.Register();
        await Registered(stack);
        Assert.Single(registrar.Registers());
        Assert.Matches(new Regex("depth=0 CN ?= ?sipral-client"), registrar.Said);
    }

    /// <summary>The same account with no certificate is told the server
    /// requires one, on its own transport.</summary>
    [Fact]
    public async Task AnAccountsOwnConnectionWithoutACertificateIsToldOneIsRequired()
    {
        using var registrar = new OpensslRegistrar(this);
        using var stack = new SipralStack(bindHost: "127.0.0.1", audio: SipralAudio.Application,
            tlsServerName: ServerName, tlsTrust: SipralTlsTrust.OnlyAuthority(_authority.Certificate));
        var account = stack.AddAccount($"sip:alice@{ServerName}", registrar.Address, registrar: $"sip:{ServerName}",
            streamProtocol: SipralTransport.Tls);
        account.Register();
        var failed = await Failed(stack, main: false);
        Assert.True(failed.Transport >= SipralStack.FirstStream);
        Assert.Equal(SipralTlsFailure.ClientCertificateRequired, failed.Tls);
        Assert.Empty(registrar.Registers());
    }
}
