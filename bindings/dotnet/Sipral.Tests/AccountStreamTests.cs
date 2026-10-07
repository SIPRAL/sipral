// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// An account on its own connection beside one on the stack's UDP socket,
/// each registering and calling through its own loopback registrar.
/// </summary>
public sealed class AccountStreamTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
    private const string ServerName = SignallingTests.ServerName;

    private static async Task<bool> Until(Func<bool> condition, double seconds = 10)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(seconds);
        while (!condition())
        {
            if (DateTime.UtcNow >= deadline)
            {
                return false;
            }
            await Task.Delay(20);
        }
        return true;
    }

    private static Task<bool> Registered(Account account) =>
        Until(() => account.RegistrationState() == SipralRegistrationState.Registered);

    [Fact]
    public async Task AnAccountOverTlsAndOneOverUdpEachReachTheirOwnServer()
    {
        using var udpRegistrar = new ReachabilityTests.Registrar();
        using var certificate = SignallingTests.Good();
        using var tlsRegistrar = new SignallingTests.Registrar(certificate);
        var pin = "sha256 Fingerprint=" + string.Join(":", SHA256.HashData(certificate.RawData).Select(b => b.ToString("X2")));

        // the account's own connection opens even with streamFallback off
        using var stack = new SipralStack(audio: SipralAudio.Application, bindHost: "127.0.0.1", streamFallback: false);
        var wanted = new ConcurrentQueue<SipralTransportWantedEventInfo>();
        stack.EventReceived += (_, args) =>
        {
            if (args.TransportWanted is { } one)
            {
                wanted.Enqueue(one);
            }
        };
        var overUdp = stack.AddAccount("sip:alice@udp.sipral.test", udpRegistrar.Address, registrar: "sip:udp.sipral.test");
        var overTls = stack.AddAccount($"sip:bob@{ServerName}", tlsRegistrar.Address, registrar: $"sip:{ServerName}",
            tlsPin: pin, streamProtocol: SipralTransport.Tls);
        Assert.Equal(SipralTransport.Tls, overTls.StreamProtocol);
        Assert.Equal((SipralTransport)0, overUdp.StreamProtocol);
        overUdp.Register();
        overTls.Register();
        Assert.True(await Registered(overUdp), "the UDP account never registered");
        Assert.True(await Registered(overTls), "the TLS account never registered");

        var asked = Assert.Single(wanted);
        Assert.Equal(SipralTransport.Tls, asked.Protocol);
        Assert.Equal(tlsRegistrar.Address, asked.Destination);
        Assert.Equal(0ul, asked.RequestBytes);
        var (connection, register) = Assert.Single(tlsRegistrar.Registers());
        Assert.StartsWith("SIP/2.0/TLS ", SignallingTests.Header("Via", register));
        Assert.Contains(";transport=tls", SignallingTests.Header("Contact", register));
        Assert.Contains("sip:bob@", register);
        Assert.NotEmpty(udpRegistrar.Registers);
        Assert.All(udpRegistrar.Registers, one => Assert.Contains("sip:alice@", one));

        var first = stack.PlaceCall(overUdp, "sip:carol@udp.sipral.test");
        var second = stack.PlaceCall(overTls, $"sip:dave@{ServerName}");
        try
        {
            Assert.True(await Until(() => udpRegistrar.Received.Any(m => m.StartsWith("INVITE sip:carol@", StringComparison.Ordinal))),
                "the UDP account's call never reached its server");
            Assert.True(await Until(() => tlsRegistrar.Requests().Any(r => r.Message.StartsWith("INVITE sip:dave@", StringComparison.Ordinal))),
                "the TLS account's call never reached its server");
            var invite = tlsRegistrar.Requests().First(r => r.Message.StartsWith("INVITE ", StringComparison.Ordinal));
            Assert.Equal(connection, invite.Connection);
            Assert.StartsWith("SIP/2.0/TLS ", SignallingTests.Header("Via", invite.Message));
            Assert.DoesNotContain(udpRegistrar.Received, m => m.Contains("dave@"));
            Assert.DoesNotContain(tlsRegistrar.Requests(), r => r.Message.Contains("carol@"));
        }
        finally
        {
            first.Close();
            second.Close();
        }
    }

    [Fact]
    public async Task AnAccountOverTcpIsOpenedAgainWhenItsServerDropsTheConnection()
    {
        using var registrar = new SignallingTests.Registrar();
        using var stack = new SipralStack(audio: SipralAudio.Application, bindHost: "127.0.0.1");
        var account = stack.AddAccount($"sip:alice@{ServerName}", registrar.Address, registrar: $"sip:{ServerName}",
            streamProtocol: SipralTransport.Tcp);
        account.Register();
        Assert.True(await Registered(account));
        var (_, register) = Assert.Single(registrar.Registers());
        Assert.StartsWith("SIP/2.0/TCP ", SignallingTests.Header("Via", register));
        Assert.Contains(";transport=tcp", SignallingTests.Header("Contact", register));

        registrar.Drop();
        Assert.True(await Until(() => registrar.Registers().Any(r => r.Connection == 2)),
            "the account did not register again over a new connection");
    }

    [Fact]
    public void OnlyAStreamOnAStackThatSignalsOverUdpIsTaken()
    {
        using var stack = new SipralStack(audio: SipralAudio.Application, bindHost: "127.0.0.1");
        Assert.Throws<ArgumentException>(() => stack.AddAccount("sip:alice@example.com", "127.0.0.1:5060",
            streamProtocol: SipralTransport.Udp));
    }

    [Fact]
    public void TheSettingsAreReadBackWithTheDefaultsFilledIn()
    {
        using var plain = new SipralStack(audio: SipralAudio.Application, bindHost: "127.0.0.1");
        var defaults = plain.Settings();
        Assert.Equal(SipralTransport.Udp, defaults.Transport);
        Assert.True(defaults.Retransmits);
        Assert.True(defaults.SystemEchoCancellation);
        Assert.False(defaults.PseudonymSalted);
        Assert.False(defaults.DiagnosticTrace);
        Assert.NotEmpty(defaults.SrtpSuites);
        Assert.True(defaults.CodecCount > 0);
        Assert.Null(defaults.RtpPorts);

        using var given = new SipralStack(audio: SipralAudio.Application, bindHost: "127.0.0.1",
            rtpPortMin: 40000, rtpPortMax: 40100,
            srtpSuites: new[] { "AES_CM_128_HMAC_SHA1_32", "AES_CM_128_HMAC_SHA1_80" },
            pseudonymSalt: Enumerable.Repeat((byte)7, 16).ToArray(), diagnosticTrace: true,
            systemEchoCancellation: false);
        var settings = given.Settings();
        Assert.Equal(new[] { SipralSrtpSuite.AesCm32, SipralSrtpSuite.AesCm80 }, settings.SrtpSuites);
        Assert.True(settings.PseudonymSalted);
        Assert.True(settings.DiagnosticTrace);
        Assert.False(settings.SystemEchoCancellation);
        Assert.Equal((40000u, 40100u), settings.RtpPorts);
        given.SetDiagnosticTrace(false);
        Assert.False(given.Settings().DiagnosticTrace);
    }
}
