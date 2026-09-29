// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// STIR/SHAKEN, the SRTP policy per account and the encryption report,
/// through this layer: two stacks on 127.0.0.1 with no registrar between
/// them — the .NET counterpart of
/// <c>bindings/python/tests/test_security.py</c>.
///
/// A valid signature is verified against the chain the C ABI's tests keep in
/// <c>bindings/fixtures/stir-provider-709J</c>, whose signing certificate
/// names a service provider code and no number. Beside that, what this
/// proves is the plumbing every
/// half of it runs through: the account's signing key and URL reach the
/// INVITE, the verifying stack asks for the certificate by
/// <see cref="SipralEventKind.CallerVerification"/>,
/// <see cref="SipralStack.StirCertificate"/> answers it, and a strict account
/// refuses what does not verify.
/// </summary>
public sealed class SecurityTests : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    // short, and the stacks offer one codec: a signed INVITE is some five
    // hundred octets longer than an unsigned one, and past RFC 3261 Section
    // 18.1.1's 1300 it needs a stream transport this test does not open
    private const string Url = "https://c.test/p";

    private readonly SipralStack _caller = new(audio: SipralAudio.Application, codecs: "PCMU");
    private readonly SipralStack _callee = new(audio: SipralAudio.Application, codecs: "PCMU");

    public void Dispose()
    {
        _caller.Dispose();
        _callee.Dispose();
    }

    [Fact]
    public async Task ASignedCallAsksForItsCertificateAndAStrictAccountRefusesIt()
    {
        // a P-256 private key as the bare scalar: any 32 octets below the
        // group order are one, and these are nobody's
        var key = Enumerable.Repeat((byte)0x2B, 32).ToArray();
        // a stack that only signs is given the time, and no anchors
        _caller.Stir(null);
        _callee.Stir(null);
        var signing = _caller.AddAccount(
            "sip:+12155551212@a.test", registrarAddress: _callee.BindAddress,
            security: new AccountSecurity(StirKey: key, StirCertificateUrl: Url));
        _callee.AddAccount(
            "sip:12125551213@b.test", registrarAddress: _caller.BindAddress,
            security: new AccountSecurity(StirVerification: SipralStirVerification.Strict));
        var call = _caller.PlaceCall(signing, $"sip:12125551213@{_callee.BindAddress}");
        try
        {
            var wanted = await FirstMatchingAsync(
                _callee.Events, e => e.Kind == SipralEventKind.CallerVerification, Timeout);
            Assert.Equal(SipralVerificationStage.CertificateWanted, wanted.Verification!.Stage);
            Assert.Equal(Url, wanted.Verification.CertificateUrl);

            // a certificate that could not be had: RFC 8224's 436, sent
            _callee.StirCertificate(wanted.Call, null);
            var verdict = (await FirstMatchingAsync(
                _callee.Events, e => e.Kind == SipralEventKind.CallerVerification, Timeout)).Verification!;
            Assert.Equal(SipralVerificationStage.Verified, verdict.Stage);
            Assert.Equal(SipralVerificationOutcome.Invalid, verdict.Outcome);
            Assert.Equal(SipralVerificationFailure.CertificateUnavailable, verdict.Failure);
            Assert.Equal(436u, verdict.ResponseCode);
            Assert.True(verdict.Refused);

            var ended = await FirstMatchingAsync(_caller.Events, e => e.Kind == SipralEventKind.CallEnded, Timeout);
            Assert.Equal(436u, ended.CallInfo!.StatusCode);
        }
        finally
        {
            call.Close();
        }
    }

    [Fact]
    public void AnAccountThatSignsNeedsTheTimeFirst()
    {
        var key = Enumerable.Repeat((byte)0x2B, 32).ToArray();
        var refused = Assert.Throws<SipralException>(() => _caller.AddAccount(
            "sip:+12155551212@a.test", registrarAddress: _callee.BindAddress,
            security: new AccountSecurity(StirKey: key, StirCertificateUrl: Url)));
        Assert.Equal(SipralStatus.WrongState, refused.Status);
    }

    [Fact]
    public async Task AnSdesCallReportsHowItIsProtected()
    {
        var placing = _caller.AddAccount(
            "sip:alice@sipral.invalid", registrarAddress: _callee.BindAddress,
            security: new AccountSecurity(SipralSrtp.Required, new[] { "AES_CM_128_HMAC_SHA1_80" }));
        _callee.AddAccount(
            "sip:bob@sipral.invalid", registrarAddress: _caller.BindAddress,
            security: new AccountSecurity(SipralSrtp.Required));
        var call = _caller.PlaceCall(placing, $"sip:bob@{_callee.BindAddress}");
        var incoming = await FirstMatchingAsync(_callee.Events, e => e.Kind == SipralEventKind.IncomingCall, Timeout);
        var answered = _callee.AnswerCall(incoming);
        try
        {
            var started = await FirstMatchingAsync(
                _caller.Events, e => e.Kind == SipralEventKind.MediaStarted, Timeout);
            Assert.Equal(SipralKeyExchange.Sdes, started.Media!.KeyExchange);
            Assert.True(started.Media.Encrypted);
            Assert.Equal(SipralSrtpSuite.AesCm80, started.Media.Suite);

            using var cts = new CancellationTokenSource(Timeout);
            var media = await call.WaitForMediaAsync(cts.Token);
            Assert.NotNull(media);
            var report = media!.Encryption();
            Assert.Single(report);
            Assert.Equal(SipralMediaKind.Audio, report[0].Media);
            Assert.Equal(SipralKeyExchange.Sdes, report[0].KeyExchange);
            Assert.True(report[0].Encrypted);
            Assert.False(report[0].Authenticated, "SDES authenticates nothing");
        }
        finally
        {
            call.Close();
            answered.Close();
        }
    }

    // a moment inside every certificate of the provider chain below
    private const ulong Within = 1_790_000_000;

    /// <summary>One of the credentials <c>sipral_stir::testing</c> issues
    /// for the service provider code 709J, checked against it by the C ABI's
    /// own tests: a root, a chain whose signing certificate names that code
    /// and no number, and its key.</summary>
    private static string Provider(string name, [CallerFilePath] string here = "") =>
        Path.Combine(Path.GetDirectoryName(here)!, "..", "..", "fixtures", "stir-provider-709J", name);

    private async Task<SipralVerificationEventInfo> VerdictAsync(bool acceptServiceProviderCodes)
    {
        _caller.Stir(null, unixSeconds: Within);
        _callee.Stir(
            File.ReadAllBytes(Provider("anchor.pem")), unixSeconds: Within,
            acceptServiceProviderCodes: acceptServiceProviderCodes);
        var key = Convert.FromHexString(File.ReadAllText(Provider("signing-scalar.hex")).Trim());
        var signing = _caller.AddAccount(
            "sip:+12155551212@a.test", registrarAddress: _callee.BindAddress,
            security: new AccountSecurity(StirKey: key, StirCertificateUrl: Url));
        _callee.AddAccount("sip:12125551213@b.test", registrarAddress: _caller.BindAddress);
        var call = _caller.PlaceCall(signing, $"sip:12125551213@{_callee.BindAddress}");
        try
        {
            var wanted = await FirstMatchingAsync(
                _callee.Events, e => e.Kind == SipralEventKind.CallerVerification, Timeout);
            Assert.Equal(SipralVerificationStage.CertificateWanted, wanted.Verification!.Stage);
            _callee.StirCertificate(wanted.Call, File.ReadAllBytes(Provider("chain.pem")));
            var verdict = (await FirstMatchingAsync(
                _callee.Events, e => e.Kind == SipralEventKind.CallerVerification, Timeout)).Verification!;
            Assert.Equal(SipralVerificationStage.Verified, verdict.Stage);
            return verdict;
        }
        finally
        {
            call.Close();
        }
    }

    [Fact]
    public async Task ACertificateNamingOnlyACodeCoversNoNumberByDefault()
    {
        var verdict = await VerdictAsync(acceptServiceProviderCodes: false);
        Assert.Equal(SipralVerificationOutcome.Invalid, verdict.Outcome);
        Assert.Equal(SipralVerificationFailure.NumberNotCovered, verdict.Failure);
    }

    [Fact]
    public async Task AStackThatAcceptsCodesVerifiesTheCaller()
    {
        var verdict = await VerdictAsync(acceptServiceProviderCodes: true);
        Assert.Equal(SipralVerificationOutcome.Valid, verdict.Outcome);
    }

    [Fact]
    public void ASuiteNoSrtpNamesIsRefusedWhereItIsGiven()
    {
        var refused = Assert.Throws<SipralException>(() => _caller.AddAccount(
            "sip:alice@sipral.invalid", registrarAddress: _callee.BindAddress,
            security: new AccountSecurity(SrtpSuites: new[] { "AES_CM_128_HMAC_SHA1_80", "NOT_A_SUITE" })));
        Assert.Equal(SipralStatus.InvalidArgument, refused.Status);
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
}
