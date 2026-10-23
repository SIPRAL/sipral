// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Sipral;

/// <summary>
/// The certificate this end presents when a TLS server asks for one
/// (<c>docs/22-tls.md</c>, "A client certificate"): an
/// <see cref="X509Certificate2"/> whose private key the platform holds — a
/// CNG key on Windows, the Keychain on macOS, a key loaded from a file on
/// Linux — and the intermediates sent after it. The key is used where it
/// lives and never exported.
///
/// Before each connection the layer checks the certificate's dates and that
/// its key can be opened; a failure is
/// <see cref="SipralTlsFailure.ClientCertificateExpired"/> or
/// <see cref="SipralTlsFailure.ClientKeyUnavailable"/> with no connection
/// made. What the server says of it arrives as
/// <see cref="SipralTlsFailure.ClientCertificateRefused"/>, and a server that
/// wants one from a stack given none as
/// <see cref="SipralTlsFailure.ClientCertificateRequired"/>.
/// </summary>
public sealed class SipralClientCertificate
{
    /// <summary><paramref name="certificate"/> with its private key, and
    /// any <paramref name="intermediates"/> between it and the authority the
    /// server trusts, sent in that order.</summary>
    public SipralClientCertificate(X509Certificate2 certificate, X509Certificate2Collection? intermediates = null)
    {
        Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        Intermediates = intermediates ?? new X509Certificate2Collection();
    }

    /// <summary>The certificate presented, with its private key.</summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>The certificates sent after it.</summary>
    public X509Certificate2Collection Intermediates { get; }

    /// <summary>A certificate and its key from PEM files: the first
    /// certificate in <paramref name="certificatePath"/> is presented and the
    /// others follow it as intermediates; <paramref name="keyPath"/> holds its
    /// PKCS#8 or SEC 1 private key, unencrypted. On Windows the key is moved
    /// into an in-memory PKCS#12 import first, because SChannel cannot sign
    /// with an ephemeral key.</summary>
    public static SipralClientCertificate FromPemFiles(string certificatePath, string keyPath)
    {
        var leaf = X509Certificate2.CreateFromPemFile(certificatePath, keyPath);
        var all = new X509Certificate2Collection();
        all.ImportFromPemFile(certificatePath);
        var intermediates = new X509Certificate2Collection();
        foreach (var one in all.Cast<X509Certificate2>().Skip(1))
        {
            intermediates.Add(one);
        }
        if (OperatingSystem.IsWindows())
        {
            using var ephemeral = leaf;
            leaf = new X509Certificate2(ephemeral.Export(X509ContentType.Pkcs12));
        }
        return new SipralClientCertificate(leaf, intermediates);
    }

    // Null when it can be presented now; otherwise why not, with no
    // connection made.
    internal SignallingRefusedException? Unusable()
    {
        var subject = Certificate.Subject.Length == 0 ? "the client certificate" : $"the client certificate {Certificate.Subject}";
        if (!Certificate.HasPrivateKey)
        {
            return new SignallingRefusedException(SipralTransportError.Other, SipralTlsFailure.ClientKeyUnavailable,
                $"{subject} has no private key");
        }
        try
        {
            // opens the key where it lives, as the handshake will; nothing
            // is signed, so a key that asks its user for each use does not ask
            using var key = (AsymmetricAlgorithm?)Certificate.GetECDsaPrivateKey() ?? Certificate.GetRSAPrivateKey();
            if (key is null)
            {
                return new SignallingRefusedException(SipralTransportError.Other,
                    SipralTlsFailure.ClientKeyUnavailable, $"{subject} has a key that is neither ECDSA nor RSA");
            }
        }
        catch (CryptographicException ex)
        {
            return new SignallingRefusedException(SipralTransportError.Other, SipralTlsFailure.ClientKeyUnavailable,
                $"the private key of {subject} cannot be used: {ex.Message}");
        }
        var now = DateTime.Now;
        if (now < Certificate.NotBefore)
        {
            return new SignallingRefusedException(SipralTransportError.Other,
                SipralTlsFailure.ClientCertificateExpired,
                $"{subject} is not valid until {Certificate.NotBefore.ToUniversalTime():u}");
        }
        if (now > Certificate.NotAfter)
        {
            return new SignallingRefusedException(SipralTransportError.Other,
                SipralTlsFailure.ClientCertificateExpired,
                $"{subject} expired on {Certificate.NotAfter.ToUniversalTime():u}");
        }
        return null;
    }
}

/// <summary>One connection's use of a client certificate: what it presents,
/// whether the server asked, and how a failure reads in that light.</summary>
internal sealed class ClientCertificateUse
{
    private readonly SipralClientCertificate? _certificate;
    private int _asked;

    private ClientCertificateUse(SipralClientCertificate? certificate) => _certificate = certificate;

    private bool Presented => _certificate is not null;

    private bool Asked => Volatile.Read(ref _asked) != 0;

    /// <summary>For one attempt: its use. Throws
    /// <see cref="SignallingRefusedException"/> saying why when the
    /// certificate cannot be presented, and then nothing is to be
    /// connected.</summary>
    internal static ClientCertificateUse Prepare(SipralClientCertificate? certificate)
    {
        if (certificate?.Unusable() is { } refused)
        {
            throw refused;
        }
        return new ClientCertificateUse(certificate);
    }

    internal void Apply(SslClientAuthenticationOptions options)
    {
        if (_certificate is { } mine)
        {
            options.ClientCertificateContext =
                SslStreamCertificateContext.Create(mine.Certificate, mine.Intermediates, offline: true);
            return;
        }
        // called only when the server sends a CertificateRequest
        options.LocalCertificateSelectionCallback = (_, _, _, _, _) =>
        {
            Volatile.Write(ref _asked, 1);
            return null!;
        };
    }

    /// <summary>
    /// After a TLS 1.3 handshake in which a certificate was asked for, the
    /// server's verdict on it is one round trip away: a request written
    /// meanwhile reaches a server that then closes with it unread, its TCP
    /// stack answers with a reset, and the alert that said why is lost. So
    /// the first read is started here and waited for twice as long as the
    /// handshake took, at least 250 ms and at most 3 s: an alert in that
    /// time fails the connection with its reason (thrown as
    /// <see cref="SignallingRefusedException"/>); bytes, or silence, accept
    /// it, and the read, finished or still pending, is the caller's first,
    /// into the buffer returned. Nothing to wait for in TLS 1.2, where the
    /// verdict is part of the handshake, nor when nobody asked.
    /// </summary>
    internal (Task<int>? First, byte[]? Buffer) AwaitVerdict(SslStream tls, TimeSpan handshake, int bufferBytes)
    {
        if (tls.SslProtocol != SslProtocols.Tls13 || !(Asked || tls.LocalCertificate is not null))
        {
            return (null, null);
        }
        var window = handshake * 2;
        window = window < MinimumWait ? MinimumWait : window > MaximumWait ? MaximumWait : window;
        var buffer = new byte[bufferBytes];
        var first = tls.ReadAsync(buffer, 0, buffer.Length);
        try
        {
            first.Wait(window);
        }
        catch (AggregateException)
        {
            // read below, from the task
        }
        if (first.IsFaulted)
        {
            var failure = first.Exception!.GetBaseException();
            throw Explain(failure) ?? new SignallingRefusedException(SipralTransportError.ConnectionReset,
                SipralTlsFailure.None, failure.Message);
        }
        if (first.IsCompletedSuccessfully && first.Result == 0)
        {
            // Asterisk's way of refusing a certificate its authority did not
            // sign: a clean close and no alert, read as the Kotlin layer
            // reads it. A certificate that went out was asked for; with none
            // configured, the selection callback says whether one was.
            var silent = tls.LocalCertificate is not null ? SipralTlsFailure.ClientCertificateRefused
                : Asked ? SipralTlsFailure.ClientCertificateRequired
                : SipralTlsFailure.None;
            throw new SignallingRefusedException(SipralTransportError.ConnectionReset, silent,
                silent == SipralTlsFailure.None
                    ? "the server closed the connection as the handshake ended"
                    : "the server asked for a client certificate and closed the connection as the handshake ended, no alert reaching this end");
        }
        return (first, buffer);
    }

    private static readonly TimeSpan MinimumWait = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan MaximumWait = TimeSpan.FromSeconds(3);

    /// <summary>What a failed handshake, or a failed read or write on the
    /// connection it made, says about the client certificate, or
    /// <see langword="null"/> when it says nothing about it. TLS 1.3 sends
    /// the server's verdict after this end's Finished, so it arrives as a
    /// read that fails.</summary>
    internal SignallingRefusedException? Explain(Exception failure)
    {
        var alert = AlertOf(failure, out var said);
        var keyFailed = KeyFailed(failure);
        SipralTlsFailure? tls = null;
        if (Presented)
        {
            if (alert == CertificateExpired)
            {
                tls = SipralTlsFailure.ClientCertificateExpired;
            }
            else if (alert is { } refusal && Refusals.Contains(refusal))
            {
                tls = SipralTlsFailure.ClientCertificateRefused;
            }
            else if (alert is null && keyFailed)
            {
                tls = SipralTlsFailure.ClientKeyUnavailable;
            }
        }
        else if (alert is { } refusal && (Refusals.Contains(refusal) || (refusal is HandshakeFailure or UnknownAlert && Asked)))
        {
            tls = SipralTlsFailure.ClientCertificateRequired;
        }
        if (tls is not { } reason)
        {
            return null;
        }
        var why = reason switch
        {
            SipralTlsFailure.ClientCertificateRequired => "the server requires a client certificate and none was given",
            SipralTlsFailure.ClientCertificateExpired => "the server refused the client certificate as expired",
            SipralTlsFailure.ClientKeyUnavailable => "the client certificate's private key could not sign",
            _ => "the server refused the client certificate",
        };
        return new SignallingRefusedException(SipralTransportError.ConnectionReset, reason,
            said.Length == 0 ? why : $"{why}: {said}");
    }

    // TLS alert descriptions (RFC 8446 §6, RFC 5246 §7.2); UnknownAlert is a
    // fatal alert the platform does not name.
    private const int HandshakeFailure = 40;
    private const int CertificateExpired = 45;
    private const int CertificateRequired = 116;
    private const int UnknownAlert = -1;

    // bad_certificate, unsupported_certificate, certificate_revoked,
    // certificate_unknown, unknown_ca, access_denied, certificate_required
    private static readonly HashSet<int> Refusals = new() { 42, 43, 44, 46, 48, 49, CertificateRequired };

    // Apple's SecureTransport (.NET on macOS) reports a received alert as the
    // OSStatus in the exception's HResult (SecBase.h).
    private static readonly Dictionary<int, int> AppleAlerts = new()
    {
        [-9824] = HandshakeFailure,
        [-9825] = 42,
        [-9826] = 43,
        [-9827] = 44,
        [-9828] = CertificateExpired,
        [-9829] = 46,
        [-9831] = 48,
        [-9832] = 49,
        [-9863] = CertificateRequired,
    };

    // SChannel (Windows) names few alerts: SEC_E_CERT_EXPIRED,
    // SEC_E_CERT_UNKNOWN, and SEC_E_ILLEGAL_MESSAGE for any other fatal one.
    private static readonly Dictionary<int, int> SchannelAlerts = new()
    {
        [unchecked((int)0x80090328)] = CertificateExpired,
        [unchecked((int)0x80090327)] = 46,
        [unchecked((int)0x80090326)] = UnknownAlert,
    };

    // OpenSSL (.NET on Linux) writes the alert's name into its reason:
    // "sslv3 alert bad certificate", "tlsv13 alert certificate required".
    private static readonly (string Name, int Alert)[] OpenSslAlerts =
    {
        ("handshake failure", HandshakeFailure),
        ("bad certificate", 42),
        ("unsupported certificate", 43),
        ("certificate revoked", 44),
        ("certificate expired", CertificateExpired),
        ("certificate unknown", 46),
        ("unknown ca", 48),
        ("access denied", 49),
        ("certificate required", CertificateRequired),
    };

    private static readonly Regex OpenSslAlert = new(@"alert ([a-z ]+?)(?:$|[^a-z ])",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    // OpenSSL 1.1 also gives the number: "SSL alert number 42".
    private static readonly Regex OpenSslAlertNumber = new(@"alert number (\d+)",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static IEnumerable<Exception> Chain(Exception failure)
    {
        for (var one = failure; one is not null; one = one.InnerException)
        {
            yield return one;
        }
    }

    // The alert the server sent, by the platform's way of saying it, and the
    // platform's sentence for it.
    private static int? AlertOf(Exception failure, out string said)
    {
        foreach (var one in Chain(failure).Reverse())
        {
            said = one.Message;
            if (AppleAlerts.TryGetValue(one.HResult, out var apple))
            {
                return apple;
            }
            if (one is Win32Exception win32 && SchannelAlerts.TryGetValue(win32.NativeErrorCode, out var schannel))
            {
                return schannel;
            }
            if (OpenSslAlertNumber.Match(one.Message) is { Success: true } numbered
                && int.TryParse(numbered.Groups[1].Value, out var number))
            {
                return number;
            }
            if (OpenSslAlert.Match(one.Message) is { Success: true } match)
            {
                var name = match.Groups[1].Value.Trim().ToLowerInvariant();
                foreach (var (known, alert) in OpenSslAlerts)
                {
                    if (name == known)
                    {
                        return alert;
                    }
                }
            }
        }
        said = string.Empty;
        return null;
    }

    // The platform could not sign with the key during the handshake: a
    // cryptographic failure in the chain other than OpenSSL's own report of
    // the TLS error, SEC_E_NO_CREDENTIALS, or the Keychain refusing the key's
    // use (errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled).
    private static bool KeyFailed(Exception failure) => Chain(failure).Any(one =>
        (one is CryptographicException && one.GetType().FullName?.Contains("OpenSsl", StringComparison.Ordinal) != true)
        || (one is Win32Exception win32 && win32.NativeErrorCode == unchecked((int)0x8009030E))
        || one.HResult is -25308 or -25293 or -128);
}
