// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using Sipral.Interop;
using static Sipral.Interop.NativeText;

namespace Sipral;

/// <summary>
/// What a TLS connection to the SIP server trusts (<c>docs/22-tls.md</c>):
/// <see cref="Platform"/>, <see cref="PrivateAuthority"/> (a private CA
/// beside the platform's), <see cref="OnlyAuthority"/>, or
/// <see cref="Pinned"/> (one certificate by fingerprint, for a self-signed
/// PBX). None turns the check off; the name is always checked.
/// </summary>
public sealed class SipralTlsTrust
{
    private readonly X509Certificate2Collection _authorities;
    private readonly bool _only;
    private readonly byte[]? _pin;

    private SipralTlsTrust(X509Certificate2Collection authorities, bool only, byte[]? pin = null)
    {
        _authorities = authorities;
        _only = only;
        _pin = pin;
    }

    /// <summary>Trust only the certificate with this SHA-256 fingerprint: 64
    /// hex digits, any case, colons and spaces ignored, optionally after
    /// <c>sha-256 </c>, <c>SHA256=</c> or <c>SHA256 Fingerprint=</c> (as
    /// OpenSSL or RFC 8122 print it; see
    /// <c>bindings/fixtures/pin-forms.txt</c>). Anything else throws
    /// <see cref="ArgumentException"/>. No authority, name or date is
    /// checked; the leaf's DER is compared in constant time.</summary>
    public static SipralTlsTrust Pinned(string fingerprint) =>
        new(new X509Certificate2Collection(), only: false, PinDigest(fingerprint));

    /// <summary>The 32 bytes of a fingerprint in any form
    /// <see cref="Pinned"/> takes.</summary>
    public static byte[] PinDigest(string fingerprint)
    {
        var text = fingerprint.Trim();
        var prefix = PinPrefixes.FirstOrDefault(one => text.StartsWith(one, StringComparison.OrdinalIgnoreCase));
        if (prefix is not null)
        {
            text = text[prefix.Length..];
        }
        var digits = text.Replace(":", "").Replace(" ", "");
        if (digits.Length != 64 || !digits.All(Uri.IsHexDigit))
        {
            throw new ArgumentException(
                "a certificate pin is a SHA-256 fingerprint: 64 hexadecimal digits, "
                + "optionally after sha-256, SHA256= or SHA256 Fingerprint=", nameof(fingerprint));
        }
        return Convert.FromHexString(digits);
    }

    private static readonly string[] PinPrefixes = { "sha256 fingerprint=", "sha-256 ", "sha256=" };

    /// <summary>The platform's own trust anchors.</summary>
    public static SipralTlsTrust Platform { get; } = new(new X509Certificate2Collection(), only: false);

    /// <summary>The platform's anchors, and <paramref name="authority"/>
    /// beside them.</summary>
    public static SipralTlsTrust PrivateAuthority(X509Certificate2 authority) =>
        new(new X509Certificate2Collection(authority), only: false);

    /// <summary>Only <paramref name="authority"/>; the platform's store is
    /// not consulted.</summary>
    public static SipralTlsTrust OnlyAuthority(X509Certificate2 authority) =>
        new(new X509Certificate2Collection(authority), only: true);

    internal void Apply(SslClientAuthenticationOptions options, Verdict verdict)
    {
        if (_pin is { } pin)
        {
            // the pin replaces the chain, the name and the dates
            options.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
            {
                var leaf = certificate?.GetRawCertData() ?? Array.Empty<byte>();
                var matches = CryptographicOperations.FixedTimeEquals(SHA256.HashData(leaf), pin);
                if (!matches)
                {
                    verdict.RecordPinMismatch();
                }
                return matches;
            };
            return;
        }
        if (_only)
        {
            // Revocation off, as SslStream's default: a custom policy starts
            // from Online, and a private CA publishes no revocation list, so
            // on Linux every certificate it signed would fail the chain.
            var policy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
            };
            policy.CustomTrustStore.AddRange(_authorities);
            options.CertificateChainPolicy = policy;
        }
        var extra = _only ? null : _authorities;
        options.RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
        {
            if (extra is { Count: > 0 } && errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors)
                && certificate is not null)
            {
                // rebuild the refused chain with the private CA as a root;
                // any other platform error still stands
                using var again = new X509Chain();
                again.ChainPolicy.ExtraStore.AddRange(extra);
                again.ChainPolicy.CustomTrustStore.AddRange(extra);
                again.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                again.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                var rest = errors & ~SslPolicyErrors.RemoteCertificateChainErrors;
                if (again.Build(new X509Certificate2(certificate)))
                {
                    verdict.Record(rest, again);
                    return rest == SslPolicyErrors.None;
                }
                verdict.Record(errors, again);
                return false;
            }
            verdict.Record(errors, chain);
            return errors == SslPolicyErrors.None;
        };
    }

    // Kept to explain a refused handshake.
    internal sealed class Verdict
    {
        internal SslPolicyErrors? Errors { get; private set; }
        internal X509ChainStatusFlags Chain { get; private set; }
        internal string Detail { get; private set; } = string.Empty;

        /// <summary>The certificate is not the pinned one: untrusted.</summary>
        internal void RecordPinMismatch()
        {
            Errors = SslPolicyErrors.RemoteCertificateChainErrors;
            Chain = X509ChainStatusFlags.UntrustedRoot;
            Detail = "the server's certificate is not the pinned one";
        }

        internal void Record(SslPolicyErrors errors, X509Chain? chain)
        {
            Errors = errors;
            var statuses = chain?.ChainStatus ?? Array.Empty<X509ChainStatus>();
            Chain = statuses.Aggregate(X509ChainStatusFlags.NoError, (all, one) => all | one.Status);
            var words = statuses.Select(one => one.StatusInformation.Trim()).Where(one => one.Length > 0);
            Detail = string.Join("; ", new[] { errors.ToString() }.Concat(words));
        }
    }
}

/// <summary>How fast one address may ring a stack: <see cref="Burst"/>
/// INVITEs at once, then one every <see cref="EveryMs"/>; beyond that, 480
/// (<c>sipral_stack_invite_limit</c>).</summary>
public readonly record struct SipralInviteLimit(uint Burst, ulong EveryMs)
{
    /// <summary>Ten at once, then one every two seconds.</summary>
    public static SipralInviteLimit Default { get; } =
        new(global::Sipral.Sipral.InviteLimitBurst, global::Sipral.Sipral.InviteLimitEveryMs);

    /// <summary>For a service taking a trunk's calls: 128 at once, then one
    /// every 50 ms.</summary>
    public static SipralInviteLimit VoiceAgent { get; } =
        new(global::Sipral.Sipral.InviteLimitVoiceAgentBurst, global::Sipral.Sipral.InviteLimitVoiceAgentEveryMs);
}

/// <summary>What a <see cref="SipralEventKind.TransportFailed"/> event
/// carries. <see cref="Detail"/> is the TLS library's own text.</summary>
public sealed record SipralTransportFailedEventInfo(
    uint Transport,
    SipralTransport Protocol,
    SipralTransportError Error,
    SipralTlsFailure Tls,
    string? Detail);

internal sealed class SignallingRefusedException : Exception
{
    internal SignallingRefusedException(SipralTransportError error, SipralTlsFailure tls, string detail)
        : base(detail)
    {
        Error = error;
        Tls = tls;
    }

    internal SipralTransportError Error { get; }
    internal SipralTlsFailure Tls { get; }
}

public sealed partial class SipralStack
{
    // Per attempt, TLS handshake included.
    private static readonly TimeSpan SignallingPatience = TimeSpan.FromSeconds(5);
    // Doubled after each failure, up to ReconnectMost.
    private static readonly TimeSpan ReconnectFirst = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ReconnectMost = TimeSpan.FromSeconds(30);

    private SipralTransport _signalling;
    private (string Host, int Port)? _server;
    private string? _serverName;
    private SipralTlsTrust _tlsTrust = SipralTlsTrust.Platform;
    private string? _bindHost;
    private Link? _link;
    private int _reconnecting;

    // Writes take the lock: one TLS session written from two threads
    // interleaves its records.
    private sealed class Link
    {
        public required TcpClient Client { get; init; }
        public required Stream Stream { get; init; }
        public required string Local { get; init; }
        public required string Remote { get; init; }
        public object WriteLock { get; } = new();
    }

    /// <summary>What SIP travels over.</summary>
    public SipralTransport Signalling => _signalling;

    /// <summary>Whether SIP can go out now: always over UDP, over TCP or TLS
    /// while connected.</summary>
    public bool Connected => !Streamed || Volatile.Read(ref _link) is not null;

    private bool Streamed => _signalling is SipralTransport.Tcp or SipralTransport.Tls;

    // The Contact's transport parameter (RFC 3261 §19.1.1).
    internal string ContactParameters => _signalling switch
    {
        SipralTransport.Tls => ";transport=tls",
        SipralTransport.Tcp => ";transport=tcp",
        _ => string.Empty,
    };

    private (Link? Link, SignallingRefusedException? Refused) PrepareSignalling(
        SipralTransport signalling, string? bindHost, string? signallingServer, string? tlsServerName,
        SipralTlsTrust? tlsTrust)
    {
        _signalling = signalling == 0 ? SipralTransport.Udp : signalling;
        if (_signalling is not (SipralTransport.Udp or SipralTransport.Tcp or SipralTransport.Tls))
        {
            throw new ArgumentException("signalling is Udp, Tcp or Tls", nameof(signalling));
        }
        _bindHost = bindHost;
        _givenTlsServerName = tlsServerName;
        _tlsTrust = tlsTrust ?? SipralTlsTrust.Platform;
        if (!Streamed)
        {
            return (null, null);
        }
        if (signallingServer is null)
        {
            throw new ArgumentException("SIP over TCP or TLS needs signallingServer, host:port", nameof(signallingServer));
        }
        _server = ParseAddress(signallingServer);
        _serverName = tlsServerName ?? _server.Value.Host;
        _tlsTrust = tlsTrust ?? SipralTlsTrust.Platform;
        try
        {
            return (Connect(bindHost), null);
        }
        catch (SignallingRefusedException refused)
        {
            return (null, refused);
        }
    }

    private void StartSignalling(Link? link, SignallingRefusedException? refused)
    {
        if (link is not null)
        {
            Install(link);
        }
        else if (Streamed)
        {
            Report(refused ?? new SignallingRefusedException(SipralTransportError.Other, SipralTlsFailure.None, "no connection"));
            ReconnectLater();
        }
    }

    private Link Connect(string? bindHost)
    {
        var (host, port) = _server!.Value;
        TcpClient? client = null;
        try
        {
            var address = IPAddress.Parse(host);
            client = new TcpClient(address.AddressFamily) { NoDelay = true };
            if (bindHost is not null)
            {
                client.Client.Bind(new IPEndPoint(IPAddress.Parse(bindHost), 0));
            }
            try
            {
                if (!client.ConnectAsync(address, port).Wait(SignallingPatience))
                {
                    throw new SignallingRefusedException(SipralTransportError.TimedOut, SipralTlsFailure.None,
                        $"no connection to {host}:{port} in {SignallingPatience.TotalSeconds} seconds");
                }
            }
            catch (AggregateException wrapped) when (wrapped.InnerException is SocketException socket)
            {
                throw Refused(socket);
            }
            Stream carried = client.GetStream();
            if (_signalling == SipralTransport.Tls)
            {
                var tls = new SslStream(carried, leaveInnerStreamOpen: false);
                var verdict = new SipralTlsTrust.Verdict();
                var options = new SslClientAuthenticationOptions { TargetHost = _serverName };
                _tlsTrust.Apply(options, verdict);
                try
                {
                    tls.AuthenticateAsClient(options);
                }
                catch (Exception ex) when (ex is AuthenticationException or IOException)
                {
                    tls.Dispose();
                    throw Refused(verdict, ex);
                }
                carried = tls;
            }
            client.ReceiveTimeout = 0;
            client.SendTimeout = (int)SignallingPatience.TotalMilliseconds;
            return new Link
            {
                Client = client,
                Stream = carried,
                Local = FormatAddress((IPEndPoint)client.Client.LocalEndPoint!),
                Remote = FormatAddress((IPEndPoint)client.Client.RemoteEndPoint!),
            };
        }
        catch (SignallingRefusedException)
        {
            client?.Dispose();
            throw;
        }
        catch (Exception ex) when (ex is SocketException or FormatException or IOException)
        {
            client?.Dispose();
            throw ex is SocketException socket
                ? Refused(socket)
                : new SignallingRefusedException(SipralTransportError.Other, SipralTlsFailure.None, Sentence(ex.Message));
        }
    }

    // A refused certificate is untrusted, expired or a name mismatch; any
    // other handshake failure is "handshake refused".
    internal static SignallingRefusedException Refused(SipralTlsTrust.Verdict verdict, Exception ex)
    {
        const X509ChainStatusFlags untrusted = X509ChainStatusFlags.UntrustedRoot
            | X509ChainStatusFlags.PartialChain | X509ChainStatusFlags.NotSignatureValid
            | X509ChainStatusFlags.ExplicitDistrust | X509ChainStatusFlags.Revoked;
        const X509ChainStatusFlags expired = X509ChainStatusFlags.NotTimeValid | X509ChainStatusFlags.NotTimeNested;
        if (verdict.Errors is not { } errors || errors == SslPolicyErrors.None)
        {
            return new SignallingRefusedException(SipralTransportError.ConnectionReset,
                SipralTlsFailure.HandshakeRefused, Sentence(ex.Message));
        }
        SipralTlsFailure tls;
        if ((verdict.Chain & untrusted) != 0)
        {
            tls = SipralTlsFailure.Untrusted;
        }
        else if ((verdict.Chain & expired) != 0)
        {
            tls = SipralTlsFailure.Expired;
        }
        else if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            tls = SipralTlsFailure.NameMismatch;
        }
        else if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
        {
            tls = SipralTlsFailure.HandshakeRefused;
        }
        else
        {
            tls = SipralTlsFailure.Untrusted;
        }
        return new SignallingRefusedException(SipralTransportError.ConnectionReset, tls, Sentence(verdict.Detail));
    }

    internal static SignallingRefusedException Refused(SocketException socket)
    {
        var error = socket.SocketErrorCode switch
        {
            SocketError.ConnectionRefused => SipralTransportError.ConnectionRefused,
            SocketError.TimedOut => SipralTransportError.TimedOut,
            SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.NetworkDown
                or SocketError.HostDown => SipralTransportError.Unreachable,
            SocketError.ConnectionReset or SocketError.ConnectionAborted or SocketError.Shutdown =>
                SipralTransportError.ConnectionReset,
            _ => SipralTransportError.Other,
        };
        return new SignallingRefusedException(error, SipralTlsFailure.None, Sentence(socket.Message));
    }

    // One line, at most SIPRAL_TRANSPORT_DETAIL_BYTES of UTF-8.
    private static string Sentence(string text)
    {
        var line = new string(text.Select(ch => char.IsControl(ch) ? ' ' : ch).ToArray()).Trim();
        var limit = (int)global::Sipral.Sipral.TransportDetailBytes;
        while (Encoding.UTF8.GetByteCount(line) > limit)
        {
            line = line[..^1];
        }
        return line;
    }

    private void Report(SignallingRefusedException refused)
    {
        var detail = Encoding.UTF8.GetBytes(refused.Message);
        var pinned = GCHandle.Alloc(detail, GCHandleType.Pinned);
        try
        {
            var failure = SipralTransportFailure.Sized();
            failure.Transport = global::Sipral.Sipral.TransportMain;
            failure.Error = (uint)refused.Error;
            failure.Tls = _signalling == SipralTransport.Tls ? (uint)refused.Tls : (uint)SipralTlsFailure.None;
            failure.Detail = detail.Length == 0 ? IntPtr.Zero : pinned.AddrOfPinnedObject();
            failure.DetailLen = (nuint)detail.Length;
            SipralErrors.Call(() => NativeMethods.sipral_stack_transport_failed_with(Handle, in failure, NowMs),
                "sipral_stack_transport_failed_with");
        }
        catch (Exception ex) when (ex is SipralException or ObjectDisposedException)
        {
            // the stack is going away
        }
        finally
        {
            pinned.Free();
        }
    }

    private void Install(Link link)
    {
        var local = ToSBytes(link.Local);
        var remote = ToSBytes(link.Remote);
        try
        {
            SipralErrors.Call(
                () => NativeMethods.sipral_stack_transport_bind(
                    Handle, global::Sipral.Sipral.TransportMain, (uint)_signalling, local, (nuint)local.Length,
                    remote, (nuint)remote.Length, NowMs, out _),
                "sipral_stack_transport_bind");
        }
        catch
        {
            link.Stream.Dispose();
            link.Client.Dispose();
            throw;
        }
        BindAddress = link.Local;
        _link = link;
        new Thread(() => ReadLink(link)) { IsBackground = true, Name = "sipral-signalling" }.Start();
    }

    // A busy stack is waited for, not skipped: a stream that loses a byte
    // never resyncs.
    private void ReadLink(Link link)
    {
        var buffer = new byte[TransmitBytes];
        while (!_closed.IsSet)
        {
            int read;
            try
            {
                read = link.Stream.Read(buffer, 0, buffer.Length);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or SocketException)
            {
                var socket = ex as SocketException ?? ex.InnerException as SocketException;
                LoseLink(link, socket is not null
                    ? Refused(socket)
                    : new SignallingRefusedException(SipralTransportError.ConnectionReset, SipralTlsFailure.None,
                        Sentence(ex.Message)));
                return;
            }
            if (read == 0)
            {
                LoseLink(link, null);
                return;
            }
            var bytes = buffer.AsSpan(0, read).ToArray();
            var status = SipralStatus.Busy;
            while (!_closed.IsSet)
            {
                status = NativeMethods.sipral_stack_receive_stream(
                    Handle, global::Sipral.Sipral.TransportMain, bytes, (nuint)bytes.Length, NowMs);
                if (status != SipralStatus.Busy)
                {
                    break;
                }
                Thread.Sleep(1);
            }
            if (status != SipralStatus.Ok && status != SipralStatus.Busy)
            {
                // framing lost: the stack retired the transport itself
                LoseLink(link, null, tell: false);
                return;
            }
        }
    }

    // A failed write loses the connection.
    private void WriteLink(byte[] payload)
    {
        var link = Volatile.Read(ref _link);
        if (link is null)
        {
            return;
        }
        try
        {
            lock (link.WriteLock)
            {
                link.Stream.Write(payload, 0, payload.Length);
                link.Stream.Flush();
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or SocketException)
        {
            var socket = ex as SocketException ?? ex.InnerException as SocketException;
            LoseLink(link, socket is not null
                ? Refused(socket)
                : new SignallingRefusedException(SipralTransportError.ConnectionReset, SipralTlsFailure.None,
                    Sentence(ex.Message)));
        }
    }

    // Closes the link if still current, reports stream_closed (refused
    // null) or transport_failed_with (unless !tell), and reconnects.
    private void LoseLink(Link link, SignallingRefusedException? refused, bool tell = true)
    {
        if (Interlocked.CompareExchange(ref _link, null, link) != link)
        {
            return;
        }
        lock (link.WriteLock)
        {
            link.Stream.Dispose();
            link.Client.Dispose();
        }
        if (_closed.IsSet)
        {
            return;
        }
        if (tell && refused is null)
        {
            try
            {
                SipralErrors.Call(
                    () => NativeMethods.sipral_stack_stream_closed(Handle, global::Sipral.Sipral.TransportMain, NowMs),
                    "sipral_stack_stream_closed");
            }
            catch (Exception ex) when (ex is SipralException or ObjectDisposedException)
            {
            }
        }
        else if (tell)
        {
            Report(refused!);
        }
        ReconnectLater();
    }

    // Set when the stack retired the main TCP/TLS transport for missed
    // keep-alives (RFC 5626 §4.4.1) while the socket is still open here.
    // Poll thread only.
    private bool _mainLetGo;

    private void ActOnMainLetGo()
    {
        if (!_mainLetGo)
        {
            return;
        }
        _mainLetGo = false;
        if (Volatile.Read(ref _link) is { } link)
        {
            LoseLink(link, null, tell: false);
        }
    }

    private void ReconnectLater()
    {
        if (_closed.IsSet || Interlocked.Exchange(ref _reconnecting, 1) != 0)
        {
            return;
        }
        new Thread(Reconnect) { IsBackground = true, Name = "sipral-reconnect" }.Start();
    }

    private void Reconnect()
    {
        var delay = ReconnectFirst;
        try
        {
            while (!_closed.Wait(delay))
            {
                delay = delay * 2 > ReconnectMost ? ReconnectMost : delay * 2;
                Link link;
                try
                {
                    link = Connect(_bindHost);
                }
                catch (SignallingRefusedException refused)
                {
                    Report(refused);
                    continue;
                }
                if (_closed.IsSet)
                {
                    link.Stream.Dispose();
                    link.Client.Dispose();
                    return;
                }
                try
                {
                    Install(link);
                }
                catch (SipralException)
                {
                    continue;
                }
                AfterReconnect();
                return;
            }
        }
        finally
        {
            Interlocked.Exchange(ref _reconnecting, 0);
        }
    }

    // Accounts without their own Contact move to the new address; those
    // registering register again now, not at their next back-off.
    private void AfterReconnect()
    {
        List<Account> accounts;
        lock (_accounts)
        {
            accounts = _accounts.ToList();
        }
        foreach (var account in accounts)
        {
            try
            {
                if (!account.ContactGiven)
                {
                    account.Rebind();
                }
                if (account.WantsRegistration)
                {
                    account.Register();
                }
            }
            catch (SipralException)
            {
                // the next loss or refresh retries
            }
        }
    }

    // For MoveTo: the old connection belongs to a network we left. On
    // failure the stack is told and reconnection continues.
    private void MoveLink(string host)
    {
        _bindHost = host;
        var old = Interlocked.Exchange(ref _link, null);
        if (old is not null)
        {
            lock (old.WriteLock)
            {
                old.Stream.Dispose();
                old.Client.Dispose();
            }
        }
        try
        {
            Install(Connect(host));
        }
        catch (SignallingRefusedException refused)
        {
            BindAddress = $"{host}:0";
            Report(refused);
            ReconnectLater();
        }
    }

    private void CloseLink()
    {
        var link = Interlocked.Exchange(ref _link, null);
        if (link is null)
        {
            return;
        }
        lock (link.WriteLock)
        {
            link.Stream.Dispose();
            link.Client.Dispose();
        }
    }
}
