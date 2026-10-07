// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Sipral;

/// <summary>The pinned certificate's dates (Unix seconds, zero when
/// unreadable) and validity. It is accepted either way; warn on an expired
/// one.</summary>
public sealed record SipralPinnedCertificateInfo(ulong NotBefore, ulong NotAfter, bool Expired, bool NotYetValid);

internal sealed record AccountLocation(
    string? ServerUri, bool ServerNaptr, ulong KeepaliveMs, string? TlsPin, string? Advertised,
    SipralTransport StreamProtocol = 0, IEnumerable<string>? Realms = null,
    string? WebsocketHost = null, string? WebsocketResource = null);

/// <summary>
/// One <c>sipral_account_add</c> handle. Built through
/// <see cref="SipralStack.AddAccount"/>, since a handle only means something
/// on the stack that minted it.
/// </summary>
public sealed class Account
{
    private readonly SipralStack _stack;
    private readonly AccountSafeHandle _handle;

    /// <summary>The address of record this account was added with.</summary>
    public string Aor { get; }

    /// <summary>Where requests go, <c>host:port</c>. With a <c>serverUri</c>,
    /// the last located address, empty until then.</summary>
    public string RegistrarAddress { get; private set; }

    /// <summary>The server named by a URI RFC 3263 locates, or
    /// <see langword="null"/>.</summary>
    public string? ServerUri { get; }

    /// <summary>The account's own connection protocol (TCP or TLS), or zero
    /// for the stack's transport.</summary>
    public SipralTransport StreamProtocol { get; }

    internal string? TlsPin { get; }

    // The Contact's transport parameter (RFC 3261 §19.1.1).
    private static string ContactParametersOf(SipralStack stack, SipralTransport streamProtocol) => streamProtocol switch
    {
        SipralTransport.Tcp => ";transport=tcp",
        SipralTransport.Tls => ";transport=tls",
        SipralTransport.Ws => ";transport=ws",
        SipralTransport.Wss => ";transport=wss",
        _ => stack.ContactParameters,
    };

    /// <summary>The <c>host:port</c> its <c>Contact</c> names, when this layer
    /// chose it.</summary>
    public string? Advertised { get; private set; }

    /// <summary>Whether it was added with a <c>Contact</c> of its own, which
    /// <see cref="SipralStack.MoveTo"/> then leaves to the application.</summary>
    public bool ContactGiven { get; }

    /// <summary>The raw <c>sipral_handle_t</c>, for entry points this class
    /// does not wrap. Valid until <see cref="Remove"/>.</summary>
    public ulong Handle => _handle.Value;

    private Account(
        SipralStack stack, ulong handle, string aor, string registrarAddress, bool contactGiven, string? serverUri,
        string? advertised, SipralTransport streamProtocol, string? tlsPin)
    {
        StreamProtocol = streamProtocol;
        TlsPin = tlsPin;
        _stack = stack;
        _handle = new AccountSafeHandle();
        _handle.Attach(stack.Handle, handle);
        Aor = aor;
        RegistrarAddress = registrarAddress;
        ContactGiven = contactGiven;
        ServerUri = serverUri;
        Advertised = advertised;
    }

    internal void Located(string target) => RegistrarAddress = target;

    internal void Reach(string advertised, string remote)
    {
        if (advertised == (Advertised ?? _stack.BindAddress))
        {
            return;
        }
        Rebind(remote, DefaultContact(Aor, advertised, ContactParametersOf(_stack, StreamProtocol)));
        Advertised = advertised;
    }

    // Always rebinds: the stack moved even if the route did not.
    internal void Readvertise(string advertised)
    {
        Rebind(RegistrarAddress, DefaultContact(Aor, advertised, ContactParametersOf(_stack, StreamProtocol)));
        Advertised = advertised;
    }

    /// <summary><c>sipral_account_check_certificate</c>: judge a server's leaf
    /// certificate (DER) against <c>tlsPin</c>, from the application's own
    /// TLS check. Returns its dates when it is the pinned one (accept it,
    /// whoever signed it, even expired); <see langword="null"/> when nothing
    /// is pinned and the platform decides; throws with
    /// <see cref="SipralStatus.CertificateRefused"/> otherwise.</summary>
    public SipralPinnedCertificateInfo? CheckCertificate(byte[] certificate, ulong? unixSeconds = null)
    {
        var now = unixSeconds ?? (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var found = SipralPinnedCertificate.Sized();
        SipralErrors.Call(
            () => NativeMethods.sipral_account_check_certificate(
                _stack.Handle, Handle, certificate, (nuint)certificate.Length, now, ref found),
            "sipral_account_check_certificate");
        return found.Pinned == 0
            ? null
            : new SipralPinnedCertificateInfo(found.NotBefore, found.NotAfter, found.Expired != 0, found.NotYetValid != 0);
    }

    internal static Account Add(
        SipralStack stack,
        string aor,
        string? registrarAddress,
        string? registrar,
        string? contact,
        string? displayName,
        string? authUser,
        string? authPassword,
        ulong expiresSeconds,
        SipralSessionTimer sessionTimer,
        ulong sessionIntervalSeconds,
        uint privacy,
        IEnumerable<string>? trustedPeers,
        AccountSecurity? security,
        AccountLocation location)
    {
        security ??= new AccountSecurity();
        var peersBytes = trustedPeers is null ? null : Encoding.UTF8.GetBytes(string.Join(", ", trustedPeers));
        var suitesBytes = security.SrtpSuites is null ? null : Encoding.UTF8.GetBytes(string.Join(",", security.SrtpSuites));
        var stirUrlBytes = security.StirCertificateUrl is null ? null : Encoding.UTF8.GetBytes(security.StirCertificateUrl);
        var stirOrigBytes = security.StirOrig is null ? null : Encoding.UTF8.GetBytes(security.StirOrig);
        var stirOrigidBytes = security.StirOrigid is null ? null : Encoding.UTF8.GetBytes(security.StirOrigid);
        var aorBytes = Encoding.UTF8.GetBytes(aor);
        var registrarAddressBytes = registrarAddress is null ? null : Encoding.UTF8.GetBytes(registrarAddress);
        var registrarBytes = registrar is null ? null : Encoding.UTF8.GetBytes(registrar);
        var contactBytes = Encoding.UTF8.GetBytes(
            contact ?? DefaultContact(aor, location.Advertised ?? stack.BindAddress,
                ContactParametersOf(stack, location.StreamProtocol)));
        var serverUriBytes = location.ServerUri is null ? null : Encoding.UTF8.GetBytes(location.ServerUri);
        var pinBytes = location.TlsPin is null ? null : Encoding.UTF8.GetBytes(location.TlsPin);
        var realmsBytes = location.Realms is null ? null : Encoding.UTF8.GetBytes(string.Join("\n", location.Realms));
        var websocketHostBytes = location.WebsocketHost is null ? null : Encoding.UTF8.GetBytes(location.WebsocketHost);
        var websocketResourceBytes = location.WebsocketResource is null
            ? null
            : Encoding.UTF8.GetBytes(location.WebsocketResource);
        var displayNameBytes = displayName is null ? null : Encoding.UTF8.GetBytes(displayName);
        var authUserBytes = authUser is null ? null : Encoding.UTF8.GetBytes(authUser);
        var authPasswordBytes = authPassword is null ? null : Encoding.UTF8.GetBytes(authPassword);

        ulong accountHandle = 0;
        using (var aorPin = Pin(aorBytes))
        using (var registrarAddressPin = Pin(registrarAddressBytes))
        using (var registrarPin = Pin(registrarBytes))
        using (var contactPin = Pin(contactBytes))
        using (var displayNamePin = Pin(displayNameBytes))
        using (var authUserPin = Pin(authUserBytes))
        using (var authPasswordPin = Pin(authPasswordBytes))
        using (var peersPin = Pin(peersBytes))
        using (var suitesPin = Pin(suitesBytes))
        using (var stirKeyPin = Pin(security.StirKey))
        using (var stirUrlPin = Pin(stirUrlBytes))
        using (var stirOrigPin = Pin(stirOrigBytes))
        using (var stirOrigidPin = Pin(stirOrigidBytes))
        using (var serverUriPin = Pin(serverUriBytes))
        using (var pinPin = Pin(pinBytes))
        using (var realmsPin = Pin(realmsBytes))
        using (var websocketHostPin = Pin(websocketHostBytes))
        using (var websocketResourcePin = Pin(websocketResourceBytes))
        {
            var config = SipralAccountConfig.Sized();
            config.Aor = aorPin.Pointer;
            config.AorLen = (nuint)aorBytes.Length;
            if (registrarBytes is not null)
            {
                config.Registrar = registrarPin.Pointer;
                config.RegistrarLen = (nuint)registrarBytes.Length;
            }
            config.RegistrarAddress = registrarAddressPin.Pointer;
            config.RegistrarAddressLen = (nuint)(registrarAddressBytes?.Length ?? 0);
            config.ServerUri = serverUriPin.Pointer;
            config.ServerUriLen = (nuint)(serverUriBytes?.Length ?? 0);
            config.ServerNaptr = location.ServerNaptr ? (uint)SipralToggle.On : 0;
            config.KeepaliveMs = location.KeepaliveMs;
            config.StreamProtocol = (uint)location.StreamProtocol;
            config.TlsPinSha256 = pinPin.Pointer;
            config.TlsPinSha256Len = (nuint)(pinBytes?.Length ?? 0);
            if (realmsBytes is { Length: > 0 })
            {
                config.Realms = realmsPin.Pointer;
                config.RealmsLen = (nuint)realmsBytes.Length;
            }
            if (websocketHostBytes is not null)
            {
                config.WebsocketHost = websocketHostPin.Pointer;
                config.WebsocketHostLen = (nuint)websocketHostBytes.Length;
            }
            if (websocketResourceBytes is not null)
            {
                config.WebsocketResource = websocketResourcePin.Pointer;
                config.WebsocketResourceLen = (nuint)websocketResourceBytes.Length;
            }
            config.Contact = contactPin.Pointer;
            config.ContactLen = (nuint)contactBytes.Length;
            if (displayNameBytes is not null)
            {
                config.DisplayName = displayNamePin.Pointer;
                config.DisplayNameLen = (nuint)displayNameBytes.Length;
            }
            if (authUserBytes is not null)
            {
                config.AuthUser = authUserPin.Pointer;
                config.AuthUserLen = (nuint)authUserBytes.Length;
            }
            if (authPasswordBytes is not null)
            {
                config.AuthPassword = authPasswordPin.Pointer;
                config.AuthPasswordLen = (nuint)authPasswordBytes.Length;
            }
            config.ExpiresSeconds = expiresSeconds;
            config.SessionTimer = (uint)sessionTimer;
            config.SessionIntervalSeconds = sessionIntervalSeconds;
            config.Privacy = privacy;
            if (peersBytes is { Length: > 0 })
            {
                config.TrustedPeers = peersPin.Pointer;
                config.TrustedPeersLen = (nuint)peersBytes.Length;
            }
            config.Srtp = (uint)security.Srtp;
            if (suitesBytes is { Length: > 0 })
            {
                config.SrtpSuites = suitesPin.Pointer;
                config.SrtpSuitesLen = (nuint)suitesBytes.Length;
            }
            config.StirVerification = (uint)security.StirVerification;
            if (security.StirKey is { Length: > 0 })
            {
                config.StirKey = stirKeyPin.Pointer;
                config.StirKeyLen = (nuint)security.StirKey.Length;
            }
            if (stirUrlBytes is not null)
            {
                config.StirCertificateUrl = stirUrlPin.Pointer;
                config.StirCertificateUrlLen = (nuint)stirUrlBytes.Length;
            }
            if (stirOrigBytes is not null)
            {
                config.StirOrig = stirOrigPin.Pointer;
                config.StirOrigLen = (nuint)stirOrigBytes.Length;
            }
            if (stirOrigidBytes is not null)
            {
                config.StirOrigid = stirOrigidPin.Pointer;
                config.StirOrigidLen = (nuint)stirOrigidBytes.Length;
            }
            config.StirAttestation = (uint)security.StirAttestation;
            config.RecordingInClear = security.RecordingInClear ? (uint)SipralToggle.On : 0;

            SipralErrors.Call(() => NativeMethods.sipral_account_add(stack.Handle, config, out accountHandle), "sipral_account_add");
        }

        return new Account(
            stack, accountHandle, aor, registrarAddress ?? string.Empty, contact is not null, location.ServerUri,
            location.Advertised, location.StreamProtocol, location.TlsPin);
    }

    /// <summary><c>sipral_account_rebind</c> after a network change: point
    /// the account at <paramref name="remote"/> (default: its original
    /// address) and <paramref name="contact"/> (default: the AOR's user at
    /// the stack's address). The next REGISTER uses both.</summary>
    public void Rebind(string? remote = null, string? contact = null)
    {
        var remoteBytes = Interop.NativeText.ToSBytes(remote ?? RegistrarAddress);
        var contactBytes = Interop.NativeText.ToSBytes(
            contact ?? DefaultContact(Aor, _stack.BindAddress, ContactParametersOf(_stack, StreamProtocol)));
        SipralErrors.Call(
            () => NativeMethods.sipral_account_rebind(
                _stack.Handle, Handle, global::Sipral.Sipral.TransportMain, remoteBytes, (nuint)remoteBytes.Length,
                contactBytes, (nuint)contactBytes.Length, _stack.NowMs),
            "sipral_account_rebind");
    }

    /// <summary>The default <c>Contact</c>: the AOR's user at this stack's
    /// address. The AOR itself names who this is, not a reachable socket.
    /// <paramref name="parameters"/> follows, e.g. <c>;transport=tls</c>.</summary>
    private static string DefaultContact(string aor, string bindAddress, string parameters)
    {
        var colon = aor.IndexOf(':');
        if (colon < 0)
        {
            return $"sip:{bindAddress}{parameters}";
        }
        var scheme = aor[..colon];
        var rest = aor[(colon + 1)..];
        var at = rest.IndexOf('@');
        return at < 0 ? $"{scheme}:{bindAddress}{parameters}" : $"{scheme}:{rest[..at]}@{bindAddress}{parameters}";
    }

    /// <summary>Whether registration was asked for and not undone; such
    /// accounts register again when a TCP/TLS stack reconnects.</summary>
    public bool WantsRegistration { get; private set; }

    /// <summary><c>sipral_account_register</c>. Refused by an account with
    /// no registrar. While a TCP/TLS connection is down, the request is kept
    /// and sent on reconnect.</summary>
    public void Register()
    {
        WantsRegistration = true;
        try
        {
            SipralErrors.Call(() => NativeMethods.sipral_account_register(_stack.Handle, Handle, _stack.NowMs), "sipral_account_register");
        }
        catch (SipralException refused) when (refused.Status == SipralStatus.TransportDown)
        {
        }
    }

    /// <summary><c>sipral_account_set_access_token</c>: set or replace the
    /// OAuth 2.0 token (RFC 8898), <c>null</c> to remove it. Answers
    /// <see cref="SipralEventKind.TokenRequired"/> and installs renewals; the
    /// next <c>Bearer</c> challenge uses it. A registration that failed for
    /// want of a token restarts with <see cref="Register"/>. Throws
    /// <see cref="SipralStatus.InvalidArgument"/> for a token that is not an
    /// RFC 6750 <c>b64token</c>. The marshalled copy is cleared.</summary>
    public void SetAccessToken(string? token)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(token ?? "");
        var signed = (sbyte[])(Array)bytes;
        try
        {
            SipralErrors.Call(
                () => NativeMethods.sipral_account_set_access_token(_stack.Handle, Handle, signed, (nuint)signed.Length),
                "sipral_account_set_access_token");
        }
        finally
        {
            Array.Clear(bytes);
        }
    }

    /// <summary><c>sipral_account_refresh_binding</c>: refresh the
    /// registration now (RFC 8599 §5.5), e.g. on a push wake-up, dropping
    /// any back-off. Nothing is sent while a REGISTER is in flight or after
    /// an unfixable refusal such as a wrong password. An account with no
    /// registrar gets <see cref="SipralStatus.InvalidArgument"/>.</summary>
    public void RefreshBinding()
    {
        SipralErrors.Call(
            () => NativeMethods.sipral_account_refresh_binding(_stack.Handle, Handle, _stack.NowMs),
            "sipral_account_refresh_binding");
    }

    /// <summary><c>sipral_account_unregister</c>.</summary>
    /// <remarks>
    /// Sends REGISTER with Expires: 0. The state reads unregistered at once;
    /// the registrar's answer arrives as a later event. Wait for it before
    /// closing the stack, or a challenge to the un-REGISTER goes unanswered.
    /// </remarks>
    public void Unregister()
    {
        WantsRegistration = false;
        SipralErrors.Call(() => NativeMethods.sipral_account_unregister(_stack.Handle, Handle, _stack.NowMs), "sipral_account_unregister");
    }

    /// <summary><c>sipral_account_registration_state</c>.</summary>
    public SipralRegistrationState RegistrationState()
    {
        uint state = 0;
        SipralErrors.Call(() => NativeMethods.sipral_account_registration_state(_stack.Handle, Handle, out state), "sipral_account_registration_state");
        return (SipralRegistrationState)state;
    }

    /// <summary>
    /// <c>sipral_account_subscribe</c>: watch <paramref name="target"/>
    /// through event <paramref name="package"/> (e.g. <c>dialog</c>),
    /// optionally via <paramref name="destination"/>.
    /// <paramref name="expiresSeconds"/> zero means an hour. Notifications
    /// arrive as events naming <see cref="SipralSubscription.Handle"/>.
    /// </summary>
    public SipralSubscription Subscribe(string target, string package, string? accept = null, uint expiresSeconds = 0, string? destination = null)
    {
        var targetBytes = Encoding.UTF8.GetBytes(target);
        var packageBytes = Encoding.UTF8.GetBytes(package);
        var acceptBytes = accept is null ? null : Encoding.UTF8.GetBytes(accept);
        var destinationBytes = destination is null ? null : Encoding.UTF8.GetBytes(destination);
        ulong subscription = 0;
        using (var targetPin = Pin(targetBytes))
        using (var packagePin = Pin(packageBytes))
        using (var acceptPin = Pin(acceptBytes))
        using (var destinationPin = Pin(destinationBytes))
        {
            var config = SipralSubscribeConfig.Sized();
            config.Target = targetPin.Pointer;
            config.TargetLen = (nuint)targetBytes.Length;
            config.Package = packagePin.Pointer;
            config.PackageLen = (nuint)packageBytes.Length;
            config.Accept = acceptPin.Pointer;
            config.AcceptLen = (nuint)(acceptBytes?.Length ?? 0);
            config.ExpiresSeconds = expiresSeconds;
            config.Destination = destinationPin.Pointer;
            config.DestinationLen = (nuint)(destinationBytes?.Length ?? 0);
            SipralErrors.Call(
                () => NativeMethods.sipral_account_subscribe(_stack.Handle, Handle, config, out subscription, _stack.NowMs),
                "sipral_account_subscribe");
        }
        return new SipralSubscription(_stack, subscription, package);
    }

    /// <summary>Watch a presentity (RFC 3856). Each document arrives as
    /// <see cref="SipralEventKind.PresenceChanged"/> with
    /// <see cref="SipralPresenceKind.Watched"/>.</summary>
    public SipralSubscription WatchPresence(string target, uint expiresSeconds = 0, string? destination = null) =>
        Subscribe(target, "presence", expiresSeconds: expiresSeconds, destination: destination);

    /// <summary>
    /// <c>sipral_account_publish_presence</c> (RFC 3903). Later calls modify
    /// the same publication, refreshed until <see cref="UnpublishPresence"/>.
    /// <see cref="SipralActivity.Other"/> is refused (it has no name).
    /// Results arrive as <see cref="SipralEventKind.PresenceChanged"/> with
    /// <see cref="SipralPresenceKind.Publication"/>.
    /// </summary>
    public void PublishPresence(SipralBasic basic, SipralActivity activity = SipralActivity.None, string? note = null)
    {
        var noteBytes = note is null ? null : Encoding.UTF8.GetBytes(note);
        using var notePin = Pin(noteBytes);
        var presence = SipralPresence.Sized();
        presence.Basic = (uint)basic;
        presence.Activity = (uint)activity;
        presence.Note = notePin.Pointer;
        presence.NoteLen = (nuint)(noteBytes?.Length ?? 0);
        SipralErrors.Call(
            () => NativeMethods.sipral_account_publish_presence(_stack.Handle, Handle, presence, _stack.NowMs),
            "sipral_account_publish_presence");
    }

    /// <summary><c>sipral_account_unpublish_presence</c>: take the published
    /// presence away (RFC 3903 §4.5); <see cref="SipralPublicationState.Removed"/>
    /// says when it is gone. <see cref="SipralStatus.WrongState"/> when nothing
    /// was published.</summary>
    public void UnpublishPresence()
    {
        SipralErrors.Call(
            () => NativeMethods.sipral_account_unpublish_presence(_stack.Handle, Handle, _stack.NowMs),
            "sipral_account_unpublish_presence");
    }

    /// <summary><c>sipral_account_remove</c>. The account's placed calls
    /// end.</summary>
    public void Remove()
    {
        if (!_handle.IsClosed)
        {
            SipralErrors.Call(() => NativeMethods.sipral_account_remove(_stack.Handle, Handle), "sipral_account_remove");
            // released above: the finalizer must not release it again
            _handle.SetHandleAsInvalid();
        }
        _stack.ForgetAccount(this);
    }

    private static Interop.PinnedBytes Pin(byte[]? bytes) => new(bytes);
}

/// <summary>Per-account SRTP and STIR/SHAKEN settings for
/// <see cref="SipralStack.AddAccount"/>.
///
/// <see cref="Srtp"/> overrides the stack's policy (zero keeps it); a call
/// may ask for more, never less. <see cref="SrtpSuites"/> are by RFC 4568 /
/// RFC 7714 name, most preferred first; GCM suites only if named.
/// <see cref="StirVerification"/> applies once <see cref="SipralStack.Stir"/>
/// set anchors. <see cref="StirKey"/> (P-256: raw 32 bytes, SEC1 or PKCS #8,
/// DER or PEM) with <see cref="StirCertificateUrl"/> signs placed calls (RFC
/// 8224) as <see cref="StirOrig"/> or the AOR's number, with
/// <see cref="StirAttestation"/> (<see cref="SipralAttestation.None"/> means
/// A) and <see cref="StirOrigid"/> (generated if absent). Signing needs the
/// clock <see cref="SipralStack.Stir"/> gives, so call it first.
/// <see cref="RecordingInClear"/> lets encrypted calls be recorded as plain
/// RTP; otherwise copies go as SRTP or not at all (RFC 7866 §12.2).</summary>
public sealed record AccountSecurity(
    SipralSrtp Srtp = 0,
    IReadOnlyList<string>? SrtpSuites = null,
    SipralStirVerification StirVerification = SipralStirVerification.Default,
    byte[]? StirKey = null,
    string? StirCertificateUrl = null,
    string? StirOrig = null,
    string? StirOrigid = null,
    SipralAttestation StirAttestation = SipralAttestation.None,
    bool RecordingInClear = false);
