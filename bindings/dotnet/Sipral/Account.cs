// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Sipral;

/// <summary>What <see cref="Account.CheckCertificate"/> found in the
/// certificate the account pins: its dates, in seconds since 1970 (zero when
/// its DER could not be read that far), and whether the clock is past or
/// before them. Accepted either way; an expired one is worth a
/// warning.</summary>
public sealed record SipralPinnedCertificateInfo(ulong NotBefore, ulong NotAfter, bool Expired, bool NotYetValid);

/// <summary>How an account names and keeps its server, beside the
/// registrar's address: the ABI 0.34 members of
/// <c>sipral_account_config_t</c>, and the address this layer chose for its
/// <c>Contact</c>.</summary>
internal sealed record AccountLocation(
    string? ServerUri, bool ServerNaptr, ulong KeepaliveMs, string? TlsPin, string? Advertised,
    SipralTransport StreamProtocol = 0, IEnumerable<string>? Realms = null);

/// <summary>
/// One <c>sipral_account_add</c> handle, and the entry points that take
/// it.
///
/// Built through <see cref="SipralStack.AddAccount"/>, never directly: a
/// handle only means something on the stack that minted it
/// (<c>docs/08-ffi.md</c>, "A handle names something only on the stack
/// that minted it"), so keeping the two together is what makes every
/// method here safe to call with nothing further to pass.
/// </summary>
public sealed class Account
{
    private readonly SipralStack _stack;
    private readonly AccountSafeHandle _handle;

    /// <summary>The address of record this account was added with.</summary>
    public string Aor { get; }

    /// <summary>Where this account's requests go, <c>host:port</c>: the
    /// registrar or the outbound proxy it was added with, or — for one added
    /// with a <c>serverUri</c> — the address it was last located at, empty
    /// until then.</summary>
    public string RegistrarAddress { get; private set; }

    /// <summary>The server named by a URI RFC 3263 locates, or
    /// <see langword="null"/>.</summary>
    public string? ServerUri { get; }

    /// <summary>The protocol of the connection of its own the account's
    /// requests go over, <see cref="SipralTransport.Tcp"/> or
    /// <see cref="SipralTransport.Tls"/>, or zero for the stack's own
    /// transport (<see cref="SipralStack.AddAccount"/>'s
    /// <c>streamProtocol</c>).</summary>
    public SipralTransport StreamProtocol { get; }

    /// <summary>The certificate pin it was added with, which a TLS connection
    /// of its own is held to.</summary>
    internal string? TlsPin { get; }

    /// <summary>What goes after the address in the <c>Contact</c> this layer
    /// derives for it: the parameter naming its own connection's protocol
    /// (RFC 3261 §19.1.1), or the stack's.</summary>
    private static string ContactParametersOf(SipralStack stack, SipralTransport streamProtocol) => streamProtocol switch
    {
        SipralTransport.Tcp => ";transport=tcp",
        SipralTransport.Tls => ";transport=tls",
        _ => stack.ContactParameters,
    };

    /// <summary>The <c>host:port</c> its <c>Contact</c> names, when this layer
    /// chose it.</summary>
    public string? Advertised { get; private set; }

    /// <summary>Whether it was added with a <c>Contact</c> of its own, which
    /// <see cref="SipralStack.MoveTo"/> then leaves to the application.</summary>
    public bool ContactGiven { get; }

    internal ulong Handle => _handle.Value;

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

    /// <summary>The account's server was located at
    /// <paramref name="target"/>.</summary>
    internal void Located(string target) => RegistrarAddress = target;

    /// <summary><c>sipral_account_rebind</c> toward <paramref name="remote"/>,
    /// reached at <paramref name="advertised"/>, unless it is reached there
    /// already.</summary>
    internal void Reach(string advertised, string remote)
    {
        if (advertised == (Advertised ?? _stack.BindAddress))
        {
            return;
        }
        Rebind(remote, DefaultContact(Aor, advertised, ContactParametersOf(_stack, StreamProtocol)));
        Advertised = advertised;
    }

    /// <summary><c>sipral_account_rebind</c> after a network change, reached
    /// at <paramref name="advertised"/>, the route toward its server: always,
    /// since the stack it is on has moved whether or not that route
    /// did.</summary>
    internal void Readvertise(string advertised)
    {
        Rebind(RegistrarAddress, DefaultContact(Aor, advertised, ContactParametersOf(_stack, StreamProtocol)));
        Advertised = advertised;
    }

    /// <summary><c>sipral_account_check_certificate</c>: the verdict of this
    /// account's <c>tlsPin</c> on <paramref name="certificate"/>, the DER bytes
    /// of the leaf a TLS server presented, from inside the application's own
    /// certificate check. The certificate's dates when it is the pinned one —
    /// accept the handshake whoever signed it, an expired one included;
    /// <see langword="null"/> when the account pins nothing and the
    /// platform's own checks decide; <see cref="SipralException"/> with
    /// <see cref="SipralStatus.CertificateRefused"/> when it pins
    /// another.</summary>
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

    /// <summary><c>sipral_account_rebind</c>: points this account at
    /// <paramref name="remote"/> (<c>host:port</c>; the address it was added
    /// with when left out) and makes it reachable at
    /// <paramref name="contact"/> (the AOR's user at the stack's current
    /// address when left out). What a network change asks for; the next
    /// REGISTER — sent at once when the stack is waiting for it — uses
    /// both.</summary>
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

    /// <summary>Where this account can actually be reached, for a caller
    /// who gave no <c>Contact</c> of its own — the user part of the AOR,
    /// kept, with the host replaced by the address this stack is
    /// listening on. The AOR itself is never a usable default: it names
    /// who this is, not a socket anything can write to. <paramref name="parameters"/>
    /// follows the address: <c>;transport=tls</c> on a stack signalling over
    /// TLS, since a server reaching this end names the transport it reaches
    /// it over.</summary>
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

    /// <summary>Whether it was asked to register and not to unregister
    /// since: the accounts a stack signalling over TCP or TLS registers again
    /// once its connection is made again.</summary>
    public bool WantsRegistration { get; private set; }

    /// <summary><c>sipral_account_register</c>. A no-op account refuses
    /// this. On a stack signalling over TCP or TLS whose connection is down
    /// (<see cref="SipralStatus.TransportDown"/>, already raised as
    /// <see cref="SipralEventKind.TransportFailed"/>) it is kept, and the
    /// REGISTER goes the moment the connection is made again.</summary>
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

    /// <summary><c>sipral_account_unregister</c>.</summary>
    /// <remarks>
    /// Gives the binding up: a REGISTER with Expires: 0. The registration state
    /// reads unregistered as soon as this returns, before the registrar answers;
    /// the answer is the registration-changed event that follows. Wait for that
    /// event before closing the stack, which otherwise cannot answer a challenge
    /// to the un-REGISTER.
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
    /// <c>sipral_account_subscribe</c>: watch <paramref name="target"/> (a SIP
    /// URI) through the event package <paramref name="package"/> —
    /// <c>presence</c>, <c>conference</c>, <c>dialog</c>… — sent where this
    /// account sends, or to <paramref name="destination"/> (<c>host:port</c>).
    /// <paramref name="accept"/> is the body type wanted when it is not the
    /// package's default; <paramref name="expiresSeconds"/> is how long to ask
    /// for, zero for an hour. Nothing has happened when this returns: the
    /// SUBSCRIBE is on its way, and what the notifier says arrives as events
    /// naming <see cref="SipralSubscription.Handle"/>.
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

    /// <summary>Watch a presentity's presence (RFC 3856): <see cref="Subscribe"/>
    /// to the <c>presence</c> package. Each document it sends arrives as
    /// <see cref="SipralEventKind.PresenceChanged"/> with
    /// <see cref="SipralPresenceKind.Watched"/>, open or closed, the activity,
    /// the note and the entity decoded.</summary>
    public SipralSubscription WatchPresence(string target, uint expiresSeconds = 0, string? destination = null) =>
        Subscribe(target, "presence", expiresSeconds: expiresSeconds, destination: destination);

    /// <summary>
    /// <c>sipral_account_publish_presence</c>: publish this account's presence
    /// (RFC 3903) — <paramref name="basic"/> open or closed (required), an RPID
    /// <paramref name="activity"/> (<see cref="SipralActivity.None"/> publishes
    /// no person; <see cref="SipralActivity.Other"/> is refused, having no name
    /// to publish under) and a one-line <paramref name="note"/>. The first call
    /// publishes and every later one modifies the same publication, which the
    /// stack keeps refreshed until <see cref="UnpublishPresence"/>.
    /// <see cref="SipralEventKind.PresenceChanged"/> with
    /// <see cref="SipralPresenceKind.Publication"/> says what the compositor
    /// did with it.
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

    /// <summary><c>sipral_account_remove</c>. Every call this account
    /// placed ends.</summary>
    public void Remove()
    {
        _handle.Dispose();
        _stack.ForgetAccount(this);
    }

    private static Interop.PinnedBytes Pin(byte[]? bytes) => new(bytes);
}

/// <summary>What one account holds its calls to, and signs them with, beyond
/// what the stack does: the <c>srtp</c> and <c>stir_*</c> members of
/// <c>sipral_account_config_t</c>, given to
/// <see cref="SipralStack.AddAccount"/>.
///
/// <see cref="Srtp"/> is the account's own SRTP policy over the stack's
/// (zero keeps the stack's); a call it places may
/// ask for more and never less. <see cref="SrtpSuites"/> are the suites it
/// runs, most preferred first, by their RFC 4568 and RFC 7714 names; RFC
/// 7714's GCM ones only if named. <see cref="StirVerification"/> is what the
/// account does with the <c>Identity</c> of the calls it receives, once
/// <see cref="SipralStack.Stir"/> gave the stack trust anchors.
/// <see cref="StirKey"/> (a P-256 key: the bare 32 bytes, or SEC1 or PKCS #8
/// in DER or PEM) with <see cref="StirCertificateUrl"/> signs every call the
/// account places (RFC 8224), as <see cref="StirOrig"/> or the number in the
/// AOR, claiming <see cref="StirAttestation"/> (<see cref="SipralAttestation.None"/>
/// is A) and <see cref="StirOrigid"/> (one drawn for the account when left
/// out). A PASSporT carries the time, which <see cref="SipralStack.Stir"/>
/// gives the stack: call it first, with no anchors on a stack that only
/// signs. <see cref="RecordingInClear"/> lets the account's encrypted calls
/// be recorded to a recording server as plain RTP; otherwise their copies go
/// as SRTP or not at all (RFC 7866 §12.2).</summary>
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
