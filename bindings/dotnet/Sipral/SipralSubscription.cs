// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Generic;
using Sipral.Interop;

namespace Sipral;

/// <summary>
/// One subscription (RFC 6665), e.g. presence (RFC 3856) or conference (RFC
/// 4575). The stack refreshes it while live; notifications arrive as events
/// naming <see cref="Handle"/>.
/// </summary>
public sealed class SipralSubscription
{
    private readonly SipralStack _stack;

    /// <summary>The raw <c>sipral_handle_t</c> events name.</summary>
    public ulong Handle { get; }

    /// <summary>The event package.</summary>
    public string Package { get; }

    internal SipralSubscription(SipralStack stack, ulong handle, string package)
    {
        _stack = stack;
        Handle = handle;
        Package = package;
    }

    /// <summary><c>sipral_subscription_state</c>, read fresh:
    /// <see cref="SipralSubscriptionState.Unknown"/> once it has
    /// ended.</summary>
    public SipralSubscriptionState State
    {
        get
        {
            uint state = 0;
            SipralErrors.Call(
                () => NativeMethods.sipral_subscription_state(_stack.Handle, Handle, out state),
                "sipral_subscription_state");
            return (SipralSubscriptionState)state;
        }
    }

    /// <summary><c>sipral_subscription_end</c>: unsubscribe; it is over once
    /// the closing NOTIFY is answered.</summary>
    public void End()
    {
        SipralErrors.Call(
            () => NativeMethods.sipral_subscription_end(_stack.Handle, Handle, _stack.NowMs),
            "sipral_subscription_end");
    }

    /// <summary>
    /// The conference state held now, or <see langword="null"/> (another
    /// package, no document yet, or ended). Read again after each
    /// <see cref="SipralEventKind.ConferenceChanged"/>.
    /// </summary>
    public SipralConferencePicture? Conference()
    {
        var conference = SipralConference.Sized();
        var deadline = Environment.TickCount64 + 500;
        var status = NativeMethods.sipral_subscription_conference(_stack.Handle, Handle, ref conference);
        while (status == SipralStatus.Busy && Environment.TickCount64 < deadline)
        {
            System.Threading.Thread.Sleep(1);
            status = NativeMethods.sipral_subscription_conference(_stack.Handle, Handle, ref conference);
        }
        if (status == SipralStatus.NotSupported)
        {
            return null;
        }
        SipralErrors.Check(status, "sipral_subscription_conference");

        var users = new List<SipralConferenceParticipant>((int)conference.Users);
        for (nuint index = 0; index < conference.Users; index++)
        {
            var user = SipralConferenceUser.Sized();
            var at = index;
            SipralErrors.Call(
                () => NativeMethods.sipral_subscription_conference_user_at(_stack.Handle, Handle, at, ref user),
                "sipral_subscription_conference_user_at");
            users.Add(new SipralConferenceParticipant(
                Text(SipralConferenceText.UserEntity, index),
                Text(SipralConferenceText.UserDisplayText, index),
                Text(SipralConferenceText.UserEndpoint, index),
                (SipralEndpointStatus)user.Status,
                user.Endpoints,
                user.Media));
        }
        return new SipralConferencePicture(
            conference.Version,
            Text(SipralConferenceText.Entity, 0),
            Text(SipralConferenceText.Subject, 0),
            Text(SipralConferenceText.DisplayText, 0),
            conference.HasUserCount != 0 ? conference.UserCount : null,
            Tristate(conference.Active),
            Tristate(conference.Locked),
            users);
    }

    private static bool? Tristate(uint value) => value switch
    {
        1 => true,
        2 => false,
        _ => null,
    };

    private string? Text(SipralConferenceText which, nuint index)
    {
        var text = SipralText.Read(
            buffer =>
            {
                var status = NativeMethods.sipral_subscription_conference_text(
                    _stack.Handle, Handle, index, (uint)which, buffer, (nuint)buffer.Length, out var needed);
                return (status, needed);
            },
            "sipral_subscription_conference_text");
        return text.Length == 0 ? null : text;
    }
}

/// <summary>
/// Reads a <c>*_text</c> entry point: on
/// <see cref="SipralStatus.BufferTooSmall"/> it retries once with the size
/// asked for, which always fits.
/// </summary>
internal static class SipralText
{
    internal static string Read(Func<sbyte[], (SipralStatus Status, nuint Needed)> copy, string where)
    {
        var buffer = new sbyte[256];
        var (status, needed) = copy(buffer);
        var deadline = Environment.TickCount64 + 500;
        while (status == SipralStatus.Busy && Environment.TickCount64 < deadline)
        {
            System.Threading.Thread.Sleep(1);
            (status, needed) = copy(buffer);
        }
        if (status == SipralStatus.BufferTooSmall)
        {
            buffer = new sbyte[(int)needed];
            (status, needed) = copy(buffer);
        }
        SipralErrors.Check(status, where);
        return NativeText.FromSBytes(buffer, Math.Max((int)needed - 1, 0));
    }
}

/// <summary>A conference's state (RFC 4575 §5). <see cref="UserCount"/> may
/// exceed <see cref="Users"/>' length: a focus need not list everyone.
/// Users are in the order the focus first named them.</summary>
public sealed record SipralConferencePicture(
    uint Version,
    string? Entity,
    string? Subject,
    string? DisplayText,
    uint? UserCount,
    bool? Active,
    bool? Locked,
    IReadOnlyList<SipralConferenceParticipant> Users);

/// <summary>One conference user (RFC 4575 §5.7.2); the device and media
/// fields describe its first endpoint.</summary>
public sealed record SipralConferenceParticipant(
    string? Entity,
    string? DisplayText,
    string? Endpoint,
    SipralEndpointStatus Status,
    uint Endpoints,
    uint Media);
