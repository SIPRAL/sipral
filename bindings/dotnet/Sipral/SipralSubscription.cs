// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Generic;
using Sipral.Interop;

namespace Sipral;

/// <summary>
/// One subscription: something at the far end this stack watches (RFC
/// 6665) — a presentity's <c>presence</c> (RFC 3856), a focus's
/// <c>conference</c> (RFC 4575), or any other package named to
/// <see cref="Account.Subscribe"/>.
///
/// Made by <see cref="Account.Subscribe"/>, <see cref="Account.WatchPresence"/>
/// and <see cref="Call.SubscribeConference"/>. The stack refreshes it for as
/// long as it is live; what the notifier says arrives as events naming
/// <see cref="Handle"/>: <see cref="SipralEventKind.PresenceChanged"/> with
/// <see cref="SipralEventArgs.Presence"/> for a presentity, and
/// <see cref="SipralEventKind.ConferenceChanged"/> with
/// <see cref="SipralEventArgs.Conference"/> for a conference, whose whole
/// picture <see cref="Conference"/> then reads.
/// </summary>
public sealed class SipralSubscription
{
    private readonly SipralStack _stack;

    /// <summary>The raw <c>sipral_handle_t</c>: what
    /// <see cref="SipralPresenceEventInfo.Subscription"/> and
    /// <see cref="SipralConferenceEventInfo.Subscription"/> name.</summary>
    public ulong Handle { get; }

    /// <summary>The event package, as it went out: <c>presence</c>,
    /// <c>conference</c>, <c>dialog</c>…</summary>
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

    /// <summary><c>sipral_subscription_end</c>: an unsubscribe goes out, and
    /// the subscription is over once the notifier's closing notification
    /// is answered.</summary>
    public void End()
    {
        SipralErrors.Call(
            () => NativeMethods.sipral_subscription_end(_stack.Handle, Handle, _stack.NowMs),
            "sipral_subscription_end");
    }

    /// <summary>
    /// The conference as this subscription holds it now
    /// (<c>sipral_subscription_conference</c>, then each user with
    /// <c>sipral_subscription_conference_user_at</c> and their text with
    /// <c>sipral_subscription_conference_text</c>), or
    /// <see langword="null"/> when it holds none: a subscription to another
    /// package, one no document has reached yet, or one that ended.
    /// Read it again after every <see cref="SipralEventKind.ConferenceChanged"/>
    /// naming <see cref="Handle"/>.
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

    /// <summary>One piece of the conference's text, <see langword="null"/>
    /// for one the focus did not send.</summary>
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
/// Copies a piece of text out the way every <c>*_text</c> entry point of
/// this ABI copies one: into the caller's buffer with its NUL, answering
/// <see cref="SipralStatus.BufferTooSmall"/> and the bytes it needs when
/// that buffer is short, so a second try with exactly that many always
/// fits.
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

/// <summary>A conference as a <c>conference</c> subscription holds it
/// (RFC 4575 §5): the version of the last document merged, the
/// conference's own URI, subject and display text, what
/// <c>conference-state</c> said — <see cref="UserCount"/> may differ from
/// <see cref="Users"/>' length, since a focus need not list everyone — and
/// every user listed, in the order the focus first named them.</summary>
public sealed record SipralConferencePicture(
    uint Version,
    string? Entity,
    string? Subject,
    string? DisplayText,
    uint? UserCount,
    bool? Active,
    bool? Locked,
    IReadOnlyList<SipralConferenceParticipant> Users);

/// <summary>One user of a conference: the address of record it takes part
/// as, its display text, the device its first endpoint is on and where
/// that endpoint is (RFC 4575 §5.7.2), how many endpoints it is in from,
/// and how many media streams the first of them has.</summary>
public sealed record SipralConferenceParticipant(
    string? Entity,
    string? DisplayText,
    string? Endpoint,
    SipralEndpointStatus Status,
    uint Endpoints,
    uint Media);
