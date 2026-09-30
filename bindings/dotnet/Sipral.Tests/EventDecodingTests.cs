// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Sipral;
using Sipral.Interop;
using Xunit;

namespace Sipral.Tests;

/// <summary>Every event the C ABI raises reaches .NET with its payload read:
/// an event whose arm this layer never reads would reach the application as a
/// kind and nothing else.</summary>
public class EventDecodingTests
{
    private static readonly string[] Plain =
    {
        nameof(SipralEventArgs.Kind), nameof(SipralEventArgs.KindName), nameof(SipralEventArgs.Stack),
        nameof(SipralEventArgs.Account), nameof(SipralEventArgs.Call), nameof(SipralEventArgs.Message),
    };

    /// <summary>The library is found the way a stack finds it: decoding
    /// asks it for each kind's name, and here no stack came first.</summary>
    public EventDecodingTests() => NativeLibraryLoader.EnsureRegistered();

    /// <summary>Decodes <paramref name="evt"/> the way the callback does,
    /// from unmanaged memory.</summary>
    private static SipralEventArgs Decode(global::Sipral.SipralEvent evt)
    {
        var raw = Marshal.AllocHGlobal(Marshal.SizeOf<global::Sipral.SipralEvent>());
        try
        {
            Marshal.StructureToPtr(evt, raw, false);
            return SipralEventArgs.Decode(raw);
        }
        finally
        {
            Marshal.FreeHGlobal(raw);
        }
    }

    private static global::Sipral.SipralEvent Raw(SipralEventKind kind)
    {
        var evt = global::Sipral.SipralEvent.Sized();
        evt.Kind = kind;
        return evt;
    }

    [Fact]
    public void EveryKindWithAPayloadIsDecoded()
    {
        var views = typeof(SipralEventArgs).GetProperties().Where(p => !Plain.Contains(p.Name)).ToArray();
        var unread = new List<string>();
        foreach (var kind in Enum.GetValues<SipralEventKind>())
        {
            if (kind == SipralEventKind.Started)
            {
                // the first event on every stack; its arm carries nothing
                continue;
            }
            var decoded = Decode(Raw(kind));
            if (views.All(p => p.GetValue(decoded) is null))
            {
                unread.Add(kind.ToString());
            }
        }
        Assert.Empty(unread);
    }

    [Fact]
    public void ASubscriptionNoticeCarriesItsState()
    {
        var evt = Raw(SipralEventKind.Notified);
        evt.Payload.Subscription.Subscription = 7;
        evt.Payload.Subscription.State = (uint)SipralSubscriptionState.Active;
        evt.Payload.Subscription.StatusCode = 202;
        evt.Payload.Subscription.ExpiresMs = 600_000;
        evt.Payload.Subscription.HasDialogInfo = 1;
        var decoded = Decode(evt).Subscription!;
        Assert.Equal(7UL, decoded.Subscription);
        Assert.Equal(SipralSubscriptionState.Active, decoded.State);
        Assert.Equal(202U, decoded.StatusCode);
        Assert.Equal(600_000UL, decoded.ExpiresMs);
        Assert.True(decoded.HasDialogInfo);
    }

    [Fact]
    public void AMessageCarriesItsBodyAndASummaryItsCounts()
    {
        var body = Encoding.UTF8.GetBytes("hello");
        var type = Encoding.UTF8.GetBytes("text/plain");
        var bodyPtr = Marshal.AllocHGlobal(body.Length);
        var typePtr = Marshal.AllocHGlobal(type.Length);
        try
        {
            Marshal.Copy(body, 0, bodyPtr, body.Length);
            Marshal.Copy(type, 0, typePtr, type.Length);
            var evt = Raw(SipralEventKind.MessageReceived);
            evt.Payload.Message.Message = 3;
            evt.Payload.Message.Body = bodyPtr;
            evt.Payload.Message.BodyLen = (nuint)body.Length;
            evt.Payload.Message.ContentType = typePtr;
            evt.Payload.Message.ContentTypeLen = (nuint)type.Length;
            var decoded = Decode(evt).MessageInfo!;
            Assert.Equal(3UL, decoded.Message);
            Assert.Equal(body, decoded.Body);
            Assert.Equal("text/plain", decoded.ContentType);
        }
        finally
        {
            Marshal.FreeHGlobal(bodyPtr);
            Marshal.FreeHGlobal(typePtr);
        }

        var waiting = Raw(SipralEventKind.MessagesWaiting);
        waiting.Payload.Message.Waiting = 1;
        waiting.Payload.Message.NewMessages = 2;
        waiting.Payload.Message.UrgentOldMessages = 1;
        var summary = Decode(waiting).MessageInfo!;
        Assert.True(summary.Waiting);
        Assert.Equal(2U, summary.NewMessages);
        Assert.Equal(1U, summary.UrgentOldMessages);
    }

    [Fact]
    public void ARecoveryAndAnAnnouncementCarryTheirPayloads()
    {
        var evt = Raw(SipralEventKind.Recovery);
        evt.Payload.Recovery.State = (uint)SipralRecoveryOutcome.GaveUp;
        evt.Payload.Recovery.Unverified = 2;
        var recovery = Decode(evt).Recovery!;
        Assert.Equal(SipralRecoveryOutcome.GaveUp, recovery.State);
        Assert.Equal(2U, recovery.Unverified);

        var missing = Raw(SipralEventKind.AnnouncedCallMissing);
        missing.Payload.Announce.Announcement = 9;
        missing.Payload.Announce.WaitedMs = 30_000;
        var announce = Decode(missing).Announce!;
        Assert.Equal(9UL, announce.Announcement);
        Assert.Equal(30_000UL, announce.WaitedMs);
    }
}
