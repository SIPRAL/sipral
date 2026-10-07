// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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

    /// <summary>A challenge an account's password was not given to says why,
    /// who asked, and every realm it was asked for, one per line in
    /// C.</summary>
    [Fact]
    public void ADeclinedChallengeCarriesWhoAskedAndForWhat()
    {
        var server = Encoding.UTF8.GetBytes("203.0.113.9:5060");
        var realms = Encoding.UTF8.GetBytes("sbc.example\ncallee, inc.");
        var serverPtr = Marshal.AllocHGlobal(server.Length);
        var realmsPtr = Marshal.AllocHGlobal(realms.Length);
        try
        {
            Marshal.Copy(server, 0, serverPtr, server.Length);
            Marshal.Copy(realms, 0, realmsPtr, realms.Length);
            var evt = Raw(SipralEventKind.ChallengeDeclined);
            evt.Payload.Challenge.Refusal = (uint)SipralChallengeRefusal.NotTheAccountsRealm;
            evt.Payload.Challenge.Server = serverPtr;
            evt.Payload.Challenge.ServerLen = (nuint)server.Length;
            evt.Payload.Challenge.Realms = realmsPtr;
            evt.Payload.Challenge.RealmsLen = (nuint)realms.Length;
            var decoded = Decode(evt).Challenge!;
            Assert.Equal(SipralChallengeRefusal.NotTheAccountsRealm, decoded.Refusal);
            Assert.Equal("203.0.113.9:5060", decoded.Server);
            Assert.Equal(new[] { "sbc.example", "callee, inc." }, decoded.Realms);
        }
        finally
        {
            Marshal.FreeHGlobal(serverPtr);
            Marshal.FreeHGlobal(realmsPtr);
        }
    }

    /// <summary>A network test's event carries every part and the
    /// verdict.</summary>
    [Fact]
    public void ANetworkTestCarriesItsPartsAndItsVerdict()
    {
        string[] texts = { "192.0.2.10:40000", "203.0.113.7:41002" };
        var pointers = new IntPtr[texts.Length];
        try
        {
            for (var i = 0; i < texts.Length; i++)
            {
                var bytes = Encoding.UTF8.GetBytes(texts[i]);
                pointers[i] = Marshal.AllocHGlobal(bytes.Length);
                Marshal.Copy(bytes, 0, pointers[i], bytes.Length);
            }
            var evt = Raw(SipralEventKind.NetworkTest);
            evt.Payload.NetworkTest.Test = 4;
            evt.Payload.NetworkTest.Verdict = (uint)SipralNetworkVerdict.Acceptable;
            evt.Payload.NetworkTest.Stun = (uint)SipralNetworkProbe.Succeeded;
            evt.Payload.NetworkTest.Nat = (uint)SipralNatKind.PortChanged;
            evt.Payload.NetworkTest.Turn = (uint)SipralNetworkProbe.Failed;
            evt.Payload.NetworkTest.Server = (uint)SipralServerReach.Answered;
            evt.Payload.NetworkTest.ServerStatus = 200;
            evt.Payload.NetworkTest.ServerRoundTripMs = 37;
            evt.Payload.NetworkTest.HasRoundTrip = 1;
            evt.Payload.NetworkTest.RoundTripMs = 80;
            evt.Payload.NetworkTest.Mos = 4.2f;
            evt.Payload.NetworkTest.Local = pointers[0];
            evt.Payload.NetworkTest.LocalLen = (nuint)texts[0].Length;
            evt.Payload.NetworkTest.Mapped = pointers[1];
            evt.Payload.NetworkTest.MappedLen = (nuint)texts[1].Length;
            var decoded = Decode(evt).NetworkTest!;
            Assert.Equal(4u, decoded.Test);
            Assert.Equal(SipralNetworkVerdict.Acceptable, decoded.Verdict);
            Assert.Equal(SipralNetworkProbe.Succeeded, decoded.Stun);
            Assert.Equal(SipralNatKind.PortChanged, decoded.Nat);
            Assert.Equal(SipralNetworkProbe.Failed, decoded.Turn);
            Assert.Equal(SipralServerReach.Answered, decoded.Server);
            Assert.Equal(200u, decoded.ServerStatus);
            Assert.Equal(37u, decoded.ServerRoundTripMs);
            Assert.Equal(80u, decoded.RoundTripMs);
            Assert.Equal(4.2f, decoded.Mos);
            Assert.Equal("192.0.2.10:40000", decoded.Local);
            Assert.Equal("203.0.113.7:41002", decoded.Mapped);
        }
        finally
        {
            foreach (var pointer in pointers)
            {
                if (pointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pointer);
                }
            }
        }
    }

    /// <summary>An account's server asking for an OAuth access token says
    /// where one comes from, for what scope, and why the last was
    /// refused.</summary>
    [Fact]
    public void ATokenRequiredCarriesTheAuthorizationServerAndTheError()
    {
        string[] texts = { "203.0.113.9:5060", "example.com", "sip register", "https://as.example.com", "invalid_token" };
        var pointers = new IntPtr[texts.Length];
        try
        {
            for (var i = 0; i < texts.Length; i++)
            {
                var bytes = Encoding.UTF8.GetBytes(texts[i]);
                pointers[i] = Marshal.AllocHGlobal(bytes.Length);
                Marshal.Copy(bytes, 0, pointers[i], bytes.Length);
            }
            var evt = Raw(SipralEventKind.TokenRequired);
            evt.Payload.Token.Error = (uint)SipralTokenError.InvalidToken;
            evt.Payload.Token.Proxy = (uint)SipralToggle.On;
            evt.Payload.Token.Server = pointers[0];
            evt.Payload.Token.ServerLen = (nuint)texts[0].Length;
            evt.Payload.Token.Realm = pointers[1];
            evt.Payload.Token.RealmLen = (nuint)texts[1].Length;
            evt.Payload.Token.Scope = pointers[2];
            evt.Payload.Token.ScopeLen = (nuint)texts[2].Length;
            evt.Payload.Token.AuthzServer = pointers[3];
            evt.Payload.Token.AuthzServerLen = (nuint)texts[3].Length;
            evt.Payload.Token.ErrorCode = pointers[4];
            evt.Payload.Token.ErrorCodeLen = (nuint)texts[4].Length;
            var decoded = Decode(evt).Token!;
            Assert.Equal(SipralTokenError.InvalidToken, decoded.Error);
            Assert.Equal("invalid_token", decoded.ErrorCode);
            Assert.True(decoded.Proxy);
            Assert.Equal("203.0.113.9:5060", decoded.Server);
            Assert.Equal("example.com", decoded.Realm);
            Assert.Equal("sip register", decoded.Scope);
            Assert.Equal("https://as.example.com", decoded.AuthzServer);
        }
        finally
        {
            foreach (var pointer in pointers)
            {
                if (pointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pointer);
                }
            }
        }
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
