// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// The protocols a call and an account carry beyond audio, through this
/// layer — the .NET counterpart of
/// <c>bindings/python/tests/test_protocols.py</c>: real-time text and RTCP
/// feedback agreed between two stacks on 127.0.0.1, a focus named on an
/// answer, L16 as the codec, and — against this test's own UDP or TCP peer
/// writing RFC text by hand — a conference picture, presence published and
/// watched, and a call recorded to a recording server.
/// </summary>
public sealed class ProtocolTests : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);
    private readonly List<IDisposable> _owned = new();

    public void Dispose()
    {
        foreach (var owned in Enumerable.Reverse(_owned))
        {
            owned.Dispose();
        }
    }

    private T Own<T>(T disposable) where T : IDisposable
    {
        _owned.Add(disposable);
        return disposable;
    }

    private SipralStack Stack(string codecs = "PCMU") =>
        Own(new SipralStack(audio: SipralAudio.Application, codecs: codecs));

    private async Task<(Call Alice, Call Bob)> PlaceAndAnswerAsync(
        SipralStack alice, SipralStack bob, SipralCallOptions? placed = null, SipralCallOptions? answered = null)
    {
        var aliceAccount = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);
        var aliceCall = Own(alice.PlaceCall(aliceAccount, $"sip:bob@{bob.BindAddress}", options: placed));
        var incoming = await FirstMatchingAsync(bob.Events, e => e.Kind == SipralEventKind.IncomingCall);
        var bobCall = Own(bob.AnswerCall(incoming, options: answered));
        using var cts = new CancellationTokenSource(Timeout);
        Assert.True(await aliceCall.WaitForConfirmedAsync(cts.Token));
        Assert.NotNull(await aliceCall.WaitForMediaAsync(cts.Token));
        Assert.NotNull(await bobCall.WaitForMediaAsync(cts.Token));
        return (aliceCall, bobCall);
    }

    // -- between two stacks --------------------------------------------------

    [Fact]
    public async Task RealTimeTextCrossesBothWays()
    {
        var (alice, bob) = await PlaceAndAnswerAsync(
            Stack(), Stack(), new SipralCallOptions(Text: true), new SipralCallOptions(Text: true));
        Assert.NotNull(alice.TextAddress);
        Assert.True(alice.Media!.Info().HasText);
        Assert.True(bob.Media!.Info().HasText);

        alice.SendText("hello");
        Assert.Equal("hello", await TypedAsync(bob.Text, "hello"));
        bob.SendText("hi\b");
        Assert.Equal("hi\b", await TypedAsync(alice.Text, "hi\b"));
    }

    [Fact]
    public async Task TextOnACallThatAgreedNoneIsNotNegotiated()
    {
        var (alice, _) = await PlaceAndAnswerAsync(Stack(), Stack());
        Assert.Null(alice.TextAddress);
        Assert.False(alice.Media!.Info().HasText);
        var refused = Assert.Throws<SipralException>(() => alice.SendText("lost"));
        Assert.Equal(SipralStatus.NotNegotiated, refused.Status);
    }

    [Fact]
    public async Task FeedbackAskedForIsAgreedAndCounted()
    {
        var (alice, bob) = await PlaceAndAnswerAsync(
            Stack(), Stack(), new SipralCallOptions(Feedback: true), new SipralCallOptions(Feedback: true));
        foreach (var media in new[] { alice.Media!, bob.Media! })
        {
            var info = media.Info();
            Assert.True(info.Feedback);
            Assert.True(info.GenericNack);
            Assert.True(info.ReducedSize);
            Assert.NotNull(media.Statistics().Feedback);
        }
    }

    [Fact]
    public async Task FeedbackIsOffByDefault()
    {
        var (alice, _) = await PlaceAndAnswerAsync(Stack(), Stack());
        var info = alice.Media!.Info();
        Assert.False(info.Feedback);
        Assert.False(info.GenericNack);
        Assert.Null(alice.Media.Statistics().Feedback);
    }

    [Fact]
    public async Task AFocusThatAnsweredNamesItsConference()
    {
        var (alice, bob) = await PlaceAndAnswerAsync(Stack(), Stack(), answered: new SipralCallOptions(Focus: true));
        var uri = alice.ConferenceUri;
        Assert.NotNull(uri);
        Assert.StartsWith("sip:", uri);
        Assert.Null(bob.ConferenceUri);
        var watched = alice.SubscribeConference();
        Assert.Equal("conference", watched.Package);
        Assert.NotEqual(0UL, watched.Handle);
    }

    [Fact]
    public async Task ACallFromAnyoneElseHasNoConference()
    {
        var (alice, _) = await PlaceAndAnswerAsync(Stack(), Stack());
        Assert.Null(alice.ConferenceUri);
        var refused = Assert.Throws<SipralException>(() => alice.SubscribeConference());
        Assert.Equal(SipralStatus.NotAFocus, refused.Status);
    }

    [Fact]
    public async Task L16IsTheCodecWhenItIsTheOnlyOneNamed()
    {
        var (alice, bob) = await PlaceAndAnswerAsync(Stack("L16/16000"), Stack("L16/16000"));
        var info = alice.Media!.Info();
        Assert.Equal(SipralCodec.L16Wideband, info.Codec);
        Assert.Equal(16_000u, info.ClockRate);
        Assert.Equal(SipralCodec.L16Wideband, bob.Media!.Info().Codec);
    }

    // -- against a notifier and a compositor of this test's own ----------------

    private const string Room =
        "<?xml version=\"1.0\"?>\r\n" +
        "<conference-info xmlns=\"urn:ietf:params:xml:ns:conference-info\" entity=\"sip:room@example.com\" state=\"full\" version=\"1\">\r\n" +
        "  <conference-description><subject>Weekly</subject><display-text>Team room</display-text></conference-description>\r\n" +
        "  <conference-state><user-count>3</user-count><active>true</active><locked>false</locked></conference-state>\r\n" +
        "  <users>\r\n" +
        "    <user entity=\"sip:bob@example.com\" state=\"full\"><display-text>Bob</display-text>\r\n" +
        "      <endpoint entity=\"sip:bob@203.0.113.5\"><status>connected</status><media id=\"1\"><type>audio</type></media></endpoint>\r\n" +
        "    </user>\r\n" +
        "    <user entity=\"sip:carol@example.com\" state=\"full\">\r\n" +
        "      <endpoint entity=\"sip:carol@203.0.113.6\"><status>alerting</status></endpoint>\r\n" +
        "    </user>\r\n" +
        "  </users>\r\n" +
        "</conference-info>";

    private const string Deleted =
        "<conference-info xmlns=\"urn:ietf:params:xml:ns:conference-info\" entity=\"sip:room@example.com\" state=\"deleted\" version=\"2\"/>";

    private const string Buddy =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" +
        "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" xmlns:dm=\"urn:ietf:params:xml:ns:pidf:data-model\" xmlns:rpid=\"urn:ietf:params:xml:ns:pidf:rpid\" entity=\"sip:bob@example.com\">\r\n" +
        "  <tuple id=\"t1\"><status><basic>open</basic></status><note>Back at four</note></tuple>\r\n" +
        "  <dm:person id=\"p1\"><rpid:activities><rpid:meeting/></rpid:activities></dm:person>\r\n" +
        "</presence>";

    [Fact]
    public async Task AConferenceIsReadBackWholeAndItsEndIsTold()
    {
        var stack = Stack();
        using var notifier = new Peer();
        var account = stack.AddAccount("sip:alice@sipral.invalid", registrarAddress: notifier.Address);
        var subscription = account.Subscribe("sip:room@example.com", "conference");
        Assert.Null(subscription.Conference());

        var subscribe = await notifier.RequestAsync("SUBSCRIBE");
        Assert.Equal("conference", Peer.Header("Event", subscribe));
        notifier.Send(Peer.Answer(subscribe, "200 OK", "notifier", "Expires: 3600\r\nContact: <sip:room@" + notifier.Address + ">\r\n"), stack.BindAddress);
        notifier.Send(Peer.Notify(subscribe, notifier.Address, "conference", "application/conference-info+xml", Room, 1), stack.BindAddress);

        var changed = await FirstMatchingAsync(stack.Events, e => e.Kind == SipralEventKind.ConferenceChanged);
        Assert.Equal(subscription.Handle, changed.Conference!.Subscription);
        Assert.Equal(SipralConferenceUpdate.Applied, changed.Conference.Update);
        Assert.Equal(1u, changed.Conference.Version);
        Assert.Equal(2u, changed.Conference.Users);

        var picture = subscription.Conference();
        Assert.NotNull(picture);
        Assert.Equal("sip:room@example.com", picture!.Entity);
        Assert.Equal("Weekly", picture.Subject);
        Assert.Equal("Team room", picture.DisplayText);
        Assert.Equal(3u, picture.UserCount);
        Assert.True(picture.Active);
        Assert.False(picture.Locked);
        Assert.Equal(2, picture.Users.Count);
        Assert.Equal(new SipralConferenceParticipant("sip:bob@example.com", "Bob", "sip:bob@203.0.113.5", SipralEndpointStatus.Connected, 1, 1), picture.Users[0]);
        Assert.Equal("sip:carol@example.com", picture.Users[1].Entity);
        Assert.Null(picture.Users[1].DisplayText);
        Assert.Equal(SipralEndpointStatus.Alerting, picture.Users[1].Status);

        notifier.Send(Peer.Notify(subscribe, notifier.Address, "conference", "application/conference-info+xml", Deleted, 2), stack.BindAddress);
        var ended = await FirstMatchingAsync(stack.Events, e => e.Kind == SipralEventKind.ConferenceChanged);
        Assert.Equal(SipralConferenceUpdate.Ended, ended.Conference!.Update);
        Assert.Equal(0u, ended.Conference.Users);
    }

    [Fact]
    public async Task PresenceIsPublishedModifiedAndTakenAway()
    {
        var stack = Stack();
        using var compositor = new Peer();
        var account = stack.AddAccount("sip:alice@sipral.invalid", registrarAddress: compositor.Address);

        var nothing = Assert.Throws<SipralException>(() => account.UnpublishPresence());
        Assert.Equal(SipralStatus.WrongState, nothing.Status);
        var unnamed = Assert.Throws<SipralException>(() => account.PublishPresence(SipralBasic.Open, SipralActivity.Other));
        Assert.Equal(SipralStatus.InvalidArgument, unnamed.Status);

        account.PublishPresence(SipralBasic.Open, SipralActivity.OnThePhone, "In a call");
        var publish = await compositor.RequestAsync("PUBLISH");
        Assert.Equal("presence", Peer.Header("Event", publish));
        Assert.Contains("<basic>open</basic>", publish);
        Assert.Contains("on-the-phone", publish);
        Assert.Contains("In a call", publish);
        compositor.Send(Peer.Answer(publish, "200 OK", "compositor", "SIP-ETag: tag-one\r\nExpires: 1800\r\n"), stack.BindAddress);
        var published = await FirstMatchingAsync(stack.Events, e => e.Kind == SipralEventKind.PresenceChanged);
        Assert.Equal(account.Handle, published.Account);
        Assert.Equal(SipralPresenceKind.Publication, published.Presence!.Kind);
        Assert.Equal(SipralPublicationState.Published, published.Presence.PublicationState);
        Assert.Equal(1_800_000UL, published.Presence.ExpiresMs);
        Assert.InRange(published.Presence.RefreshInMs, 1UL, 1_799_999UL);

        account.PublishPresence(SipralBasic.Closed, SipralActivity.Away);
        var modified = await compositor.RequestAsync("PUBLISH");
        Assert.Equal("tag-one", Peer.Header("SIP-If-Match", modified));
        Assert.Contains("<basic>closed</basic>", modified);
        compositor.Send(Peer.Answer(modified, "200 OK", "compositor", "SIP-ETag: tag-two\r\nExpires: 1800\r\n"), stack.BindAddress);
        await FirstMatchingAsync(stack.Events, e => e.Kind == SipralEventKind.PresenceChanged);

        account.UnpublishPresence();
        var removal = await compositor.RequestAsync("PUBLISH");
        Assert.Equal("0", Peer.Header("Expires", removal));
        compositor.Send(Peer.Answer(removal, "200 OK", "compositor", "SIP-ETag: tag-two\r\nExpires: 0\r\n"), stack.BindAddress);
        var removed = await FirstMatchingAsync(stack.Events, e => e.Kind == SipralEventKind.PresenceChanged);
        Assert.Equal(SipralPublicationState.Removed, removed.Presence!.PublicationState);
    }

    [Fact]
    public async Task ACompositorThatKnowsNoPresenceIsAFailureWithItsReason()
    {
        var stack = Stack();
        using var compositor = new Peer();
        var account = stack.AddAccount("sip:alice@sipral.invalid", registrarAddress: compositor.Address);
        account.PublishPresence(SipralBasic.Open);
        var publish = await compositor.RequestAsync("PUBLISH");
        compositor.Send(Peer.Answer(publish, "489 Bad Event", "compositor", string.Empty), stack.BindAddress);
        var failed = await FirstMatchingAsync(stack.Events, e => e.Kind == SipralEventKind.PresenceChanged);
        Assert.Equal(SipralPublicationState.Failed, failed.Presence!.PublicationState);
        Assert.Equal(SipralPublishFailure.BadEvent, failed.Presence.Failure);
        Assert.Equal(489u, failed.Presence.StatusCode);
    }

    [Fact]
    public async Task AWatchedPresentityIsToldWithItsActivityAndNote()
    {
        var stack = Stack();
        using var notifier = new Peer();
        var account = stack.AddAccount("sip:alice@sipral.invalid", registrarAddress: notifier.Address);
        var watched = account.WatchPresence("sip:bob@example.com");
        Assert.Equal("presence", watched.Package);

        var subscribe = await notifier.RequestAsync("SUBSCRIBE");
        Assert.Equal("presence", Peer.Header("Event", subscribe));
        notifier.Send(Peer.Answer(subscribe, "200 OK", "notifier", "Expires: 3600\r\nContact: <sip:bob@" + notifier.Address + ">\r\n"), stack.BindAddress);
        notifier.Send(Peer.Notify(subscribe, notifier.Address, "presence", "application/pidf+xml", Buddy, 1), stack.BindAddress);

        var told = await FirstMatchingAsync(stack.Events, e => e.Kind == SipralEventKind.PresenceChanged);
        Assert.Equal(new SipralPresenceEventInfo(
            SipralPresenceKind.Watched, watched.Handle, SipralBasic.Open, SipralActivity.Meeting,
            "sip:bob@example.com", "Back at four", SipralPublicationState.Unknown, SipralPublishFailure.None, 0, 0, 0),
            told.Presence);
        Assert.Equal(SipralSubscriptionState.Active, watched.State);

        watched.End();
        var ending = await notifier.RequestAsync("SUBSCRIBE");
        Assert.Equal("0", Peer.Header("Expires", ending));
    }

    // -- a recording server ------------------------------------------------

    [Fact]
    public async Task ACallIsRecordedToARecordingServer()
    {
        using var server = new StreamPeer();
        using var rtp = new Peer();
        using var labelOne = new Peer();
        using var labelTwo = new Peer();
        var stack = Own(new SipralStack(
            audio: SipralAudio.Application, codecs: "PCMU", signalling: SipralTransport.Tcp, signallingServer: server.Address));
        stack.AddAccount("sip:alice@sipral.invalid", registrarAddress: server.Address);
        await server.ConnectedAsync();

        var sdp = "v=0\r\no=bob 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
                  $"m=audio {rtp.Port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        server.Send(
            "INVITE sip:alice@sipral.invalid SIP/2.0\r\n" +
            $"Via: SIP/2.0/TCP {server.Address};branch=z9hG4bK-recorded-1\r\n" +
            "Max-Forwards: 70\r\n" +
            "From: <sip:bob@example.com>;tag=bob\r\n" +
            "To: <sip:alice@sipral.invalid>\r\n" +
            "Call-ID: recorded-call\r\n" +
            "CSeq: 1 INVITE\r\n" +
            $"Contact: <sip:bob@{server.Address};transport=tcp>\r\n" +
            "Content-Type: application/sdp\r\n" +
            $"Content-Length: {Encoding.UTF8.GetByteCount(sdp)}\r\n\r\n" + sdp);
        var incoming = await FirstMatchingAsync(stack.Events, e => e.Kind == SipralEventKind.IncomingCall);
        var call = Own(stack.AnswerCall(incoming));
        var ok = await server.MessageAsync(m => m.StartsWith("SIP/2.0 200", StringComparison.Ordinal) && Peer.Header("CSeq", m) == "1 INVITE");
        server.Send(
            $"ACK {Peer.Uri(Peer.Header("Contact", ok)!)} SIP/2.0\r\n" +
            $"Via: SIP/2.0/TCP {server.Address};branch=z9hG4bK-recorded-ack\r\n" +
            "Max-Forwards: 70\r\n" +
            "From: <sip:bob@example.com>;tag=bob\r\n" +
            $"To: {Peer.Header("To", ok)}\r\n" +
            "Call-ID: recorded-call\r\n" +
            "CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n");
        using (var cts = new CancellationTokenSource(Timeout))
        {
            Assert.NotNull(await call.WaitForMediaAsync(cts.Token));
        }

        var session = call.RecordTo("sip:srs@example.com");
        Assert.Equal(session, call.RecordingSession);
        var offer = await server.MessageAsync(m => m.StartsWith("INVITE sip:srs@example.com", StringComparison.Ordinal));
        Assert.Equal("siprec", Peer.Header("Require", offer));
        Assert.StartsWith("multipart/mixed", Peer.Header("Content-Type", offer));
        Assert.Contains("a=label:1", offer);
        Assert.Contains("a=label:2", offer);
        Assert.Contains("application/rs-metadata+xml", offer);

        var answer = "v=0\r\no=srs 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
                     $"m=audio {labelOne.Port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=label:1\r\na=recvonly\r\n" +
                     $"m=audio {labelTwo.Port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=label:2\r\na=recvonly\r\n";
        server.Send(
            Peer.Answer(offer, "200 OK", "srs",
                $"Contact: <sip:srs@{server.Address};transport=tcp>\r\nContent-Type: application/sdp\r\n", answer));

        var copy = await labelOne.DatagramAsync();
        Assert.Equal(0x80, copy[0] & 0xc0);
        Assert.Equal(0, copy[1] & 0x7f);

        call.StopRecordingTo();
        Assert.Null(call.RecordingSession);
        await server.MessageAsync(m => m.StartsWith("BYE ", StringComparison.Ordinal) && Peer.Header("Call-ID", m) == Peer.Header("Call-ID", offer));
        var twice = Assert.Throws<SipralException>(() => call.StopRecordingTo());
        Assert.Equal(SipralStatus.WrongState, twice.Status);
    }

    [Fact]
    public async Task ACallWithNoMediaYetCannotBeRecorded()
    {
        var alice = Stack();
        var bob = Stack();
        var account = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        var call = Own(alice.PlaceCall(account, $"sip:bob@{bob.BindAddress}"));
        var refused = Assert.Throws<SipralException>(() => call.RecordTo("sip:srs@example.com"));
        Assert.Equal(SipralStatus.WrongState, refused.Status);
        await FirstMatchingAsync(bob.Events, e => e.Kind == SipralEventKind.IncomingCall);
    }

    // -- helpers -----------------------------------------------------------

    private static async Task<string> TypedAsync(IAsyncEnumerable<string> text, string expected)
    {
        using var cts = new CancellationTokenSource(Timeout);
        var typed = new StringBuilder();
        try
        {
            await foreach (var piece in text.WithCancellation(cts.Token))
            {
                typed.Append(piece);
                if (typed.Length >= expected.Length)
                {
                    return typed.ToString();
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        throw new TimeoutException($"only {typed} was typed within {Timeout}");
    }

    private static async Task<T> FirstMatchingAsync<T>(IAsyncEnumerable<T> source, Func<T, bool> predicate)
    {
        using var cts = new CancellationTokenSource(Timeout);
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
        throw new TimeoutException($"nothing matching arrived within {Timeout}");
    }

    /// <summary>A UDP socket on loopback that reads SIP as text and writes
    /// what a test hands it: a notifier, a compositor, or a far end's RTP
    /// port.</summary>
    private sealed class Peer : IDisposable
    {
        private readonly UdpClient _socket = new(new IPEndPoint(IPAddress.Loopback, 0));

        public int Port => ((IPEndPoint)_socket.Client.LocalEndPoint!).Port;
        public string Address => $"127.0.0.1:{Port}";

        public static string? Header(string name, string message) =>
            message.Split("\r\n")
                .TakeWhile(line => line.Length > 0)
                .FirstOrDefault(line => line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
                ?.Split(':', 2)[1].Trim();

        /// <summary>The URI inside a name-addr's angle brackets.</summary>
        public static string Uri(string nameAddr)
        {
            var open = nameAddr.IndexOf('<');
            var close = nameAddr.IndexOf('>');
            return open >= 0 && close > open ? nameAddr[(open + 1)..close] : nameAddr;
        }

        /// <summary>A response to <paramref name="request"/>, its dialog's
        /// headers copied and <paramref name="tag"/> on its <c>To</c>.</summary>
        public static string Answer(string request, string status, string tag, string more, string body = "")
        {
            var lines = new StringBuilder($"SIP/2.0 {status}\r\n");
            foreach (var name in new[] { "Via", "From", "To", "Call-ID", "CSeq" })
            {
                var value = Header(name, request);
                lines.Append(name == "To" ? $"To: {value};tag={tag}\r\n" : $"{name}: {value}\r\n");
            }
            lines.Append(more);
            lines.Append($"Content-Length: {Encoding.UTF8.GetByteCount(body)}\r\n\r\n");
            lines.Append(body);
            return lines.ToString();
        }

        /// <summary>A notification in the dialog <paramref name="subscribe"/>
        /// opened, carrying <paramref name="body"/>.</summary>
        public static string Notify(string subscribe, string from, string package, string type, string body, int cseq) =>
            $"NOTIFY {Uri(Header("Contact", subscribe)!)} SIP/2.0\r\n" +
            $"Via: SIP/2.0/UDP {from};branch=z9hG4bK-notify-{cseq}\r\n" +
            "Max-Forwards: 70\r\n" +
            $"From: {Header("To", subscribe)};tag=notifier\r\n" +
            $"To: {Header("From", subscribe)}\r\n" +
            $"Call-ID: {Header("Call-ID", subscribe)}\r\n" +
            $"CSeq: {cseq} NOTIFY\r\n" +
            $"Contact: <sip:notifier@{from}>\r\n" +
            $"Event: {package}\r\n" +
            "Subscription-State: active;expires=3600\r\n" +
            $"Content-Type: {type}\r\n" +
            $"Content-Length: {Encoding.UTF8.GetByteCount(body)}\r\n\r\n" + body;

        public void Send(string message, string to)
        {
            var bytes = Encoding.UTF8.GetBytes(message);
            var (host, port) = SipralStack.ParseAddress(to);
            _socket.Send(bytes, bytes.Length, new IPEndPoint(IPAddress.Parse(host), port));
        }

        public async Task<byte[]> DatagramAsync()
        {
            using var cts = new CancellationTokenSource(Timeout);
            return (await _socket.ReceiveAsync(cts.Token)).Buffer;
        }

        /// <summary>The next request with <paramref name="method"/>, every
        /// other datagram — the stack's answers to NOTIFYs among them —
        /// passed over.</summary>
        public async Task<string> RequestAsync(string method)
        {
            while (true)
            {
                var text = Encoding.UTF8.GetString(await DatagramAsync());
                if (text.StartsWith(method + " ", StringComparison.Ordinal))
                {
                    return text;
                }
            }
        }

        public void Dispose() => _socket.Dispose();
    }

    /// <summary>A TCP listener on loopback that takes the one connection a
    /// stack signalling over TCP opens, and reads and writes SIP on it,
    /// framed by <c>Content-Length</c>.</summary>
    private sealed class StreamPeer : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly TaskCompletionSource<NetworkStream> _stream = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly System.Threading.Channels.Channel<string> _messages = System.Threading.Channels.Channel.CreateUnbounded<string>();
        private TcpClient? _client;

        public StreamPeer()
        {
            _listener.Start();
            _ = Task.Run(AcceptAsync);
        }

        public string Address => $"127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}";

        public async Task ConnectedAsync()
        {
            using var cts = new CancellationTokenSource(Timeout);
            await _stream.Task.WaitAsync(cts.Token);
        }

        private async Task AcceptAsync()
        {
            try
            {
                _client = await _listener.AcceptTcpClientAsync();
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                return;
            }
            var stream = _client.GetStream();
            _stream.TrySetResult(stream);
            var held = string.Empty;
            var buffer = new byte[65536];
            try
            {
                while (true)
                {
                    var read = await stream.ReadAsync(buffer);
                    if (read == 0)
                    {
                        break;
                    }
                    held += Encoding.UTF8.GetString(buffer, 0, read);
                    while (held.IndexOf("\r\n\r\n", StringComparison.Ordinal) is var end and >= 0)
                    {
                        var length = int.Parse(Peer.Header("Content-Length", held[..(end + 2)]) ?? "0");
                        if (held.Length < end + 4 + length)
                        {
                            break;
                        }
                        _messages.Writer.TryWrite(held[..(end + 4 + length)]);
                        held = held[(end + 4 + length)..];
                    }
                    held = held.TrimStart('\r', '\n');
                }
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
            }
        }

        public void Send(string message)
        {
            _stream.Task.Result.Write(Encoding.UTF8.GetBytes(message));
        }

        public async Task<string> MessageAsync(Func<string, bool> wanted)
        {
            using var cts = new CancellationTokenSource(Timeout);
            await foreach (var message in _messages.Reader.ReadAllAsync(cts.Token))
            {
                if (wanted(message))
                {
                    return message;
                }
            }
            throw new TimeoutException("the connection closed");
        }

        public void Dispose()
        {
            _listener.Stop();
            _client?.Dispose();
        }
    }
}
