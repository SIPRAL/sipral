// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// The .NET layer's own SRV and NAPTR client against a DNS server that
/// answers the way a test tells it to: only the reply RFC 5452 §9.1 matches
/// is taken — from the server asked, with the query's id and its question —
/// and a truncated one is asked again over TCP.
/// </summary>
public sealed class DnsClientTests
{
    private const string Asked = "_sip._udp.pbx.sipral.test";

    /// <summary>What the server does with one query: the replies it sends,
    /// each from its own socket or from a stranger's.</summary>
    private delegate IEnumerable<(bool FromStranger, byte[] Reply)> Script(byte[] query);

    /// <summary>A DNS server on loopback, UDP and TCP on one port, that hands
    /// every UDP query to a script and answers every TCP one
    /// properly.</summary>
    private sealed class ScriptedDns : IDisposable
    {
        private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly UdpClient _stranger = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly TcpListener _tcp;
        private readonly Script _script;
        private readonly Thread _udpThread;
        private readonly Thread _tcpThread;
        private volatile bool _stopped;
        private int _tcpQueries;

        /// <param name="tcp">Whether it takes TCP at all: one that does not
        /// refuses the connection a truncated reply leads to.</param>
        public ScriptedDns(Script script, bool tcp = true)
        {
            _script = script;
            _udp.Client.ReceiveTimeout = 50;
            EndPoint = (IPEndPoint)_udp.Client.LocalEndPoint!;
            _tcp = new TcpListener(IPAddress.Loopback, EndPoint.Port);
            if (tcp)
            {
                _tcp.Start();
            }
            _udpThread = new Thread(ServeUdp) { IsBackground = true };
            _tcpThread = new Thread(ServeTcp) { IsBackground = true };
            _udpThread.Start();
            if (tcp)
            {
                _tcpThread.Start();
            }
        }

        public IPEndPoint EndPoint { get; }

        public int TcpQueries => Volatile.Read(ref _tcpQueries);

        private void ServeUdp()
        {
            while (!_stopped)
            {
                IPEndPoint? from = null;
                byte[] query;
                try
                {
                    query = _udp.Receive(ref from);
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                {
                    continue;
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                {
                    return;
                }
                foreach (var (fromStranger, reply) in _script(query))
                {
                    (fromStranger ? _stranger : _udp).Send(reply, reply.Length, from!);
                    // each reply well ahead of the next, so that the one a
                    // test means to come first is the first to arrive
                    Thread.Sleep(100);
                }
            }
        }

        private void ServeTcp()
        {
            while (!_stopped)
            {
                TcpClient client;
                try
                {
                    client = _tcp.AcceptTcpClient();
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
                {
                    return;
                }
                using (client)
                using (var stream = client.GetStream())
                {
                    var length = new byte[2];
                    stream.ReadExactly(length, 0, 2);
                    var query = new byte[length[0] << 8 | length[1]];
                    stream.ReadExactly(query, 0, query.Length);
                    Interlocked.Increment(ref _tcpQueries);
                    var reply = Reply(query, port: 5070);
                    stream.Write(new[] { (byte)(reply.Length >> 8), (byte)reply.Length });
                    stream.Write(reply);
                }
            }
        }

        public void Dispose()
        {
            _stopped = true;
            _tcp.Stop();
            _udpThread.Join();
            if (_tcpThread.IsAlive)
            {
                _tcpThread.Join();
            }
            _udp.Dispose();
            _stranger.Dispose();
        }
    }

    /// <summary>The proper answer to <paramref name="query"/>: its id and its
    /// question, and one SRV record naming <paramref name="port"/> on
    /// pbx.sipral.test.</summary>
    private static byte[] Reply(byte[] query, int port = 5060, bool truncated = false)
    {
        var questionEnd = Array.IndexOf(query, (byte)0, 12) + 5;
        var reply = new List<byte>(query[..questionEnd]);
        reply[2] = (byte)(0x81 | (truncated ? 0x02 : 0));
        reply[3] = 0x80;
        reply[7] = 1;
        reply.AddRange(new byte[] { 0xC0, 12, 0, 33, 0, 1, 0, 0, 1, 44, 0, 8, 0, 10, 0, 60, (byte)(port >> 8), (byte)port, 0xC0, 12 + 5 + 5 });
        return reply.ToArray();
    }

    /// <summary><paramref name="reply"/> with another id.</summary>
    private static byte[] OtherId(byte[] reply)
    {
        var changed = (byte[])reply.Clone();
        changed[1] ^= 0x5A;
        return changed;
    }

    /// <summary><paramref name="reply"/> with a question that is not the one
    /// asked: one letter of its name changed.</summary>
    private static byte[] OtherQuestion(byte[] reply)
    {
        var changed = (byte[])reply.Clone();
        var at = Array.IndexOf(changed, (byte)'p', 12);
        changed[at] = (byte)'q';
        return changed;
    }

    private static SipralLookup Ask(ScriptedDns dns) =>
        SipralDns.Query(Asked, SipralDnsRecordType.Srv, new[] { dns.EndPoint });

    [Fact]
    public void AReplyFromAnotherSocketIsIgnoredAndTheServersTaken()
    {
        using var dns = new ScriptedDns(query => new[]
        {
            (true, Reply(query, port: 6666)),
            (false, Reply(query)),
        });
        var found = Ask(dns);
        Assert.Equal(SipralDnsAnswer.Records, found.Answer);
        Assert.Equal("300 10 60 5060 pbx.sipral.test", Assert.Single(found.Records));
    }

    [Fact]
    public void AReplyWithAnotherIdOrQuestionIsIgnored()
    {
        using var dns = new ScriptedDns(query => new[]
        {
            (false, OtherId(Reply(query, port: 6666))),
            (false, OtherQuestion(Reply(query, port: 6667))),
            (false, Reply(query)),
        });
        var found = Ask(dns);
        Assert.Equal("300 10 60 5060 pbx.sipral.test", Assert.Single(found.Records));
    }

    [Fact]
    public void TheQuestionIsMatchedInAnyCase()
    {
        using var dns = new ScriptedDns(query =>
        {
            var reply = Reply(query);
            var at = Array.IndexOf(reply, (byte)'p', 12);
            reply[at] = (byte)'P';
            return new[] { (false, reply) };
        });
        Assert.Equal("300 10 60 5060 pbx.sipral.test", Assert.Single(Ask(dns).Records));
    }

    [Fact]
    public void OnlyAStrangersReplyIsNoAnswerAtAll()
    {
        using var dns = new ScriptedDns(query => new[] { (true, Reply(query)) });
        Assert.Equal(SipralDnsAnswer.Failed, Ask(dns).Answer);
    }

    [Fact]
    public void ATruncatedReplyIsAskedAgainOverTcp()
    {
        using var dns = new ScriptedDns(query => new[] { (false, Reply(query, port: 6666, truncated: true)) });
        var found = Ask(dns);
        Assert.Equal(1, dns.TcpQueries);
        Assert.Equal("300 10 60 5070 pbx.sipral.test", Assert.Single(found.Records));
    }

    [Fact]
    public void AResponseMatchesOnlyItsOwnIdTypeAndDirection()
    {
        var asked = new List<byte> { 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in Asked.Split('.'))
        {
            asked.Add((byte)label.Length);
            asked.AddRange(Encoding.ASCII.GetBytes(label));
        }
        asked.AddRange(new byte[] { 0, 0, 33, 0, 1 });
        var reply = Reply(asked.ToArray());
        Assert.True(SipralDns.Answers(reply, 0x1234, Asked, 33));
        Assert.False(SipralDns.Answers(reply, 0x1234, Asked, 35), "another type");
        Assert.False(SipralDns.Answers(reply, 0x1235, Asked, 33), "another id");
        var notAResponse = (byte[])reply.Clone();
        notAResponse[2] &= 0x7F;
        Assert.False(SipralDns.Answers(notAResponse, 0x1234, Asked, 33), "a query, not a response");
    }
    [Fact]
    public void AReplyWhoseQuestionRunsPastItsEndIsIgnored()
    {
        // the id, the response bit and one question, then a label longer
        // than the bytes left: not an answer, and not a reason to stop
        // waiting for the real one
        static byte[] Cut(byte[] query)
        {
            var cut = query[..14];
            cut[2] = 0x81;
            return cut;
        }
        var asked = new List<byte> { 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in Asked.Split('.'))
        {
            asked.Add((byte)label.Length);
            asked.AddRange(Encoding.ASCII.GetBytes(label));
        }
        Assert.False(SipralDns.Answers(Cut(asked.ToArray()), 0x1234, Asked, 33));
        using var dns = new ScriptedDns(query => new[]
        {
            (false, Cut(query)),
            (false, Reply(query)),
        });
        Assert.Equal("300 10 60 5060 pbx.sipral.test", Assert.Single(Ask(dns).Records));
    }

    [Fact]
    public void ATruncatedReplyFromAServerWithoutTcpMovesToTheNextServer()
    {
        using var first = new ScriptedDns(query => new[] { (false, Reply(query, port: 6666, truncated: true)) }, tcp: false);
        using var second = new ScriptedDns(query => new[] { (false, Reply(query)) });
        var found = SipralDns.Query(Asked, SipralDnsRecordType.Srv, new[] { first.EndPoint, second.EndPoint });
        Assert.Equal("300 10 60 5060 pbx.sipral.test", Assert.Single(found.Records));
    }
}
