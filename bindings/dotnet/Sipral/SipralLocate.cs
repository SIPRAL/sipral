// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Sipral.Interop;

namespace Sipral;

/// <summary>A resolver's answer to one lookup. Each record is its TTL in
/// seconds, then its data in zone-file form, e.g.
/// <c>300 10 60 5060 sip1.example.com</c>.</summary>
public sealed record SipralLookup(SipralDnsAnswer Answer, IReadOnlyList<string> Records)
{
    /// <summary>The name has no record of that kind, or does not
    /// exist.</summary>
    public static SipralLookup Nothing { get; } = new(SipralDnsAnswer.Nothing, Array.Empty<string>());

    /// <summary>The resolver could not answer.</summary>
    public static SipralLookup Failed { get; } = new(SipralDnsAnswer.Failed, Array.Empty<string>());
}

/// <summary>Answers <see cref="SipralEventKind.LookupWanted"/> for accounts
/// added with <c>serverUri</c>. Runs on its own thread per lookup and may
/// block.</summary>
public delegate SipralLookup SipralResolver(string name, SipralDnsRecordType record);

/// <summary>
/// The default resolver. .NET only resolves addresses, so those come from
/// <see cref="Dns.GetHostAddresses(string)"/> with TTL
/// <see cref="AddressTtl"/> (the real one is not exposed). SRV and NAPTR are
/// queried here, to each of <see cref="Servers"/> in turn.
/// </summary>
public static class SipralDns
{
    /// <summary>TTL, in seconds, given to platform-resolved addresses.</summary>
    public const uint AddressTtl = 60;

    /// <summary>How long one DNS server may take to answer.</summary>
    public static readonly TimeSpan Patience = TimeSpan.FromSeconds(2);

    private const ushort TypeSrv = 33;
    private const ushort TypeNaptr = 35;

    /// <summary>The platform resolver described above.</summary>
    public static SipralResolver Platform { get; } = (name, record) => record switch
    {
        SipralDnsRecordType.A => Addresses(name, AddressFamily.InterNetwork),
        SipralDnsRecordType.Aaaa => Addresses(name, AddressFamily.InterNetworkV6),
        SipralDnsRecordType.Srv or SipralDnsRecordType.Naptr => Query(name, record, Servers()),
        _ => SipralLookup.Nothing,
    };

    /// <summary>The addresses of one family <see cref="Dns"/> finds for
    /// <paramref name="name"/>.</summary>
    public static SipralLookup Addresses(string name, AddressFamily family)
    {
        IPAddress[] found;
        try
        {
            found = Dns.GetHostAddresses(name, family);
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.HostNotFound or SocketError.NoData)
        {
            return SipralLookup.Nothing;
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            return SipralLookup.Failed;
        }
        var records = found.Where(one => one.AddressFamily == family)
            .Select(one => one.ToString().Split('%')[0]).Distinct()
            .Select(one => $"{AddressTtl} {one}").ToList();
        return records.Count == 0 ? SipralLookup.Nothing : new SipralLookup(SipralDnsAnswer.Records, records);
    }

    /// <summary>The DNS servers the interfaces name, else those in
    /// <c>/etc/resolv.conf</c>.</summary>
    public static IReadOnlyList<IPEndPoint> Servers()
    {
#if ANDROID
        // Android names no DNS server per interface and has no resolv.conf
        // an application may read: the active network's link says them,
        // from Android 6 (API 23); before it, none is known
        return OperatingSystem.IsAndroidVersionAtLeast(23)
            ? AndroidServers().Distinct().Select(one => new IPEndPoint(one, 53)).ToList()
            : new List<IPEndPoint>();
#else
        var found = new List<IPAddress>();
        try
        {
            foreach (var network in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (network.OperationalStatus == OperationalStatus.Up)
                {
                    found.AddRange(network.GetIPProperties().DnsAddresses);
                }
            }
        }
        catch (NetworkInformationException)
        {
            // read from the file below instead
        }
        if (found.Count == 0 && File.Exists("/etc/resolv.conf"))
        {
            foreach (var line in File.ReadAllLines("/etc/resolv.conf"))
            {
                var words = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (words.Length >= 2 && words[0] == "nameserver" && IPAddress.TryParse(words[1].Split('%')[0], out var one))
                {
                    found.Add(one);
                }
            }
        }
        return found.Distinct().Select(one => new IPEndPoint(one, 53)).ToList();
#endif
    }

#if ANDROID
    [System.Runtime.Versioning.SupportedOSPlatform("android23.0")]
    private static IEnumerable<IPAddress> AndroidServers()
    {
        var manager = Android.App.Application.Context.GetSystemService(Android.Content.Context.ConnectivityService)
            as Android.Net.ConnectivityManager;
        var network = manager?.ActiveNetwork;
        var link = network is null ? null : manager!.GetLinkProperties(network);
        if (link is null)
        {
            yield break;
        }
        foreach (var server in link.DnsServers)
        {
            if (IPAddress.TryParse((server.HostAddress ?? "").Split('%')[0], out var one))
            {
                yield return one;
            }
        }
    }
#endif

    /// <summary>One SRV or NAPTR query, to each of
    /// <paramref name="servers"/> in turn until one answers. A reply counts
    /// only if it matches source, id and question (RFC 5452 §9.1); anything
    /// else is ignored. A truncated reply is retried over TCP (RFC 1035
    /// §4.2.2, RFC 7766).</summary>
    public static SipralLookup Query(string name, SipralDnsRecordType record, IReadOnlyList<IPEndPoint> servers)
    {
        var type = record == SipralDnsRecordType.Srv ? TypeSrv : TypeNaptr;
        foreach (var server in servers)
        {
            var id = (ushort)RandomNumberGenerator.GetInt32(0, 0x10000);
            var question = Question(id, name, type);
            try
            {
                var reply = OverUdp(server, question, id, name, type);
                if (reply is not null && (reply[2] & 0x02) != 0)
                {
                    reply = OverTcp(server, question, id, name, type);
                }
                if (reply is not null)
                {
                    return Answer(reply, type, record);
                }
            }
            catch (Exception ex) when (ex is SocketException or IOException or AggregateException)
            {
                // next server
            }
        }
        return SipralLookup.Failed;
    }

    private static byte[]? OverUdp(IPEndPoint server, byte[] question, ushort id, string name, ushort type)
    {
        using var socket = new UdpClient(server.AddressFamily);
        socket.Send(question, question.Length, server);
        var deadline = DateTime.UtcNow + Patience;
        while (true)
        {
            var left = deadline - DateTime.UtcNow;
            if (left <= TimeSpan.Zero)
            {
                return null;
            }
            socket.Client.ReceiveTimeout = Math.Max(1, (int)left.TotalMilliseconds);
            IPEndPoint? from = null;
            byte[] reply;
            try
            {
                reply = socket.Receive(ref from);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
            {
                return null;
            }
            if (SameEndPoint(from, server) && Answers(reply, id, name, type))
            {
                return reply;
            }
        }
    }

    // Length-prefixed messages (RFC 1035 §4.2.2).
    private static byte[]? OverTcp(IPEndPoint server, byte[] question, ushort id, string name, ushort type)
    {
        using var client = new TcpClient(server.AddressFamily);
        client.SendTimeout = (int)Patience.TotalMilliseconds;
        client.ReceiveTimeout = (int)Patience.TotalMilliseconds;
        if (!client.ConnectAsync(server.Address, server.Port).Wait(Patience))
        {
            return null;
        }
        using var stream = client.GetStream();
        var framed = new byte[question.Length + 2];
        framed[0] = (byte)(question.Length >> 8);
        framed[1] = (byte)question.Length;
        question.CopyTo(framed, 2);
        stream.Write(framed, 0, framed.Length);
        var length = new byte[2];
        stream.ReadExactly(length, 0, 2);
        var reply = new byte[length[0] << 8 | length[1]];
        stream.ReadExactly(reply, 0, reply.Length);
        return Answers(reply, id, name, type) ? reply : null;
    }

    private static bool SameEndPoint(IPEndPoint? from, IPEndPoint server) =>
        from is not null && from.Port == server.Port
        && (from.Address.Equals(server.Address)
            || (from.Address.IsIPv4MappedToIPv6 && from.Address.MapToIPv4().Equals(server.Address)));

    // RFC 5452 §9.1: same id, QR set, one question echoing name, type, IN.
    internal static bool Answers(byte[] reply, ushort id, string name, ushort type)
    {
        if (reply.Length < 12 || (reply[0] << 8 | reply[1]) != id || (reply[2] & 0x80) == 0
            || (reply[4] << 8 | reply[5]) != 1)
        {
            return false;
        }
        try
        {
            var at = 12;
            var asked = Name(reply, ref at);
            var askedType = reply[at] << 8 | reply[at + 1];
            var askedClass = reply[at + 2] << 8 | reply[at + 3];
            return askedType == type && askedClass == 1
                && string.Equals(asked, name.TrimEnd('.'), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentException)
        {
            // a question that runs past the end of the reply answers nothing
            return false;
        }
    }

    // RFC 1035 §4.1, recursion desired.
    private static byte[] Question(ushort id, string name, ushort type)
    {
        var message = new List<byte> { (byte)(id >> 8), (byte)id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            message.Add((byte)bytes.Length);
            message.AddRange(bytes);
        }
        message.AddRange(new byte[] { 0, (byte)(type >> 8), (byte)type, 0, 1 });
        return message.ToArray();
    }

    // NXDOMAIN is Nothing; SERVFAIL or REFUSED is Failed.
    internal static SipralLookup Answer(byte[] reply, ushort type, SipralDnsRecordType record)
    {
        var code = reply[3] & 0x0F;
        if (code == 3)
        {
            return SipralLookup.Nothing;
        }
        if (code != 0)
        {
            return SipralLookup.Failed;
        }
        var questions = reply[4] << 8 | reply[5];
        var answers = reply[6] << 8 | reply[7];
        var at = 12;
        try
        {
            for (var i = 0; i < questions; i++)
            {
                Name(reply, ref at);
                at += 4;
            }
            var records = new List<string>();
            for (var i = 0; i < answers; i++)
            {
                Name(reply, ref at);
                var kind = reply[at] << 8 | reply[at + 1];
                var ttl = (uint)(reply[at + 4] << 24 | reply[at + 5] << 16 | reply[at + 6] << 8 | reply[at + 7]);
                var length = reply[at + 8] << 8 | reply[at + 9];
                at += 10;
                var data = at;
                at += length;
                if (kind != type || at > reply.Length)
                {
                    continue;
                }
                records.Add(record == SipralDnsRecordType.Srv ? Srv(reply, data, ttl) : Naptr(reply, data, ttl));
            }
            return records.Count == 0 ? SipralLookup.Nothing : new SipralLookup(SipralDnsAnswer.Records, records);
        }
        catch (IndexOutOfRangeException)
        {
            return SipralLookup.Failed;
        }
    }

    private static string Srv(byte[] reply, int at, uint ttl)
    {
        var priority = reply[at] << 8 | reply[at + 1];
        var weight = reply[at + 2] << 8 | reply[at + 3];
        var port = reply[at + 4] << 8 | reply[at + 5];
        at += 6;
        return $"{ttl} {priority} {weight} {port} {Name(reply, ref at)}";
    }

    // The regexp field is dropped: RFC 3263 uses none.
    private static string Naptr(byte[] reply, int at, uint ttl)
    {
        var order = reply[at] << 8 | reply[at + 1];
        var preference = reply[at + 2] << 8 | reply[at + 3];
        at += 4;
        var flags = Characters(reply, ref at);
        var service = Characters(reply, ref at);
        Characters(reply, ref at);
        return $"{ttl} {order} {preference} {(flags.Length == 0 ? "\"\"" : flags)} {service} {Name(reply, ref at)}";
    }

    private static string Characters(byte[] reply, ref int at)
    {
        var length = reply[at];
        var text = Encoding.ASCII.GetString(reply, at + 1, length);
        at += 1 + length;
        return text;
    }

    // Follows compression pointers (RFC 1035 §4.1.4); "." for the root.
    private static string Name(byte[] reply, ref int at)
    {
        var labels = new List<string>();
        var position = at;
        var jumped = false;
        for (var hops = 0; hops < 64; hops++)
        {
            var length = reply[position];
            if (length == 0)
            {
                if (!jumped)
                {
                    at = position + 1;
                }
                return labels.Count == 0 ? "." : string.Join(".", labels);
            }
            if ((length & 0xC0) == 0xC0)
            {
                if (!jumped)
                {
                    at = position + 2;
                }
                position = (length & 0x3F) << 8 | reply[position + 1];
                jumped = true;
                continue;
            }
            labels.Add(Encoding.ASCII.GetString(reply, position + 1, length));
            position += 1 + length;
        }
        throw new IndexOutOfRangeException("a name that points at itself");
    }
}

public sealed partial class SipralStack
{
    // No bindHost: the advertised address is the route toward the first
    // account's server, picked again after every move.
    private bool _routes;
    private bool _routeChosen;
    private readonly object _routeLock = new();
    private SipralResolver _resolver = SipralDns.Platform;

    // Queued during the poll, acted on right after it.
    private readonly ConcurrentQueue<(ulong Account, string Name, SipralDnsRecordType Record)> _lookupsAsked = new();
    private readonly ConcurrentQueue<(ulong Account, string Target)> _located = new();

    /// <summary><c>sipral_advertised_address</c>: what to advertise for a
    /// socket at <paramref name="bound"/> talking to <paramref name="peer"/>
    /// (both addresses, not names). A wildcard bind gives the route toward
    /// the peer. Loopback toward a remote peer throws with
    /// <see cref="SipralStatus.UnreachableAddress"/>; no route, with
    /// <see cref="SipralStatus.TransportDown"/>.</summary>
    public static string AdvertisedAddress(string bound, string peer)
    {
        NativeLibraryLoader.EnsureRegistered();
        var buffer = new sbyte[128];
        var needed = global::Sipral.Sipral.AdvertisedAddress(bound, peer, buffer);
        return NativeText.FromSBytes(buffer, (int)needed - 1);
    }

    /// <summary>This machine's address on the route toward
    /// <paramref name="peer"/>; <c>127.0.0.1</c> when there is no peer, it
    /// is a name, or no route reaches it.</summary>
    public static string RouteHost(string? peer)
    {
        if (peer is null || !IsAddress(peer))
        {
            return "127.0.0.1";
        }
        try
        {
            return ParseAddress(AdvertisedAddress(peer.StartsWith('[') ? "[::]:0" : "0.0.0.0:0", peer)).Host;
        }
        catch (SipralException)
        {
            return "127.0.0.1";
        }
    }

    internal static bool IsAddress(string text)
    {
        var colon = text.LastIndexOf(':');
        return colon > 0 && int.TryParse(text[(colon + 1)..], out _)
            && IPAddress.TryParse(text[..colon].Trim('[', ']'), out _);
    }

    // The route toward the server on this stack's port. The first server
    // named also sets the Via address.
    internal string AdvertiseToward(string peer)
    {
        var address = $"{RouteHost(peer)}:{ParseAddress(BindAddress).Port}";
        bool first;
        lock (_routeLock)
        {
            first = !_routeChosen;
            _routeChosen = true;
        }
        if (first && address != BindAddress)
        {
            AdvertiseMain(address);
        }
        return address;
    }

    private void AdvertiseMain(string address)
    {
        var local = NativeText.ToSBytes(address);
        SipralErrors.Call(
            () => NativeMethods.sipral_stack_transport_bind(
                Handle, global::Sipral.Sipral.TransportMain, (uint)SipralTransport.Udp, local, (nuint)local.Length,
                null!, 0, NowMs, out _),
            "sipral_stack_transport_bind");
        BindAddress = address;
    }

    // After a move: the route toward the first account's server, else host,
    // on the same port. The wildcard socket stays; an address this machine
    // lacks throws, as binding there would.
    private void AdvertiseAgain(string host)
    {
        var address = IPAddress.Parse(host);
        using (var probe = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
        {
            probe.Bind(new IPEndPoint(address, 0));
        }
        KeptSignallingPort = true;
        lock (_routeLock)
        {
            _routeChosen = false;
        }
        string? server;
        lock (_accounts)
        {
            server = _accounts.Select(one => one.RegistrarAddress).FirstOrDefault(IsAddress);
        }
        if (server is not null)
        {
            AdvertiseToward(server);
            return;
        }
        var local = $"{host}:{ParseAddress(BindAddress).Port}";
        if (local != BindAddress)
        {
            AdvertiseMain(local);
        }
    }

    internal bool PicksAddress
    {
        get
        {
            lock (_routeLock)
            {
                return _routes && !Streamed;
            }
        }
    }

    // mediaHost, else the route toward the destination, the account's
    // server, or the stack's own address.
    private string MediaHostFor(string? mediaHost, Account? account, string? destination)
    {
        if (mediaHost is not null)
        {
            return mediaHost;
        }
        foreach (var peer in new[] { destination, account?.RegistrarAddress })
        {
            if (peer is not null && IsAddress(peer))
            {
                return RouteHost(peer);
            }
        }
        return ParseAddress(BindAddress).Host;
    }

    private Account? AccountFor(ulong handle)
    {
        lock (_accounts)
        {
            return _accounts.FirstOrDefault(one => one.Handle == handle);
        }
    }

    private void NoteLocate(SipralEventArgs args)
    {
        if (args.Locate is not { } locate)
        {
            return;
        }
        if (args.Kind == SipralEventKind.LookupWanted && locate.Name is { } name)
        {
            _lookupsAsked.Enqueue((args.Account, name, locate.Record));
        }
        else if (args.Kind == SipralEventKind.Located && locate.Targets is { Length: > 0 } targets)
        {
            _located.Enqueue((args.Account, targets.Split(',')[0]));
        }
    }

    // Each lookup gets its own thread: a resolver may take seconds and the
    // poll thread must not wait. A newly located account is pointed at its
    // server and, when the stack picks addresses, rerouted.
    private void ActOnLookups()
    {
        while (_lookupsAsked.TryDequeue(out var asked))
        {
            var resolver = _resolver;
            Task.Run(() => LookedUp(asked.Account, asked.Name, asked.Record, Resolve(resolver, asked.Name, asked.Record)));
        }
        while (_located.TryDequeue(out var found))
        {
            var account = AccountFor(found.Account);
            if (account is null)
            {
                continue;
            }
            account.Located(found.Target);
            if (!PicksAddress || account.ContactGiven)
            {
                continue;
            }
            try
            {
                account.Reach(AdvertiseToward(found.Target), found.Target);
            }
            catch (SipralException)
            {
                // account removed meanwhile
            }
        }
    }

    private static SipralLookup Resolve(SipralResolver resolver, string name, SipralDnsRecordType record)
    {
        try
        {
            return resolver(name, record);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // a failure is still an answer; the stack waits for every one
            return SipralLookup.Failed;
        }
    }

    private void LookedUp(ulong account, string name, SipralDnsRecordType record, SipralLookup answer)
    {
        if (_closed.IsSet)
        {
            return;
        }
        var nameBytes = NativeText.ToSBytes(name);
        var recordsBytes = NativeText.ToSBytes(string.Join(",", answer.Records));
        try
        {
            SipralErrors.Call(
                () => NativeMethods.sipral_account_looked_up(
                    Handle, account, nameBytes, (nuint)nameBytes.Length, (uint)record, (uint)answer.Answer,
                    recordsBytes, (nuint)recordsBytes.Length, NowMs),
                "sipral_account_looked_up");
        }
        catch (Exception ex) when (ex is SipralException or ObjectDisposedException)
        {
            // the account, or the stack, went away while the resolver ran
        }
    }

    /// <summary><c>sipral_stack_diagnostic_trace</c>: log whole SIP messages
    /// with peers, instead of pseudonymised, at
    /// <see cref="SipralLogLevel.Trace"/>. Credentials and keys are removed
    /// either way.</summary>
    public void SetDiagnosticTrace(bool on)
    {
        SipralErrors.Call(
            () => NativeMethods.sipral_stack_diagnostic_trace(Handle, (uint)(on ? SipralToggle.On : SipralToggle.Off)),
            "sipral_stack_diagnostic_trace");
    }

    /// <summary>What the stack runs with, every default filled in
    /// (<c>sipral_stack_settings</c>), with the SRTP suites its calls offer in
    /// order (<c>sipral_stack_srtp_suite_order</c>).</summary>
    public SipralSettings Settings()
    {
        var raw = SipralStackSettings.Sized();
        SipralErrors.Call(() => NativeMethods.sipral_stack_settings(Handle, ref raw), "sipral_stack_settings");
        var suites = new uint[raw.SrtpSuiteCount];
        SipralErrors.Call(
            () => NativeMethods.sipral_stack_srtp_suite_order(Handle, suites, (nuint)suites.Length, out _),
            "sipral_stack_srtp_suite_order");
        return SipralSettings.Of(raw, suites);
    }

    /// <summary>The per-call diagnostic record as JSON
    /// (<c>sipral_stack_diagnostics_json</c>): each decision and why.</summary>
    public string DiagnosticsJson()
    {
        var capacity = 4096;
        while (true)
        {
            var buffer = new sbyte[capacity];
            var status = NativeMethods.sipral_stack_diagnostics_json(Handle, buffer, (nuint)buffer.Length, out var needed);
            if (status == SipralStatus.BufferTooSmall)
            {
                capacity = (int)needed;
                continue;
            }
            if (status == SipralStatus.Busy)
            {
                System.Threading.Thread.Sleep(1);
                continue;
            }
            SipralErrors.Check(status, "sipral_stack_diagnostics_json");
            return NativeText.FromSBytes(buffer, (int)needed - 1);
        }
    }
}
