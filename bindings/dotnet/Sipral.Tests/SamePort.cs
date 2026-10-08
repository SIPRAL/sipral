// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System.Net;
using System.Net.Sockets;

namespace Sipral.Tests;

/// <summary>A UDP socket and a TCP listener on one loopback port, the way a
/// server takes 5060 for both.</summary>
internal static class SamePort
{
    /// <summary>The system picks the UDP port, which says nothing about TCP:
    /// another process may hold that port for TCP already. Then the pair is
    /// tried again on another port rather than failing the test it serves.
    /// The listener is started; with <paramref name="tcp"/> false only the
    /// UDP socket is taken.</summary>
    public static (UdpClient Udp, TcpListener? Tcp) Take(bool tcp = true)
    {
        for (var attempt = 1; ; attempt++)
        {
            var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            if (!tcp)
            {
                return (udp, null);
            }
            var listener = new TcpListener(IPAddress.Loopback, ((IPEndPoint)udp.Client.LocalEndPoint!).Port);
            try
            {
                listener.Start();
                return (udp, listener);
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.AddressAlreadyInUse && attempt < 20)
            {
                udp.Dispose();
            }
        }
    }
}
