// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System.Collections.Generic;
using System.Text;

namespace Sipral;

/// <summary>
/// One INVITE as a <see cref="SipralStack.Screen"/> policy sees it, before it
/// has had any effect: where it came from and its bytes, copied out of
/// <c>sipral_screen_request_t</c> so they outlive the callback.
/// <see cref="Source"/> is the far end of the bytes as <c>host:port</c>, or
/// null for a stream bound without naming one.
/// </summary>
public sealed record SipralInvite(string? Source, byte[] Message)
{
    /// <summary>Every line of header field <paramref name="name"/>, in the
    /// order they arrived, read with <c>sipral_message_header</c>: a compact
    /// form and its long form are one field, and case does not matter. Safe
    /// inside a policy, since it reads these bytes and not the
    /// stack.</summary>
    public IReadOnlyList<string> Headers(string name)
    {
        var count = global::Sipral.Sipral.MessageHeaderCount(Message, name);
        var lines = new List<string>((int)count);
        for (nuint index = 0; index < count; index++)
        {
            var (offset, len) = global::Sipral.Sipral.MessageHeader(Message, name, index);
            lines.Add(Encoding.UTF8.GetString(Message, (int)offset, (int)len));
        }
        return lines;
    }

    /// <summary>The first line of header field <paramref name="name"/>, or
    /// null when the INVITE carries none.</summary>
    public string? Header(string name)
    {
        var lines = Headers(name);
        return lines.Count == 0 ? null : lines[0];
    }
}
