// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;

namespace Sipral;

/// <summary>
/// What a <see cref="SipralStack.SetMessageHook"/> hook answers for one
/// message: <see cref="Keep"/> lets it on as it is,
/// <see cref="Replace"/> puts other bytes in its place, and
/// <see cref="Drop"/> stops it.
/// </summary>
public sealed class SipralMessageVerdict
{
    private SipralMessageVerdict(uint answer, byte[]? replacement)
    {
        Answer = answer;
        Replacement = replacement;
    }

    /// <summary>The message goes on as it is.</summary>
    public static SipralMessageVerdict Keep { get; } = new(global::Sipral.Sipral.HookKeep, null);

    /// <summary>The message is not sent, or not read. A transaction whose
    /// message is dropped retransmits and times out as if it were lost.</summary>
    public static SipralMessageVerdict Drop { get; } = new(global::Sipral.Sipral.HookDrop, null);

    /// <summary>These bytes go in the message's place, from its start line
    /// to the end of its body; <c>Content-Length</c> must match the
    /// body.</summary>
    public static SipralMessageVerdict Replace(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);
        return new(global::Sipral.Sipral.HookReplace, message);
    }

    internal uint Answer { get; }

    /// <summary>The bytes of a <see cref="Replace"/>, null otherwise.</summary>
    public byte[]? Replacement { get; }
}
