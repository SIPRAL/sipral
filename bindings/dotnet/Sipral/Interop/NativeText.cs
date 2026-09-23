// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Text;

namespace Sipral.Interop;

/// <summary>
/// UTF-8 to/from <see cref="sbyte"/>/<see cref="byte"/> array conversions for
/// the entry points the generator printed to take text as <c>sbyte[]</c>
/// (every string in this ABI) or <c>byte[]</c> (the few members that are
/// bytes without being necessarily UTF-8, such as a SIP message or SDP).
/// The generator's own array-marshalling rule
/// (<c>docs/08-ffi.md</c>, "The conventions are load-bearing now") pins
/// and frees these for the length of one call; nothing here has to.
/// </summary>
internal static class NativeText
{
    internal static sbyte[] ToSBytes(string text) => ToSBytes(Encoding.UTF8.GetBytes(text));

    internal static sbyte[] ToSBytes(byte[] bytes)
    {
        var result = new sbyte[bytes.Length];
        Buffer.BlockCopy(bytes, 0, result, 0, bytes.Length);
        return result;
    }

    internal static sbyte[]? ToSBytesOrNull(string? text) => text is null ? null : ToSBytes(text);

    internal static string FromSBytes(sbyte[] bytes, int length)
    {
        var buffer = new byte[length];
        Buffer.BlockCopy(bytes, 0, buffer, 0, length);
        return Encoding.UTF8.GetString(buffer);
    }
}
