// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Text;

namespace Sipral.Interop;

/// <summary>
/// UTF-8 conversions for entry points taking <c>sbyte[]</c> (text) or
/// <c>byte[]</c> (raw bytes such as a SIP message). The marshaller pins them
/// for the call.
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
