// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Runtime.InteropServices;

namespace Sipral.Interop;

/// <summary>
/// Pins a byte array for a struct's pointer member. The library reads a
/// struct only during the call that takes it, so a <see langword="using"/>
/// scope is enough. <see langword="null"/> or empty gives
/// <see cref="IntPtr.Zero"/>, read as "not given".
/// </summary>
internal readonly struct PinnedBytes : IDisposable
{
    private readonly GCHandle _handle;
    public IntPtr Pointer { get; }

    public PinnedBytes(byte[]? bytes)
    {
        if (bytes is null || bytes.Length == 0)
        {
            _handle = default;
            Pointer = IntPtr.Zero;
            return;
        }
        _handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        Pointer = _handle.AddrOfPinnedObject();
    }

    public void Dispose()
    {
        if (_handle.IsAllocated)
        {
            _handle.Free();
        }
    }
}
