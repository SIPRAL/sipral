// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Runtime.InteropServices;

namespace Sipral.Interop;

/// <summary>
/// A short-lived pin on a managed byte array, handed to the native side
/// as an <see cref="IntPtr"/> for a versioned struct's own text/byte
/// member (<c>IntPtr</c> in every generated struct, per
/// <c>docs/08-ffi.md</c>'s "The conventions are load-bearing now") —
/// distinct from an entry point that takes text directly as
/// <c>sbyte[]</c>/<c>byte[]</c>, which the P/Invoke marshaller already
/// pins for the length of that one call and needs no help from this.
///
/// Every struct here is read once, inside the call that takes it, and
/// never touched again (<c>docs/08-ffi.md</c> calls a struct like this
/// "versioned" for exactly that reason), so a pin scoped to one
/// constructor or method — released the moment the call returns, via
/// <see langword="using"/> — is enough; nothing here has to outlive it.
/// <see langword="null"/> or an empty array pins nothing and hands over
/// <see cref="IntPtr.Zero"/>, which is what every optional member here
/// reads as "not given".
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
