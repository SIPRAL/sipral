// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using Sipral.Interop;

namespace Sipral;

/// <summary>
/// The generated <see cref="Sipral"/> checks the ABI in its static
/// constructor, which is a call into the native library; a caller whose
/// first use of the library is that class, rather than a
/// <see cref="SipralStack"/>, reached it before anything had told the
/// runtime where the library is, and got a DllNotFoundException on a
/// machine where it plainly exists.
/// </summary>
public static partial class Sipral
{
    static partial void BeforeLoad() => NativeLibraryLoader.EnsureRegistered();
}
