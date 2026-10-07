// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using Sipral.Interop;

namespace Sipral;

/// <summary>
/// The generated <see cref="Sipral"/>'s static constructor calls into the
/// library, so the resolver must be registered first, even when no
/// <see cref="SipralStack"/> was made.
/// </summary>
public static partial class Sipral
{
    static partial void BeforeLoad() => NativeLibraryLoader.EnsureRegistered();
}
