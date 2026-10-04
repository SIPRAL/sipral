// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System.Runtime.CompilerServices;

// Lets `bindings/dotnet/Sipral.Tests` reach the internal handle values and
// `NativeMethods` directly, for the tests that exercise the threading
// rules themselves — a second thread's raw entry-point call observing
// `SIPRAL_STATUS_BUSY`, and a callback surviving GC pressure — rather
// than only the public surface built on top of them.
[assembly: InternalsVisibleTo("Sipral.Tests")]
