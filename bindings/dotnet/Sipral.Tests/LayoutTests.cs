// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Runtime.InteropServices;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// The lengths tools/abi-gen worked out for every record, on the layout this
/// process runs on, held to what the marshaller lays each struct out as and
/// to the library's own answer. bindings/c/abi-layout.c holds a C compiler to
/// the same table on the layouts this machine cannot run.
/// </summary>
public class LayoutTests
{
    [Fact]
    public void EveryRecordIsAsLongAsTheLayoutSays()
    {
        var layouts = global::Sipral.Sipral.RecordLayouts();
        Assert.True(layouts.Length > 50, $"{layouts.Length} records");
        // 32-bit x86 aligns a 64-bit integer to four inside a struct on
        // every system but Windows, which aligns it to eight like ARM does
        var fourAligned = RuntimeInformation.ProcessArchitecture == Architecture.X86
            && !OperatingSystem.IsWindows();
        foreach (var (name, marshalled, p64, p32a4, p32a8) in layouts)
        {
            var expected = IntPtr.Size == 8 ? p64 : fourAligned ? p32a4 : p32a8;
            Assert.True(expected == marshalled, $"{name} marshals as {marshalled} bytes, not {expected}");
            Assert.Equal((nuint)expected, global::Sipral.Sipral.AbiStructSize(name));
        }
    }
}
