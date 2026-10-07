// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace Sipral.Interop;

/// <summary>
/// Finds the native library when it is not packaged under
/// <c>runtimes/</c> (tests, lab containers, a checkout). A NuGet package
/// loads without help; otherwise the runtime would throw
/// <see cref="DllNotFoundException"/> although the library exists.
/// </summary>
internal static class NativeLibraryLoader
{
    private static int _registered;

    /// <summary>
    /// Registers the resolver once; safe to call repeatedly. Not a
    /// <c>[ModuleInitializer]</c>, which would run for every consumer of the
    /// assembly (CA2255).
    /// </summary>
    internal static void EnsureRegistered()
    {
        if (Interlocked.Exchange(ref _registered, 1) != 0)
        {
            return;
        }
        // A mobile application carries the library itself: linked in on iOS
        // and Mac Catalyst, under lib/<abi>/ of the APK on Android, where the
        // runtime finds it unaided and no checkout exists to search.
        if (OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst() || OperatingSystem.IsAndroid())
        {
            return;
        }
        NativeLibrary.SetDllImportResolver(typeof(NativeLibraryLoader).Assembly, Resolve);
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!string.Equals(libraryName, NativeMethods.Library, StringComparison.Ordinal))
        {
            return IntPtr.Zero;
        }

        foreach (var candidate in Candidates())
        {
            if (File.Exists(candidate) && NativeLibrary.TryLoad(candidate, out var handle))
            {
                return handle;
            }
        }

        var tried = string.Join(Environment.NewLine, EnumerateTried());
        throw new DllNotFoundException(
            "sipral: could not find " + PlatformLibraryFileName() + ". Tried:" + Environment.NewLine +
            tried + Environment.NewLine + Environment.NewLine +
            "Build it with `cargo build --release -p sipral-ffi`, " +
            "or set SIPRAL_LIBRARY to its path or its directory.");
    }

    private static string PlatformLibraryFileName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return "libsipral_ffi.dylib";
        }
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return "sipral_ffi.dll";
        }
        return "libsipral_ffi.so";
    }

    private static IEnumerable<string> EnumerateTried()
    {
        foreach (var candidate in Candidates())
        {
            yield return "  " + candidate;
        }
    }

    /// <summary>
    /// In order: <c>SIPRAL_LIBRARY</c> (file or directory), beside this
    /// assembly, then <c>target/release</c> and <c>target/debug</c> found by
    /// walking up, since the output depth varies.
    /// </summary>
    private static IEnumerable<string> Candidates()
    {
        var name = PlatformLibraryFileName();

        var overridePath = Environment.GetEnvironmentVariable("SIPRAL_LIBRARY");
        if (!string.IsNullOrEmpty(overridePath))
        {
            yield return Directory.Exists(overridePath) ? Path.Combine(overridePath, name) : overridePath;
        }

        var assemblyDir = Path.GetDirectoryName(typeof(NativeLibraryLoader).Assembly.Location);
        if (assemblyDir is null)
        {
            yield break;
        }

        yield return Path.Combine(assemblyDir, name);

        var probe = new DirectoryInfo(assemblyDir);
        for (var i = 0; i < 12 && probe is not null; i++, probe = probe.Parent)
        {
            var release = Path.Combine(probe.FullName, "target", "release", name);
            var debug = Path.Combine(probe.FullName, "target", "debug", name);
            if (File.Exists(release) || File.Exists(debug) || Directory.Exists(Path.Combine(probe.FullName, "target")))
            {
                yield return release;
                yield return debug;
                yield break;
            }
        }
    }
}
