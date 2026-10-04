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
/// Points <c>NativeMethods.Library</c> ("sipral_ffi") at the actual shared
/// library the Rust workspace builds, <c>libsipral_ffi.{dylib,so}</c> or
/// <c>sipral_ffi.dll</c>, wherever it is.
///
/// The generated <c>SipralAbi.cs</c> names the library the way Cargo names
/// the crate's own file, so a NuGet package that carries it under
/// <c>runtimes/</c> loads with no help at all. What the runtime's own
/// search does not know is a library that has not been packaged: one a
/// test run or a lab container points at, or a checkout's own
/// <c>target/</c>. A caller in that position would otherwise get a
/// <see cref="DllNotFoundException"/> on a machine where the library
/// plainly exists. <see cref="NativeLibrary.SetDllImportResolver"/>
/// closes that gap the same way <c>bindings/python/sipral/_sipral_cffi.py</c>
/// closes it for `cffi`: try <c>SIPRAL_LIBRARY</c> first, then a path next
/// to this assembly, then a repository checkout's own <c>target/release</c>
/// and <c>target/debug</c>, found by walking up from this assembly's
/// directory rather than assuming a fixed depth, since a test runner's
/// output directory and a published application's are not the same
/// number of levels down.
/// </summary>
internal static class NativeLibraryLoader
{
    private static int _registered;

    /// <summary>
    /// Registers the resolver once per process. Safe to call more than
    /// once — every caller that is about to touch <c>NativeMethods</c>
    /// calls this first. Not a <c>[ModuleInitializer]</c>: that attribute
    /// runs for every consumer of this assembly whether or not it ever
    /// touches <see cref="NativeMethods"/>, which is exactly the surprise
    /// a library should not spring on an application that links it for
    /// something else (.NET's own analyzer flags it, CA2255, for that
    /// reason) — an explicit call at the one place that actually needs
    /// the resolver registered is the narrower fix.
    /// </summary>
    internal static void EnsureRegistered()
    {
        if (Interlocked.Exchange(ref _registered, 1) != 0)
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

    /// <summary>What the crate's <c>cdylib</c> is called on this platform.</summary>
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
    /// Where the library might be, in the order it is looked for:
    /// <c>SIPRAL_LIBRARY</c> (a file or a directory holding the file),
    /// then beside this assembly, then a checkout's own
    /// <c>target/release</c> and <c>target/debug</c>, found by walking
    /// up from this assembly's directory looking for a sibling
    /// <c>target</c> directory — the repository layout every build here
    /// shares, whatever depth `dotnet build`/`dotnet test` happened to
    /// put the assembly at.
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
