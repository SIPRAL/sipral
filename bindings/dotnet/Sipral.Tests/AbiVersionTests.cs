// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using Xunit;

namespace Sipral.Tests;

/// <summary>
/// The check this binding's static constructor makes, asked of the library
/// it loaded about other versions than its own: within one major a binding
/// built against an earlier or equal minor is served, and one built against
/// a later minor, another major or any 0.x is refused.
/// </summary>
public class AbiVersionTests
{
    private static void Refused(uint major, uint minor)
    {
        var refused = Assert.Throws<SipralException>(() => global::Sipral.Sipral.AbiCheck(major, minor));
        Assert.Equal(SipralStatus.UnsupportedVersion, refused.Status);
        Assert.Contains($"{major}.{minor}", refused.Message);
    }

    [Fact]
    public void TheLibraryIsAtThisBindingsMajorAndNoEarlierMinor()
    {
        var version = global::Sipral.Sipral.AbiVersion();
        Assert.Equal(global::Sipral.Sipral.AbiVersionMajor, version.Major);
        Assert.True(version.Minor >= global::Sipral.Sipral.AbiVersionMinor, $"library minor {version.Minor}");
    }

    [Fact]
    public void TheMinorThisBindingWasPrintedAgainstIsServed()
    {
        global::Sipral.Sipral.AbiCheck(global::Sipral.Sipral.AbiVersionMajor, global::Sipral.Sipral.AbiVersionMinor);
    }

    /// <summary>A library newer than its binding: every earlier minor of
    /// this major is a binding the library in hand is newer than.</summary>
    [Fact]
    public void ABindingBuiltAgainstAnEarlierMinorIsServed()
    {
        var version = global::Sipral.Sipral.AbiVersion();
        for (uint minor = 0; minor <= version.Minor; minor++)
        {
            global::Sipral.Sipral.AbiCheck(version.Major, minor);
        }
    }

    /// <summary>A library older than its binding.</summary>
    [Fact]
    public void ABindingBuiltAgainstALaterMinorIsRefused()
    {
        var version = global::Sipral.Sipral.AbiVersion();
        Refused(version.Major, version.Minor + 1);
    }

    [Fact]
    public void AnotherMajorIsRefused()
    {
        Refused(global::Sipral.Sipral.AbiVersionMajor + 1, 0);
        Refused(0, 36);
    }
}
