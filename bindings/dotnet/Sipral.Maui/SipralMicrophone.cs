// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System.Threading.Tasks;
using Microsoft.Maui.ApplicationModel;

#if ANDROID
// merged into the application's manifest: the microphone for device audio,
// the network for SIP and RTP, and the network's state for the moves
// SipralStack.MoveTo reports
[assembly: Android.App.UsesPermission(Android.Manifest.Permission.RecordAudio)]
[assembly: Android.App.UsesPermission(Android.Manifest.Permission.ModifyAudioSettings)]
[assembly: Android.App.UsesPermission(Android.Manifest.Permission.Internet)]
[assembly: Android.App.UsesPermission(Android.Manifest.Permission.AccessNetworkState)]
#endif

namespace Sipral;

/// <summary>
/// The microphone permission a call in <see cref="SipralAudio.Device"/> mode
/// needs before its first call. On Android the package declares
/// <c>RECORD_AUDIO</c> itself; on iOS the application's <c>Info.plist</c>
/// carries <c>NSMicrophoneUsageDescription</c>, without which iOS ends the
/// process at the first request.
/// </summary>
public static class SipralMicrophone
{
    /// <summary>Whether the microphone is already granted, asking nothing.</summary>
    public static async Task<bool> IsGrantedAsync() =>
        await MainThread.InvokeOnMainThreadAsync(Permissions.CheckStatusAsync<Permissions.Microphone>).ConfigureAwait(false)
            == PermissionStatus.Granted;

    /// <summary>Asks for the microphone when it is not granted yet, on the
    /// main thread as both platforms require; <see langword="true"/> once
    /// granted.</summary>
    public static async Task<bool> RequestAsync() =>
        await MainThread.InvokeOnMainThreadAsync(Permissions.RequestAsync<Permissions.Microphone>).ConfigureAwait(false)
            == PermissionStatus.Granted;
}
