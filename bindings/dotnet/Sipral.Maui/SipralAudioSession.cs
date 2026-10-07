// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if IOS
using AVFoundation;
using Foundation;

namespace Sipral;

/// <summary>
/// The iOS audio session a call in <see cref="SipralAudio.Device"/> mode
/// runs in. On iOS the session belongs to the application, not the library
/// (<c>docs/15-mobile.md</c>, "C4"): without this, or CallKit doing the same
/// when it answers, the voice-processing unit opens in a session that does
/// not record. An application on CallKit leaves activation to the system and
/// calls only <see cref="Configure"/>.
/// </summary>
public static class SipralAudioSession
{
    /// <summary>Sets the category to play-and-record in voice-chat mode,
    /// Bluetooth headsets allowed. Throws <see cref="SipralException"/> with
    /// <see cref="SipralStatus.DeviceUnusable"/> when iOS refuses.</summary>
    public static void Configure()
    {
        var session = AVAudioSession.SharedInstance();
        Refused(session.SetCategory(
            AVAudioSessionCategory.PlayAndRecord,
            AVAudioSessionCategoryOptions.AllowBluetooth | AVAudioSessionCategoryOptions.AllowBluetoothA2DP), "category");
        Refused(session.SetMode(AVAudioSessionMode.VoiceChat.GetConstant()!, out var modeError), "mode", modeError);
    }

    /// <summary><see cref="Configure"/>, then the session made active: for
    /// an application without CallKit, before its first call.</summary>
    public static void Activate()
    {
        Configure();
        Refused(AVAudioSession.SharedInstance().SetActive(true), "activation");
    }

    /// <summary>The session let go once the last call has ended, so other
    /// applications' audio comes back.</summary>
    public static void Deactivate() =>
        Refused(AVAudioSession.SharedInstance().SetActive(false, AVAudioSessionSetActiveOptions.NotifyOthersOnDeactivation), "deactivation");

    private static void Refused(NSError? error, string what) => Refused(error is null, what, error);

    private static void Refused(bool done, string what, NSError? error)
    {
        if (!done)
        {
            throw new SipralException(SipralStatus.DeviceUnusable, $"the audio session's {what} was refused: {error?.LocalizedDescription}");
        }
    }
}
#endif
