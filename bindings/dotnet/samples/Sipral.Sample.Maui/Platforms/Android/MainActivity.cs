// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using Android.App;
using Android.Content.PM;
using Android.OS;
using Android.Runtime;
using Microsoft.Maui;
using Microsoft.Maui.Hosting;

namespace Sipral.Sample.Maui;

[Activity(Theme = "@style/Maui.SplashTheme", MainLauncher = true,
    ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize)]
public sealed class MainActivity : MauiAppCompatActivity
{
    // `am start -e SIPRAL_SAMPLE_AOR ...` reaches App as the environment
    // does on iOS, read when its window is made, after this
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        if (Intent?.Extras is { } extras)
        {
            foreach (var key in extras.KeySet() ?? [])
            {
                if (key.StartsWith("SIPRAL_SAMPLE_", StringComparison.Ordinal))
                {
                    System.Environment.SetEnvironmentVariable(key, extras.GetString(key));
                }
            }
        }
        base.OnCreate(savedInstanceState);
    }
}

[Application]
public sealed class MainApplication : MauiApplication
{
    public MainApplication(IntPtr handle, JniHandleOwnership ownership)
        : base(handle, ownership)
    {
    }

    protected override MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();
}
