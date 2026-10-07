// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using Foundation;
using Microsoft.Maui;
using Microsoft.Maui.Hosting;
using UIKit;

namespace Sipral.Sample.Maui;

[Register("AppDelegate")]
public sealed class AppDelegate : MauiUIApplicationDelegate
{
    protected override MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();
}

public static class Program
{
    private static void Main(string[] args) => UIApplication.Main(args, null, typeof(AppDelegate));
}
