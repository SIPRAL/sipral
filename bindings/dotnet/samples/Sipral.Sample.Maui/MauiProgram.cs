// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using Microsoft.Maui.Controls.Hosting;
using Microsoft.Maui.Hosting;

namespace Sipral.Sample.Maui;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        // the lifecycle UseSipral adds to the services reaches App's constructor
        builder.UseMauiApp<App>().UseSipral(out _);
        return builder.Build();
    }
}
