// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;

namespace Sipral;

/// <summary>
/// When a frame thread next wakes: one frame after the last due time, not
/// after its work finished.
///
/// Waits end late (up to a 15.6 ms tick on Windows). Sleeping a frame after
/// each frame would lose every late wake, sending fewer frames than the far
/// end expects. Advancing the due time makes up for it next frame. A thread
/// already behind restarts the schedule from now instead of bursting.
/// </summary>
internal sealed class FrameSchedule
{
    private readonly double _frameSeconds;
    private readonly Func<double> _now;
    private double _due;

    // Total lag dropped by restarting the schedule.
    internal double SecondsGivenUp { get; private set; }

    /// <param name="frameSeconds">How long one frame is.</param>
    /// <param name="now">A monotonic clock in seconds.</param>
    internal FrameSchedule(double frameSeconds, Func<double> now)
    {
        _frameSeconds = frameSeconds;
        _now = now;
        _due = now();
    }

    // Zero when already due.
    internal TimeSpan Next()
    {
        _due += _frameSeconds;
        var now = _now();
        var remaining = _due - now;
        if (remaining > 0)
        {
            return TimeSpan.FromSeconds(remaining);
        }
        SecondsGivenUp += now - _due;
        _due = now;
        return TimeSpan.Zero;
    }
}
