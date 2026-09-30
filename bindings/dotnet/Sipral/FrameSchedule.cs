// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;

namespace Sipral;

/// <summary>
/// When a call's frame-rate thread next wakes: on a schedule, one frame after
/// the last due time, and not one frame after its work finished.
///
/// A wait ends late — by a fraction of a millisecond on most machines, by up
/// to a whole tick of Windows' 15.6 ms timer — and a clock that sleeps a
/// frame after each frame loses every late wake for good: it sends and plays
/// fewer frames a second than the far end's clock expects, and the far end's
/// buffer fills the gap with silence. Adding a frame to the due time instead
/// makes up for a late wake on the next one. A thread already behind when its
/// work is done starts the schedule over from now rather than send a burst to
/// catch up. The same schedule the Swift, Python and Kotlin layers and a
/// local conference's thread keep.
/// </summary>
internal sealed class FrameSchedule
{
    private readonly double _frameSeconds;
    private readonly Func<double> _now;
    private double _due;

    /// <param name="frameSeconds">How long one frame is.</param>
    /// <param name="now">A monotonic clock in seconds.</param>
    internal FrameSchedule(double frameSeconds, Func<double> now)
    {
        _frameSeconds = frameSeconds;
        _now = now;
        _due = now();
    }

    /// <summary>How long to wait before the next frame, after one was
    /// done; zero when it is due already.</summary>
    internal TimeSpan Next()
    {
        _due += _frameSeconds;
        var now = _now();
        var remaining = _due - now;
        if (remaining > 0)
        {
            return TimeSpan.FromSeconds(remaining);
        }
        _due = now;
        return TimeSpan.Zero;
    }
}
