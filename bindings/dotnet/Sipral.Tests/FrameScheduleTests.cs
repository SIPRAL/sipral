// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Diagnostics;
using System.Threading;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// A call's frame clock in application mode keeps fifty frames a second
/// whatever its waits cost: <see cref="FrameSchedule"/>, driven by a clock of
/// the test's own through several seconds of waits that end late, and then by
/// the real clock and this machine's own waits.
/// </summary>
public sealed class FrameScheduleTests
{
    private const double Frame = 0.020;

    /// <summary>How many frames a thread doing <paramref name="work"/>
    /// seconds of work per frame gets through in <paramref name="seconds"/>,
    /// when every wait is rounded up to a whole <paramref name="tick"/> (none
    /// when zero) and then ends <paramref name="late"/> seconds after
    /// that.</summary>
    private static int FramesIn(double seconds, double tick, double late, double work)
    {
        var now = 0.0;
        var schedule = new FrameSchedule(Frame, () => now);
        var frames = 0;
        while (now < seconds)
        {
            frames++;
            now += work;
            var wait = schedule.Next().TotalSeconds;
            if (wait > 0)
            {
                now += (tick > 0 ? Math.Ceiling(wait / tick) * tick : wait) + late;
            }
        }
        return frames;
    }

    [Fact]
    public void WindowsTimerTicksDoNotSlowTheFramesDown()
    {
        // 15.625 ms, the tick every wait on Windows is rounded up to: a
        // sleep after each frame waits two ticks for a twenty-millisecond
        // frame and sends thirty-one a second
        var frames = FramesIn(seconds: 5, tick: 0.015625, late: 0, work: 0.001);
        Assert.InRange(frames, 248, 251);
    }

    [Fact]
    public void WaitsThatEndLateDoNotSlowTheFramesDown()
    {
        // half a millisecond late every time: a sleep after each frame sends
        // 48.8 a second, and the far end's buffer runs dry at one frame in
        // forty
        var frames = FramesIn(seconds: 5, tick: 0, late: 0.0005, work: 0.002);
        Assert.InRange(frames, 249, 251);
    }

    [Fact]
    public void AThreadHeldUpStartsOverRatherThanSendingABurst()
    {
        var now = 0.0;
        var schedule = new FrameSchedule(Frame, () => now);
        now = 0.070;
        Assert.Equal(TimeSpan.Zero, schedule.Next());
        Assert.InRange(schedule.SecondsGivenUp, 0.0499, 0.0501);
        now = 0.071;
        var wait = schedule.Next().TotalSeconds;
        Assert.InRange(wait, 0.0189, 0.0191);
    }

    [Fact]
    public void TheRealClockKeepsFiftyFramesASecondForSeveralSeconds()
    {
        var clock = Stopwatch.StartNew();
        var schedule = new FrameSchedule(Frame, () => clock.Elapsed.TotalSeconds);
        using var never = new ManualResetEventSlim(false);
        var frames = 0;
        while (clock.Elapsed.TotalSeconds < 3.0)
        {
            frames++;
            var wait = schedule.Next();
            if (wait > TimeSpan.Zero)
            {
                never.Wait(wait);
            }
        }
        // the wake that ended the loop is held to the schedule as the
        // thread's next frame would hold it: on a busy machine it can end a
        // tenth of a second past its due time, which is the machine's too
        schedule.Next();
        // a machine busy enough to hold the thread up past a whole frame makes
        // the schedule start over, on purpose; what that gave up is the
        // machine's, and every frame of the rest must be there
        var givenUp = (int)Math.Floor(schedule.SecondsGivenUp / Frame);
        Assert.True(
            frames + givenUp >= 149,
            $"{frames} frames in three seconds, {givenUp} given up to a thread held up"
        );
    }
}
