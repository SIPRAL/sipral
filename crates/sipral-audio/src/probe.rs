// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A platform call with a time limit.
//!
//! A driver that has stopped answering does not fail: it sits there, and the
//! thread that asked sits with it. Enumerating devices and opening one are
//! the two calls seen to do that on real machines, and a softphone whose
//! signalling thread is inside one of them is a softphone that has stopped
//! ringing. So the engine asks from a thread of its own and waits a bounded
//! time for the answer; past that the call is reported as timed out and the
//! thread is left to finish whenever the driver lets it, with nothing
//! waiting on it.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::backend::BackendError;

/// How long a platform call may take before the engine stops waiting for
/// it, unless the application says otherwise.
pub const DEFAULT_PROBE_WAIT: Duration = Duration::from_secs(3);

/// Run `work` on a thread of its own and wait at most `wait` for its answer.
///
/// # Errors
/// [`BackendError::TimedOut`] when `wait` passed first, or when the thread
/// could not be started; otherwise what `work` answered.
pub(crate) fn probe<T: Send + 'static>(
    wait: Duration,
    work: impl FnOnce() -> Result<T, BackendError> + Send + 'static,
) -> Result<T, BackendError> {
    let (sender, receiver) = mpsc::channel();
    let spawned = thread::Builder::new()
        .name("sipral-audio-probe".to_owned())
        .spawn(move || {
            // a receiver that gave up is the only reason this cannot be sent,
            // and then nobody is left to tell
            let _ = sender.send(work());
        });
    if spawned.is_err() {
        return Err(BackendError::TimedOut);
    }
    match receiver.recv_timeout(wait) {
        Ok(answer) => answer,
        Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {
            Err(BackendError::TimedOut)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BackendError, probe};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    #[test]
    fn an_answer_in_time_is_the_answer() {
        assert_eq!(probe(Duration::from_secs(1), || Ok(7)), Ok(7));
        assert_eq!(
            probe(Duration::from_secs(1), || Err::<(), _>(
                BackendError::NoDevice
            )),
            Err(BackendError::NoDevice)
        );
    }

    #[test]
    fn a_driver_that_never_answers_is_a_timeout_and_the_caller_is_not_stuck_with_it() {
        let (release, stuck) = mpsc::channel::<()>();
        let started = Instant::now();
        let answer = probe(Duration::from_millis(50), move || {
            // a driver that hangs until somebody outside lets it go
            let _ = stuck.recv();
            Ok(1)
        });
        assert_eq!(answer, Err(BackendError::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(release);
    }
}
