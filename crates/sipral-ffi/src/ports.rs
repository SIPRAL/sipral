// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Media ports out of a range the deployment set.
//!
//! The application opens every socket, so a stack cannot bind a port for
//! it; what it can do is say which one to bind, out of the range a firewall
//! in front of the deployment was opened for. `sipral_stack_config_t`'s
//! `rtp_port_min` and `rtp_port_max` set the range; [`sipral_stack_rtp_port_reserve`]
//! hands out an even port from it, with the odd one above kept for RTCP
//! (RFC 3550 §11, and what the stack itself sends RTCP to unless the far end
//! says otherwise); the application binds it and describes the call there
//! with `media_address`. With a range set, a call described at a port the
//! range does not hand out is refused, so a firewall rule and the ports in
//! use cannot drift apart.
//!
//! A reserved port stays reserved while a call describes its media there and
//! comes back once the call has ended or moved off it. One no call took — the
//! bind failed because another process holds the port, the call was refused
//! — goes back with [`sipral_stack_rtp_port_release`]. Ports are handed out
//! round the range rather than lowest first, so a port a call has just let
//! go is the last to be reused while its stragglers may still arrive.

use crate::error::{entry, fail};
use crate::handle::SipralHandle;
use crate::stack::with_stack;
use crate::status::SipralStatus;

entry! {
    /// Reserve a free even port from this stack's RTP range, with the odd
    /// port above it kept for RTCP, and write it to `out_port`.
    ///
    /// `SIPRAL_STATUS_EXHAUSTED` when every pair in the range is taken —
    /// reserved, or described by a call this stack still holds — and the
    /// last error says how many pairs the range has. Nothing is reserved
    /// then. `SIPRAL_STATUS_WRONG_STATE` on a stack created without a range:
    /// its ports are the application's to choose.
    ///
    /// # Safety
    ///
    /// `out_port` must point at one `uint32_t`.
    fn sipral_stack_rtp_port_reserve(stack: SipralHandle, out_port: *mut u32) {
        if out_port.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_port is null"));
        }
        let port = with_stack(stack, |state| match state.engine.reserve_rtp_port() {
            None => Err(fail(
                SipralStatus::WrongState,
                "this stack was created without rtp_port_min and rtp_port_max, so it hands out \
                 no ports: the application chooses its own",
            )),
            Some(Err(exhausted)) => Err(fail(SipralStatus::Exhausted, exhausted.to_string())),
            Some(Ok(port)) => Ok(port),
        })?;
        unsafe { out_port.write(u32::from(port)) };
        Ok(())
    }
}

entry! {
    /// Give back a port [`sipral_stack_rtp_port_reserve`] handed out that no
    /// call is using: the socket could not be bound there, or the call was
    /// refused. A port a call took comes back by itself when the call ends,
    /// and needs no release.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for a port that is not reserved,
    /// which is also what a second release of the same port is.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_stack_rtp_port_release(stack: SipralHandle, port: u32) {
        with_stack(stack, |state| {
            let released = u16::try_from(port)
                .ok()
                .is_some_and(|port| state.engine.release_rtp_port(port));
            if released {
                Ok(())
            } else {
                Err(fail(
                    SipralStatus::InvalidArgument,
                    format!("port {port} is not one this stack has reserved"),
                ))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{sipral_stack_rtp_port_release, sipral_stack_rtp_port_reserve};
    use crate::call::tests::{MEDIA, as_text, managed_config, media_line, place};
    use crate::error::last_error_text;
    use crate::handle::SipralHandle;
    use crate::stack::tests::{Observed, config, create, record, stack};
    use crate::stack::{SipralStackSettings, sipral_stack_settings};
    use crate::status::SipralStatus;

    fn reserve(handle: SipralHandle) -> (SipralStatus, u32) {
        let mut port = 0_u32;
        let status = unsafe { sipral_stack_rtp_port_reserve(handle, &raw mut port) };
        (status, port)
    }

    fn release(handle: SipralHandle, port: u32) -> SipralStatus {
        unsafe { sipral_stack_rtp_port_release(handle, port) }
    }

    fn ranged(observed: &mut Observed, min: u32, max: u32) -> (SipralHandle, SipralHandle) {
        media_line(observed, |config| {
            config.rtp_port_min = min;
            config.rtp_port_max = max;
        })
    }

    #[test]
    fn a_stack_hands_out_even_ports_from_its_range_and_says_when_none_is_left() {
        let mut observed = Observed::default();
        let (handle, _) = ranged(&mut observed, 40001, 40005);
        assert_eq!(reserve(handle), (SipralStatus::Ok, 40002));
        assert_eq!(reserve(handle), (SipralStatus::Ok, 40004));
        let (status, _) = reserve(handle);
        assert_eq!(status, SipralStatus::Exhausted);
        assert!(
            last_error_text().contains("2 RTP port pairs in 40001..40005"),
            "{}",
            last_error_text()
        );
        assert_eq!(release(handle, 40002), SipralStatus::Ok);
        assert_eq!(release(handle, 40002), SipralStatus::InvalidArgument);
        assert_eq!(reserve(handle), (SipralStatus::Ok, 40002));

        let mut settings = SipralStackSettings {
            size: size_of::<SipralStackSettings>(),
            ..unsafe { std::mem::zeroed() }
        };
        let status = unsafe { sipral_stack_settings(handle, &raw mut settings) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            (settings.rtp_port_min, settings.rtp_port_max),
            (40001, 40005)
        );
    }

    #[test]
    fn a_stack_without_a_range_hands_out_nothing() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(reserve(handle).0, SipralStatus::WrongState);
        let mut null = unsafe { sipral_stack_rtp_port_reserve(handle, std::ptr::null_mut()) };
        assert_eq!(null, SipralStatus::InvalidArgument);
        null = release(handle, 40000);
        assert_eq!(null, SipralStatus::InvalidArgument);
    }

    #[test]
    fn a_range_that_holds_no_call_is_refused_when_the_stack_is_made() {
        let mut observed = Observed::default();
        for (min, max) in [
            (40001, 40002),
            (0, 40010),
            (40010, 0),
            (40010, 40000),
            (70000, 70010),
        ] {
            let mut made = config(record, &mut observed);
            made.rtp_port_min = min;
            made.rtp_port_max = max;
            let (status, _) = create(&made);
            assert_eq!(status, SipralStatus::InvalidArgument, "{min}..{max}");
        }
    }

    /// With a range, a call described at a port the range does not hand out
    /// is refused, so the firewall rule and the ports in use cannot drift.
    #[test]
    fn a_call_described_outside_the_range_is_refused_and_one_inside_is_placed() {
        let mut observed = Observed::default();
        let (handle, account) = ranged(&mut observed, 41000, 41009);
        assert!(MEDIA.ends_with(":40000"));
        let (status, _) = place(handle, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(
            last_error_text().contains("41000..41009"),
            "{}",
            last_error_text()
        );

        let (status, port) = reserve(handle);
        assert_eq!(status, SipralStatus::Ok);
        let inside = format!("192.0.2.10:{port}");
        let mut config = managed_config();
        (config.media_address, config.media_address_len) = as_text(&inside);
        let (status, _) = place(handle, account, &config, 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());

        let odd = "192.0.2.10:41003";
        (config.media_address, config.media_address_len) = as_text(odd);
        let (status, _) = place(handle, account, &config, 1_000);
        assert_eq!(
            status,
            SipralStatus::InvalidArgument,
            "RTCP's port is not RTP's"
        );
    }
}
