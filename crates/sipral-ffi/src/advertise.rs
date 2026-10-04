// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Which address this end advertises to a peer (ABI 0.34).
//!
//! An application that leaves its sockets on `127.0.0.1`, or advertises the
//! address it bound to without asking where that is reachable from, registers
//! a loopback `Contact` and offers loopback media: the PBX takes the binding
//! and answers the calls, and every request and every packet for this end
//! goes to the PBX's own loopback interface. The stack now refuses to
//! advertise a loopback address to a peer that is not one
//! (`SIPRAL_STATUS_UNREACHABLE_ADDRESS`, and
//! `SIPRAL_REGISTRATION_FAILURE_UNREACHABLE_CONTACT` for a REGISTER it sends on
//! its own), and [`sipral_advertised_address`] is how the application finds
//! the address to use instead.

use std::ffi::c_char;

use sipral::AdvertiseError;

use crate::diagnostics::copy_out;
use crate::error::{entry, fail};
use crate::media::address;
use crate::status::SipralStatus;

entry! {
    /// The address to advertise — in a `Contact`, a `bind_address`, a
    /// `media_address` — for a socket bound at `bound` whose traffic goes to
    /// `peer`, as `host:port`, written into `buffer` with a NUL after it.
    ///
    /// A socket bound to a specific address advertises it, unless it is a
    /// loopback address and `peer` is not: `SIPRAL_STATUS_UNREACHABLE_ADDRESS`,
    /// with nothing written. A socket bound to the wildcard address
    /// (`0.0.0.0:5060`, `[::]:5060`) advertises the address of the
    /// operating system's route toward `peer`, with its own port; the route
    /// is found by connecting a datagram socket and closing it, and nothing
    /// is sent. No route to `peer` at all is `SIPRAL_STATUS_TRANSPORT_DOWN`.
    /// `peer` is the registrar for the signalling socket, and the far end —
    /// or the registrar, while the far end is not known yet — for a media
    /// socket. Both are `host:port` addresses, not names.
    ///
    /// Callable from any thread at any time: it names no stack. Text out as
    /// every such call writes it: `out_needed` receives the length with the
    /// NUL counted, `buffer` may be null with a `capacity` of zero to ask for
    /// it, and `SIPRAL_STATUS_BUFFER_TOO_SMALL` writes nothing.
    ///
    /// # Safety
    ///
    /// `bound` and `peer` must be readable for their lengths, `buffer` must
    /// be writable for `capacity` bytes or be null with a capacity of zero,
    /// and `out_needed` must point at one `size_t` or be null.
    fn sipral_advertised_address(
        bound: *const c_char,
        bound_len: usize,
        peer: *const c_char,
        peer_len: usize,
        buffer: *mut c_char,
        capacity: usize,
        out_needed: *mut usize,
    ) {
        let bound = unsafe { address(bound, bound_len, "bound") }?;
        let peer = unsafe { address(peer, peer_len, "peer") }?;
        let advertised = sipral::advertised_address(bound, peer).map_err(|error| {
            let status = match error {
                AdvertiseError::Loopback { .. } => SipralStatus::UnreachableAddress,
                _ => SipralStatus::TransportDown,
            };
            fail(status, error.to_string())
        })?;
        unsafe { copy_out(&advertised.to_string(), buffer, capacity, out_needed) }
    }
}

#[cfg(test)]
mod tests {
    use super::sipral_advertised_address;
    use crate::error::last_error_text;
    use crate::status::SipralStatus;
    use std::ffi::c_char;
    use std::ptr;

    fn advertised(bound: &str, peer: &str) -> Result<String, SipralStatus> {
        let mut needed = 0_usize;
        let status = unsafe {
            sipral_advertised_address(
                bound.as_ptr().cast(),
                bound.len(),
                peer.as_ptr().cast(),
                peer.len(),
                ptr::null_mut(),
                0,
                &raw mut needed,
            )
        };
        if status != SipralStatus::BufferTooSmall {
            return Err(status);
        }
        let mut buffer = vec![0 as c_char; needed];
        let status = unsafe {
            sipral_advertised_address(
                bound.as_ptr().cast(),
                bound.len(),
                peer.as_ptr().cast(),
                peer.len(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut needed,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(buffer.last(), Some(&0), "a NUL, counted");
        let bytes: Vec<u8> = buffer[..needed - 1]
            .iter()
            .map(|byte| byte.cast_unsigned())
            .collect();
        Ok(String::from_utf8(bytes).expect("UTF-8"))
    }

    #[test]
    fn a_specific_address_is_advertised_as_it_was_bound() {
        assert_eq!(
            advertised("192.0.2.10:5060", "198.51.100.1:5060"),
            Ok("192.0.2.10:5060".to_owned())
        );
        assert_eq!(
            advertised("127.0.0.1:5060", "127.0.0.1:5080"),
            Ok("127.0.0.1:5060".to_owned()),
            "loopback to loopback is a peer on this machine"
        );
    }

    #[test]
    fn loopback_toward_a_peer_on_another_machine_is_refused() {
        assert_eq!(
            advertised("127.0.0.1:5060", "198.51.100.1:5060"),
            Err(SipralStatus::UnreachableAddress)
        );
        let said = last_error_text();
        assert!(
            said.contains("127.0.0.1") && said.contains("198.51.100.1"),
            "{said}"
        );
    }

    #[test]
    fn a_wildcard_bind_advertises_the_route_toward_the_peer_with_its_own_port() {
        // the loopback peer is the one route every machine the tests run on
        // has, and the answer is then the loopback address
        assert_eq!(
            advertised("0.0.0.0:5070", "127.0.0.1:5060"),
            Ok("127.0.0.1:5070".to_owned())
        );
    }

    #[test]
    fn a_name_is_not_an_address() {
        assert_eq!(
            advertised("0.0.0.0:5070", "pbx.example.com:5060"),
            Err(SipralStatus::InvalidArgument)
        );
    }
}
