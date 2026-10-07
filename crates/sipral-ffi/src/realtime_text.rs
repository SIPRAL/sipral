// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Real-time text in a call (RFC 4103): T.140 over RTP, with the redundancy
//! of RFC 2198, on a socket of its own.
//!
//! Offered and accepted only when the call config names `text_address`; then
//! `sipral_media_info_t::has_text` is set. Received text arrives as
//! `SIPRAL_EVENT_KIND_TEXT_RECEIVED`.

use std::ffi::c_char;
use std::slice;

use crate::abi::record;
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::media::{
    SIPRAL_MEDIA_PACKET_BYTES, SipralMediaPacket, address, media_failed, prepare, put_datagram,
    with_media,
};
use crate::status::SipralStatus;
use crate::versioned::{read_versioned, write_versioned};

record! {
    /// What a [`crate::event::SipralEventKind::TextReceived`] carries; the
    /// text is valid during the callback.
    #[derive(Clone, Copy)]
    pub struct SipralTextEvent {
        /// What the far end typed, UTF-8, not NUL-terminated.
        pub text: *const c_char,
        /// How many bytes of it.
        pub text_len: usize,
        /// Unrecoverable lost blocks, each marked in `text` by U+FFFD.
        pub missing: u32,
    }
}

entry! {
    /// Queue text the user typed for the far end, UTF-8.
    /// Sent every 300 ms within the far end's rate, with `red` redundancy
    /// when agreed. CR, LF or CR LF is a new line; U+0008 erases.
    ///
    /// `SIPRAL_STATUS_NOT_NEGOTIATED` without a text stream;
    /// `SIPRAL_STATUS_EXHAUSTED` when the queue is full (nothing queued).
    ///
    /// # Safety
    ///
    /// `text` must be readable for `text_len` bytes.
    fn sipral_media_send_text(media: SipralHandle, text: *const c_char, text_len: usize) {
        if text.is_null() || text_len == 0 {
            return Err(fail(SipralStatus::InvalidArgument, "text is empty"));
        }
        let raw = unsafe { slice::from_raw_parts(text.cast::<u8>(), text_len) };
        let Ok(typed) = str::from_utf8(raw) else {
            return Err(fail(SipralStatus::InvalidArgument, "text is not UTF-8"));
        };
        with_media(media, |session, _| {
            session.send_text(typed).map_err(|error| media_failed(&error))
        })
    }
}

entry! {
    /// The next datagram due on the call's text socket.
    /// `len` zero means nothing due; poll again at the stack's deadline. Send
    /// from the `text_address` socket, not the audio one.
    ///
    /// # Safety
    ///
    /// `packet` must point at a `sipral_media_packet_t` as
    /// `sipral_media_capture` describes.
    fn sipral_media_poll_text(media: SipralHandle, now_ms: u64, packet: *mut SipralMediaPacket) {
        let mut out = unsafe { read_versioned(packet) }?;
        prepare(&mut out)?;
        with_media(media, |session, entry| {
            let now = entry.instant(now_ms)?;
            match session.poll_text(now) {
                Some(datagram) => unsafe { put_datagram(&mut out, &datagram) },
                None => Ok(()),
            }
        })?;
        unsafe { write_versioned(packet, out) }
    }
}

entry! {
    /// Take a datagram off the call's text socket.
    /// `out_taken` is 1 when it was this call's text, else 0 (not RTP, other
    /// payload type, not the latched source, or no text stream).
    ///
    /// # Safety
    ///
    /// `data` must be readable for `len` bytes, `from` for `from_len`, and
    /// `out_taken` must point at one `uint32_t` or be null.
    fn sipral_media_receive_text(
        media: SipralHandle,
        data: *const u8,
        len: usize,
        from: *const c_char,
        from_len: usize,
        now_ms: u64,
        out_taken: *mut u32,
    ) {
        if data.is_null() || len == 0 || len > SIPRAL_MEDIA_PACKET_BYTES {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "data says it is {len} bytes, and a datagram is 1 to \
                     {SIPRAL_MEDIA_PACKET_BYTES}"
                ),
            ));
        }
        let peer = unsafe { address(from, from_len, "from") }?;
        let datagram = unsafe { slice::from_raw_parts(data, len) };
        let taken = with_media(media, |session, entry| -> Result<bool, Fail> {
            let now = entry.instant(now_ms)?;
            Ok(session.receive_text(datagram, peer, now))
        })?;
        if !out_taken.is_null() {
            unsafe { out_taken.write(u32::from(taken)) };
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{sipral_media_poll_text, sipral_media_receive_text, sipral_media_send_text};
    use crate::call::sipral_call_answer_with;
    use crate::call::tests::{
        accepted, account_on, as_text, body, call_config, called, deliver, invitation,
        managed_config, media_call, media_line, one, place, ring_media_config, sent, start_line,
    };
    use crate::error::last_error_text;
    use crate::event::SipralEventKind;
    use crate::handle::SipralHandle;
    use crate::media::tests::{Buffers, media_info, media_of, release};
    use crate::stack::sipral_stack_destroy;
    use crate::stack::tests::{Observed, poll, stack};
    use crate::status::SipralStatus;
    use std::ffi::c_char;
    use std::ptr;

    const TEXT_ADDRESS: &str = "192.0.2.10:40002";
    const PEER_TEXT: &str = "203.0.113.5:41002";

    /// Audio plus text with redundancy.
    const TEXT_ANSWER: &[u8] = b"v=0\r\n\
o=bob 1 1 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=sendrecv\r\n\
m=text 41002 RTP/AVP 100 98\r\n\
a=rtpmap:98 t140/1000\r\n\
a=rtpmap:100 red/1000\r\n\
a=fmtp:100 98/98/98\r\n\
a=sendrecv\r\n";

    /// One T.140 packet from the far end, without redundancy.
    fn typed(sequence: u16, text: &str) -> Vec<u8> {
        let mut out = vec![0x80, 98];
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&u32::from(sequence).to_be_bytes());
        out.extend_from_slice(&0x5445_5854_u32.to_be_bytes());
        out.extend_from_slice(text.as_bytes());
        out
    }

    fn send(media: SipralHandle, text: &str) -> SipralStatus {
        unsafe { sipral_media_send_text(media, text.as_ptr().cast::<c_char>(), text.len()) }
    }

    fn receive(
        media: SipralHandle,
        datagram: &[u8],
        from: &str,
        now_ms: u64,
    ) -> (SipralStatus, u32) {
        let mut taken = u32::MAX;
        let (from, from_len) = as_text(from);
        let status = unsafe {
            sipral_media_receive_text(
                media,
                datagram.as_ptr(),
                datagram.len(),
                from,
                from_len,
                now_ms,
                &raw mut taken,
            )
        };
        (status, taken)
    }

    fn next_text(media: SipralHandle, from_ms: u64) -> Option<(Vec<u8>, String)> {
        let mut buffers = Buffers::new();
        for now_ms in (from_ms..from_ms + 2_000).step_by(20) {
            let mut packet = buffers.packet();
            let status = unsafe { sipral_media_poll_text(media, now_ms, &raw mut packet) };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if packet.len > 0 {
                return Some(buffers.taken(&packet));
            }
        }
        None
    }

    fn text_call(observed: &mut Observed) -> (SipralHandle, SipralHandle, Vec<u8>) {
        let (handle, account) = media_line(observed, |_| {});
        let mut config = managed_config();
        (config.text_address, config.text_address_len) = as_text(TEXT_ADDRESS);
        let (status, call) = place(handle, account, &config, 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, TEXT_ANSWER, true), 1_100);
        poll(handle, 1_100);
        let _ = sent(handle);
        (handle, call, invite)
    }

    #[test]
    fn a_call_given_a_text_socket_offers_text_and_carries_it_both_ways() {
        let mut observed = Observed::default();
        let (handle, call, invite) = text_call(&mut observed);
        let offer = String::from_utf8(body(&invite)).expect("UTF-8");
        assert!(offer.contains("m=text 40002 RTP/AVP 100 98"), "{offer}");
        let media = media_of(handle, call);
        assert_eq!(media_info(media).has_text, 1);

        assert_eq!(send(media, "hi"), SipralStatus::Ok, "{}", last_error_text());
        let (packet, destination) = next_text(media, 1_200).expect("the text went");
        assert_eq!(destination, PEER_TEXT);
        assert_eq!(packet[1] & 0x7f, 100, "sent with its redundancy");
        assert!(packet.ends_with(b"hi"), "{packet:?}");

        assert_eq!(
            receive(media, &typed(1, "yo"), PEER_TEXT, 1_300),
            (SipralStatus::Ok, 1)
        );
        // latched to the far end's text socket, as RTP is
        assert_eq!(
            receive(media, &typed(2, "no"), "198.51.100.7:9", 1_310),
            (SipralStatus::Ok, 0)
        );
        poll(handle, 1_320);
        let told: Vec<_> = observed
            .protocols
            .iter()
            .filter(|told| told.kind == Some(SipralEventKind::TextReceived))
            .cloned()
            .collect();
        assert_eq!(told.len(), 1, "{:?}", observed.kinds());
        assert_eq!(told[0].text, "yo");
        assert_eq!(told[0].missing, 0);
        assert_eq!(told[0].call, call);
        release(media);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_with_no_text_stream_refuses_text() {
        let mut observed = Observed::default();
        let (handle, call) = media_call(&mut observed);
        let media = media_of(handle, call);
        assert_eq!(media_info(media).has_text, 0);
        assert_eq!(send(media, "hi"), SipralStatus::NotNegotiated);
        assert_eq!(send(media, ""), SipralStatus::InvalidArgument);
        assert!(next_text(media, 1_200).is_none());
        assert_eq!(
            receive(media, &typed(1, "yo"), PEER_TEXT, 1_300),
            (SipralStatus::Ok, 0)
        );
        let bytes = [0xff_u8, 0xfe];
        let status =
            unsafe { sipral_media_send_text(media, bytes.as_ptr().cast::<c_char>(), bytes.len()) };
        assert_eq!(status, SipralStatus::InvalidArgument, "not UTF-8");
        release(media);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_text_socket_on_a_call_the_application_describes_is_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = account_on(handle);
        let mut config = call_config();
        (config.text_address, config.text_address_len) = as_text(TEXT_ADDRESS);
        assert_eq!(
            place(handle, account, &config, 1_000).0,
            SipralStatus::InvalidArgument
        );
        let mut config = managed_config();
        (config.text_address, config.text_address_len) = as_text("not an address");
        assert_eq!(
            place(handle, account, &config, 1_000).0,
            SipralStatus::InvalidArgument
        );
        assert!(sent(handle).is_empty(), "nothing went out");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    fn invitation_offering(offer: &[u8]) -> Vec<u8> {
        let whole = String::from_utf8(invitation()).expect("text");
        let head = whole
            .split("Content-Length:")
            .next()
            .expect("a head")
            .to_owned();
        let mut out = head.into_bytes();
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", offer.len()).as_bytes());
        out.extend_from_slice(offer);
        out
    }

    #[test]
    fn an_answer_given_a_text_socket_takes_the_offered_text() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |_| {});
        deliver(handle, &invitation_offering(TEXT_ANSWER), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);
        let mut config = ring_media_config();
        (config.text_address, config.text_address_len) = as_text(TEXT_ADDRESS);
        let status =
            unsafe { sipral_call_answer_with(handle, call, ptr::from_ref(&config), 1_100) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let response = one(handle);
        assert!(
            start_line(&response).starts_with("SIP/2.0 200"),
            "answered, not rung: {}",
            start_line(&response)
        );
        let answer = String::from_utf8(body(&response)).expect("UTF-8");
        assert!(answer.contains("m=audio 40000 "), "{answer}");
        assert!(answer.contains("m=text 40002 RTP/AVP 100 98"), "{answer}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn an_answer_with_no_text_socket_refuses_the_offered_text() {
        let mut observed = Observed::default();
        let (handle, _) = media_line(&mut observed, |_| {});
        deliver(handle, &invitation_offering(TEXT_ANSWER), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);
        let config = ring_media_config();
        let status =
            unsafe { sipral_call_answer_with(handle, call, ptr::from_ref(&config), 1_100) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let response = one(handle);
        assert!(
            start_line(&response).starts_with("SIP/2.0 200"),
            "answered, not rung: {}",
            start_line(&response)
        );
        let answer = String::from_utf8(body(&response)).expect("UTF-8");
        assert!(answer.contains("m=text 0 "), "{answer}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }
}
