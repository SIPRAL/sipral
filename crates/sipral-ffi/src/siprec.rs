// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Recording a call to a recording server (SIPREC, RFC 7866).
//!
//! [`sipral_call_record_to`] places the recording session: an INVITE to the
//! server with two send-only streams, one per party, and the metadata that
//! says who is on the call (RFC 7865). It is a call like any other from then
//! on — its handle gets `SIPRAL_EVENT_KIND_CALL_ANSWERED` and
//! `SIPRAL_EVENT_KIND_CALL_ENDED` — and the stack keeps it in step with the
//! recorded call: the metadata follows a hold or a transfer, a new codec is
//! offered again, and it ends when the recorded call does.
//!
//! The copies of the recorded call's audio come out of
//! [`sipral_media_poll_recording`] on the recorded call's media handle, to
//! send from the two sockets the configuration named. The copies of an
//! encrypted call are SRTP, under SDES keys of their own in the recording
//! session's offer (RFC 7866 §12.2), and a stream the server will not take as
//! SRTP gets nothing — unless the account's `recording_in_clear` allows plain
//! RTP (ABI 0.32).

use std::ffi::c_char;
use std::net::SocketAddr;

use sipral::RecordTo;
use sipral_core::msg::Uri;

use crate::abi::record;
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::media::{SipralMediaPacket, address, media_failed, prepare, put, with_media};
use crate::stack::{StackState, handle_failed, with_stack_at};
use crate::status::SipralStatus;
use crate::text::{required_text, text};
use crate::versioned::{Versioned, read_versioned, write_versioned};

record! {
    /// Where a call is recorded, as [`sipral_call_record_to`] takes it.
    ///
    /// Set `size` to `sizeof(sipral_record_config_t)` and zero the rest
    /// before filling anything in.
    #[derive(Clone, Copy)]
    pub struct SipralRecordConfig {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// The recording server's URI, the INVITE's target. Required. Not
        /// NUL-terminated.
        pub server: *const c_char,
        /// How many bytes of it.
        pub server_len: usize,
        /// Where to send the INVITE, as an address and a port, when not
        /// where the recorded call's account sends. Null for there.
        pub destination: *const c_char,
        /// How many bytes of it.
        pub destination_len: usize,
        /// The transport `destination` is reached over, as
        /// `sipral_call_config_t::transport` names one. Read only with
        /// `destination`.
        pub transport: u32,
        /// The socket the copy of this end's audio goes from, as an address
        /// and a port, and what the offer names for the stream labelled `1`.
        /// Required: a socket the application bound.
        pub this_end: *const c_char,
        /// How many bytes of it.
        pub this_end_len: usize,
        /// The same for the far end's audio, labelled `2`. Required, and a
        /// socket of its own.
        pub far_end: *const c_char,
        /// How many bytes of it.
        pub far_end_len: usize,
    }
}

// Safety: the trait's contract. Plain data with no invariant between the
// members, and all-zero is valid: every pointer is null beside a length of
// zero, and the required ones are refused by name.
unsafe impl Versioned for SipralRecordConfig {
    const NAME: &'static str = "sipral_record_config";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralRecordConfig, far_end_len);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// What `config` asks for, read before the stack is locked but for the
/// transport, which only the stack can name.
struct Asked {
    server: Uri,
    destination: Option<SocketAddr>,
    this_end: SocketAddr,
    far_end: SocketAddr,
}

/// # Safety
///
/// Every pointer in `config` must be readable for the length beside it.
unsafe fn asked(config: &SipralRecordConfig) -> Result<Asked, Fail> {
    let named = unsafe { required_text(config.server, config.server_len, "server") }?;
    let server = Uri::parse_str(named).map_err(|error| {
        fail(
            SipralStatus::InvalidArgument,
            format!("server is {named:?}, which is not a URI: {error}"),
        )
    })?;
    let destination =
        match unsafe { text(config.destination, config.destination_len, "destination") }? {
            Some(_) => {
                Some(unsafe { address(config.destination, config.destination_len, "destination") }?)
            }
            None if config.transport != 0 => {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    "transport is read together with destination; a recording session with no \
                 destination goes where the recorded call's account sends",
                ));
            }
            None => None,
        };
    let this_end = unsafe { address(config.this_end, config.this_end_len, "this_end") }?;
    let far_end = unsafe { address(config.far_end, config.far_end_len, "far_end") }?;
    if this_end == far_end {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "this_end and far_end are the same socket, and the server tells the two parties' \
             audio apart by the stream each arrives on",
        ));
    }
    Ok(Asked {
        server,
        destination,
        this_end,
        far_end,
    })
}

fn record_to(state: &StackState, asked: Asked, transport: u32) -> Result<RecordTo, Fail> {
    let to = RecordTo::new(asked.server, asked.this_end, asked.far_end);
    Ok(match asked.destination {
        Some(remote) => to.to_address(crate::transport::named(state, transport)?, remote),
        None => to,
    })
}

entry! {
    /// Record a call to a recording server (RFC 7866), and write the
    /// recording session's handle to `out_recording`.
    ///
    /// The call must be one this stack runs the media of, with its audio
    /// started: `SIPRAL_STATUS_WRONG_STATE` before
    /// `SIPRAL_EVENT_KIND_MEDIA_STARTED`, and for a call already being
    /// recorded to a server. The recording session goes from the recorded
    /// call's account, over a stream transport when the INVITE, which
    /// carries the metadata beside the offer, is too large for UDP.
    ///
    /// Hanging the recording session up with
    /// [`sipral_call_stop_recording_to`] or `sipral_call_hangup` stops the
    /// recording; the server hanging it up does the same.
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_record_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_recording` at one `sipral_handle_t`.
    fn sipral_call_record_to(
        stack: SipralHandle,
        call: SipralHandle,
        config: *const SipralRecordConfig,
        out_recording: *mut SipralHandle,
        now_ms: u64,
    ) {
        if out_recording.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_recording is null"));
        }
        let config = unsafe { read_versioned(config) }?;
        let asked = unsafe { asked(&config) }?;
        let handle = with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let to = record_to(state, asked, config.transport)?;
            let recording = state
                .engine
                .record_to(&mut state.agent, id, to, now)
                .map_err(|error| media_failed(&error))?;
            state
                .calls
                .name_of(recording)
                .map_err(|status| fail(status, "no room for another call on this stack"))
        })?;
        unsafe { out_recording.write(handle) };
        Ok(())
    }
}

entry! {
    /// Stop recording a call to its recording server: the copies stop at
    /// once, and the recording session is hung up.
    ///
    /// `call` is the recorded call, not the recording session.
    /// `SIPRAL_STATUS_WRONG_STATE` for a call nothing records.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_stop_recording_to(stack: SipralHandle, call: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state
                .engine
                .stop_recording_to(&mut state.agent, id, now)
                .map_err(|error| media_failed(&error))
        })
    }
}

entry! {
    /// The next copy of this call's audio for its recording server.
    ///
    /// A `len` of zero in the packet means none is waiting. Otherwise
    /// `out_far_end` says which socket to send it from: 0 for `this_end`,
    /// the copy of what this end sent, and 1 for `far_end`, the copy of what
    /// it received. Collect them with every frame, in a loop to empty: a
    /// copy nobody collects for a second is dropped, the oldest first.
    ///
    /// # Safety
    ///
    /// `packet` must point at a `sipral_media_packet_t` as
    /// `sipral_media_capture` describes, and `out_far_end` at one
    /// `uint32_t`.
    fn sipral_media_poll_recording(
        media: SipralHandle,
        packet: *mut SipralMediaPacket,
        out_far_end: *mut u32,
    ) {
        if out_far_end.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_far_end is null"));
        }
        let mut out = unsafe { read_versioned(packet) }?;
        prepare(&mut out)?;
        let far_end = with_media(media, |session, _| {
            match session.poll_recording() {
                Some(copy) => {
                    unsafe {
                        put(
                            &mut out,
                            copy.destination,
                            copy.payload,
                            crate::stack::SipralTransport::Udp as u32,
                        )
                    }?;
                    Ok(copy.far_end)
                }
                None => Ok(false),
            }
        })?;
        unsafe { out_far_end.write(u32::from(far_end)) };
        unsafe { write_versioned(packet, out) }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SipralRecordConfig, sipral_call_record_to, sipral_call_stop_recording_to,
        sipral_media_poll_recording,
    };
    use crate::call::tests::{
        as_text, body, connected, field, media_call, sent, start_line, state_of,
    };
    use crate::error::last_error_text;
    use crate::event::SipralCallState;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::media::tests::{Buffers, FRAME, arrive, capture_one, media_of, release, rtp};
    use crate::stack::SipralTransport;
    use crate::stack::sipral_stack_destroy;
    use crate::stack::tests::{Observed, poll};
    use crate::status::SipralStatus;
    use crate::transport::{sipral_stack_receive_stream, sipral_stack_transport_bind};
    use sipral_core::msg::HeaderName;
    use std::ptr;

    /// The transport the recording server is reached over: a connection of
    /// its own, since the INVITE is too large for UDP.
    const TO_SERVER: u32 = 1;
    const SERVER: &str = "203.0.113.9:5060";
    const THIS_END: &str = "192.0.2.10:40010";
    const FAR_END: &str = "192.0.2.10:40012";

    fn config() -> SipralRecordConfig {
        let mut config = SipralRecordConfig {
            size: size_of::<SipralRecordConfig>(),
            server: ptr::null(),
            server_len: 0,
            destination: ptr::null(),
            destination_len: 0,
            transport: TO_SERVER,
            this_end: ptr::null(),
            this_end_len: 0,
            far_end: ptr::null(),
            far_end_len: 0,
        };
        (config.server, config.server_len) = as_text("sip:srs@example.com");
        (config.destination, config.destination_len) = as_text(SERVER);
        (config.this_end, config.this_end_len) = as_text(THIS_END);
        (config.far_end, config.far_end_len) = as_text(FAR_END);
        config
    }

    fn connect_to_server(handle: SipralHandle) {
        let (local, local_len) = as_text("192.0.2.10:5061");
        let (remote, remote_len) = as_text(SERVER);
        let status = unsafe {
            sipral_stack_transport_bind(
                handle,
                TO_SERVER,
                SipralTransport::Tcp as u32,
                local,
                local_len,
                remote,
                remote_len,
                1_150,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    }

    fn record(
        handle: SipralHandle,
        call: SipralHandle,
        config: &SipralRecordConfig,
    ) -> (SipralStatus, SipralHandle) {
        let mut recording = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_call_record_to(
                handle,
                call,
                ptr::from_ref(config),
                &raw mut recording,
                1_200,
            )
        };
        (status, recording)
    }

    /// The server's answer: one receive-only stream per label.
    const SERVER_ANSWER: &[u8] = b"v=0\r\n\
o=srs 1 1 IN IP4 203.0.113.9\r\n\
s=-\r\n\
c=IN IP4 203.0.113.9\r\n\
t=0 0\r\n\
m=audio 50000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=label:1\r\n\
a=recvonly\r\n\
m=audio 50002 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=label:2\r\n\
a=recvonly\r\n";

    fn server_accepted(invite: &[u8]) -> Vec<u8> {
        let mut out = b"SIP/2.0 200 OK\r\n".to_vec();
        for (name, value) in [
            ("Via", field(invite, HeaderName::Via)),
            ("From", field(invite, HeaderName::From)),
            ("To", {
                let mut to = field(invite, HeaderName::To);
                to.extend_from_slice(b";tag=srs");
                to
            }),
            ("Call-ID", field(invite, HeaderName::CallId)),
            ("CSeq", field(invite, HeaderName::CSeq)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"Contact: <sip:srs@203.0.113.9:5060;transport=tcp>\r\n");
        out.extend_from_slice(b"Content-Type: application/sdp\r\n");
        out.extend_from_slice(
            format!("Content-Length: {}\r\n\r\n", SERVER_ANSWER.len()).as_bytes(),
        );
        out.extend_from_slice(SERVER_ANSWER);
        out
    }

    fn poll_recording(media: SipralHandle) -> Option<(Vec<u8>, String, u32)> {
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        let mut far_end = u32::MAX;
        let status =
            unsafe { sipral_media_poll_recording(media, &raw mut packet, &raw mut far_end) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        (packet.len > 0).then(|| {
            let (payload, destination) = buffers.taken(&packet);
            (payload, destination, far_end)
        })
    }

    #[test]
    fn a_recorded_call_invites_the_server_and_copies_both_parties_to_it() {
        let mut observed = Observed::default();
        let (handle, call) = media_call(&mut observed);
        connect_to_server(handle);
        let (status, recording) = record(handle, call, &config());
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(recording, SIPRAL_HANDLE_NONE);
        assert_ne!(recording, call);
        let invite = sent(handle)
            .into_iter()
            .find(|message| start_line(message).starts_with("INVITE"))
            .expect("the recording session was offered");
        assert!(start_line(&invite).starts_with("INVITE sip:srs@example.com"));
        assert_eq!(field(&invite, HeaderName::Require), b"siprec");
        let content_type =
            String::from_utf8(field(&invite, HeaderName::ContentType)).expect("UTF-8");
        assert!(
            content_type.starts_with("multipart/mixed"),
            "{content_type}"
        );
        let whole = String::from_utf8_lossy(&body(&invite)).into_owned();
        assert!(
            whole.contains("a=label:1") && whole.contains("a=label:2"),
            "{whole}"
        );
        assert!(
            whole.contains("m=audio 40010 ") && whole.contains("m=audio 40012 "),
            "{whole}"
        );
        assert!(whole.contains("application/rs-metadata+xml"), "{whole}");

        let answer = server_accepted(&invite);
        let status = unsafe {
            sipral_stack_receive_stream(handle, TO_SERVER, answer.as_ptr(), answer.len(), 1_300)
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        poll(handle, 1_300);
        assert_eq!(
            state_of(handle, recording),
            SipralCallState::Confirmed as u32
        );
        let _ = sent(handle);

        let media = media_of(handle, call);
        assert!(poll_recording(media).is_none(), "nothing copied yet");
        assert!(capture_one(media, &[0; FRAME]) > 0, "a frame went out");
        let (copy, destination, far_end) = poll_recording(media).expect("this end's copy");
        assert_eq!(destination, "203.0.113.9:50000");
        assert_eq!(far_end, 0);
        assert_eq!(copy[1] & 0x7f, 0, "the call's codec");

        // RFC 3550 A.1 holds a new source on probation for its first packet,
        // and what is not taken is not copied either
        for sequence in 1..4_u16 {
            let mut heard = rtp(sequence, u32::from(sequence) * 160);
            let _ = arrive(media, &mut heard, crate::call::tests::PEER_MEDIA, 1_320);
        }
        let (_, destination, far_end) = poll_recording(media).expect("the far end's copy");
        assert_eq!(destination, "203.0.113.9:50002");
        assert_eq!(far_end, 1);

        let status = unsafe { sipral_call_stop_recording_to(handle, call, 1_400) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert!(
            sent(handle)
                .iter()
                .any(|message| start_line(message).starts_with("BYE")),
            "the recording session was hung up"
        );
        assert!(capture_one(media, &[0; FRAME]) > 0);
        assert!(poll_recording(media).is_none(), "the copies stopped");
        assert_eq!(
            unsafe { sipral_call_stop_recording_to(handle, call, 1_500) },
            SipralStatus::WrongState,
            "nothing records it now"
        );
        release(media);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_recording_asked_for_badly_is_refused_with_nothing_sent() {
        let mut observed = Observed::default();
        let (handle, call) = media_call(&mut observed);
        connect_to_server(handle);
        let mut no_server = config();
        (no_server.server, no_server.server_len) = (ptr::null(), 0);
        let mut not_a_uri = config();
        (not_a_uri.server, not_a_uri.server_len) = as_text("srs example");
        let mut one_socket = config();
        (one_socket.far_end, one_socket.far_end_len) = as_text(THIS_END);
        let mut transport_alone = config();
        (transport_alone.destination, transport_alone.destination_len) = (ptr::null(), 0);
        let mut unknown_transport = config();
        unknown_transport.transport = 7;
        for refused in [
            no_server,
            not_a_uri,
            one_socket,
            transport_alone,
            unknown_transport,
        ] {
            assert_eq!(
                record(handle, call, &refused).0,
                SipralStatus::InvalidArgument
            );
        }
        let short = SipralRecordConfig {
            size: 16,
            ..config()
        };
        assert_eq!(
            record(handle, call, &short).0,
            SipralStatus::UnsupportedVersion
        );
        assert_eq!(
            unsafe { sipral_call_stop_recording_to(handle, call, 1_300) },
            SipralStatus::WrongState
        );
        let media = media_of(handle, call);
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        assert_eq!(
            unsafe { sipral_media_poll_recording(media, &raw mut packet, ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
        release(media);
        assert!(
            !sent(handle)
                .iter()
                .any(|message| start_line(message).starts_with("INVITE")),
            "nothing was offered"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_whose_audio_this_stack_does_not_run_cannot_be_recorded() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        connect_to_server(handle);
        assert_eq!(record(handle, call, &config()).0, SipralStatus::WrongState);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }
}
