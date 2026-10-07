// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Printed from the declarations in crates/sipral-ffi by tools/abi-gen. Do
// not edit: `cargo run -p sipral-abi-gen` writes it again, and
// `scripts/check.sh` fails when what is committed is not what came out.
//
// The raw koffi surface over the C ABI: every alias, enumeration width,
// struct, union and callback declared to koffi under the name
// `bindings/c/include/sipral.h` gives it, so `docs/08-ffi.md` reads for
// this module too, and every entry point a member of `Sipral`, loaded
// from the library `Sipral.open` found and checked. A pointer member of
// a record is an address here, read for the length beside it.
//
// Nothing here is idiomatic. The stack, the account, the call and the
// media in `bindings/node/src/` are written against this file by hand,
// and are what an application reaches for.

import { existsSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import koffi from 'koffi';

/** An address as koffi hands one back, or anything it takes for one. */
export type Pointer = bigint | number | Buffer | ArrayBufferView | null;

/** A 64-bit integer: a `number` while it is exact, a `bigint` past that. */
export type Wide = number | bigint;

/**
 * An opaque reference to something this library owns.
 *
 * It is a number, not a pointer: nothing is to be read from it, and
 * nothing but this library can make one. Zero is never a live handle,
 * which is what a caller can zero a variable to.
 *
 * An account or a call handle names something only on the stack that
 * minted it. Used with any other stack — one alive beside it, or one
 * created after it was destroyed — it is `SIPRAL_STATUS_INVALID_HANDLE`.
 */
koffi.alias('sipral_handle_t', 'uint64_t');

/**
 * The value no live handle ever takes.
 */
export const SIPRAL_HANDLE_NONE = 0;

/**
 * The ABI's major version. Nothing published against one major works
 * against another; within one, a binding built against a minor works
 * against a library at that minor or any later one.
 */
export const SIPRAL_ABI_VERSION_MAJOR = 1;

/**
 * The ABI's minor version, raised by anything the header gains —
 * everything the generator prints, and not only a function or a struct
 * member. `sipral_abi_check` compares the major and this one; the patch it
 * does not ask about. The
 * rule for all three numbers is the Versioning section of
 * `docs/08-ffi.md`, which is where the ABI contract is written down.
 */
export const SIPRAL_ABI_VERSION_MINOR = 2;

/**
 * The ABI's patch version, raised by a fix that changes no declaration.
 */
export const SIPRAL_ABI_VERSION_PATCH = 0;

/**
 * Bits of sipral_capabilities_t::transports. A caller checks
 * `capabilities.transports & SIPRAL_TRANSPORT_BIT_TLS != 0` rather than a
 * growing list of booleans, so a transport this ABI has not learned a bit
 * for yet reads as absent rather than refusing to compile against an
 * older header.
 *
 * Named after sipral_transport_t's own numbers (`1 << (value - 1)`), so
 * a transport added there in the future gets a bit here without the two
 * numbering schemes ever being asked to agree by hand.
 */
export const SIPRAL_TRANSPORT_BIT_UDP = 1;

/**
 * See SIPRAL_TRANSPORT_BIT_UDP.
 */
export const SIPRAL_TRANSPORT_BIT_TCP = 2;

/**
 * See SIPRAL_TRANSPORT_BIT_UDP.
 */
export const SIPRAL_TRANSPORT_BIT_TLS = 4;

/**
 * See SIPRAL_TRANSPORT_BIT_UDP.
 */
export const SIPRAL_TRANSPORT_BIT_WS = 8;

/**
 * See SIPRAL_TRANSPORT_BIT_UDP.
 */
export const SIPRAL_TRANSPORT_BIT_WSS = 16;

/**
 * Bits of sipral_capabilities_t::features.
 */
export const SIPRAL_FEATURE_DTMF = 1;

/**
 * See SIPRAL_FEATURE_DTMF.
 */
export const SIPRAL_FEATURE_RTCP_MUX = 2;

/**
 * See SIPRAL_FEATURE_DTMF.
 */
export const SIPRAL_FEATURE_RECORDING = 4;

/**
 * See SIPRAL_FEATURE_DTMF.
 */
export const SIPRAL_FEATURE_MEDIA_STALL_WATCHDOG = 8;

/**
 * See SIPRAL_FEATURE_DTMF.
 */
export const SIPRAL_FEATURE_SRTP = 16;

/**
 * See SIPRAL_FEATURE_DTMF. RFC 6665 subscriptions and the
 * dialog-state package a busy lamp field is built on, reached with
 * sipral_account_subscribe.
 */
export const SIPRAL_FEATURE_SUBSCRIPTIONS = 32;

/**
 * See SIPRAL_FEATURE_DTMF. Opus is behind a compile-time feature,
 * because libopus is the one part of the audio path that is licensed
 * rather than written, so a build meant for hardware can leave it out.
 * The bit is how an application finds out without having to enumerate
 * the codecs, and it is set from the catalogue this build offers rather
 * than from any crate's feature flag; `SIPRAL_CODEC_OPUS` keeps its
 * number either way, since a value that has left this header is spent
 * for good.
 */
export const SIPRAL_FEATURE_OPUS = 64;

/**
 * DTLS-SRTP (RFC 5764): the keys for a call's media come from a
 * handshake on the media path rather than from the body of a message.
 *
 * Behind a compile-time feature for the reason Opus is: a build that
 * will only ever place SDES calls over a protected SIP transport has no
 * use for an elliptic curve, and a desk phone counts its flash. Both
 * `SIPRAL_SRTP_DTLS` and `SIPRAL_SRTP_DTLS_REQUIRED` keep their numbers
 * in a build without it — a value that has left this header is spent —
 * and naming one there answers `SIPRAL_STATUS_NOT_SUPPORTED` rather than
 * quietly placing an unencrypted call.
 *
 * An application that sets one of those policies must also drain
 * `sipral_media_poll_transmit`; see there.
 */
export const SIPRAL_FEATURE_DTLS_SRTP = 128;

/**
 * See SIPRAL_FEATURE_DTMF. ICE in the full role (RFC 8445), with
 * consent freshness (RFC 7675) and the SDP attributes of RFC 8839: a
 * call's media path is chosen by checking it rather than taken from what
 * the signalling said.
 *
 * Behind a compile-time feature for the reason DTLS-SRTP is, and off by
 * policy even where it is compiled in — `docs/06-nat.md` tabulates what
 * it costs on the wire and why it buys nothing against a PBX that learns
 * the caller's address from the media it receives. Both `SIPRAL_ICE_OFFERED`
 * and `SIPRAL_ICE_REQUIRED` keep their numbers in a build without it, and
 * naming one there answers `SIPRAL_STATUS_NOT_SUPPORTED`.
 *
 * An application that sets one of those policies must also drain
 * `sipral_media_poll_transmit`; see there.
 */
export const SIPRAL_FEATURE_ICE = 256;

/**
 * See SIPRAL_FEATURE_DTMF. STUN (RFC 8489): a stack created with
 * `SIPRAL_NAT_STUN` asks a server where its sockets appear from and
 * writes the answer in the `Contact` and in `c=` and `m=`.
 *
 * Behind a compile-time feature of its own, which brings nothing ICE
 * does not already bring. `SIPRAL_NAT_STUN` keeps its number in a build
 * without it, and naming it there answers `SIPRAL_STATUS_NOT_SUPPORTED`.
 */
export const SIPRAL_FEATURE_STUN = 512;

/**
 * See SIPRAL_FEATURE_DTMF. A TURN server reached over TCP or TLS
 * (RFC 8656 §3.1): `sipral_stack_config_t::turn_transport`, and the
 * connection the application opens for each media socket when
 * `SIPRAL_EVENT_KIND_TURN_STREAM` asks — for the network that lets no
 * UDP out.
 *
 * It comes with `SIPRAL_FEATURE_ICE`, since a relay is only ever a
 * call's relayed ICE candidate, and without it `turn_transport` other
 * than UDP answers `SIPRAL_STATUS_NOT_SUPPORTED` as a `turn_server`
 * does.
 */
export const SIPRAL_FEATURE_TURN_STREAM = 1024;

/**
 * See SIPRAL_FEATURE_DTMF. The built-in audio engine: a stack
 * created with `sipral_stack_config_t::audio` set to
 * `SIPRAL_AUDIO_DEVICE` opens the platform's devices and pumps every
 * managed call itself, with the `sipral_audio_*` entry points to list,
 * choose and control them. Clear where there is no backend — on Linux,
 * and on an Android phone below API level 28, where AAudio cannot open
 * a voice-communication stream — and `SIPRAL_AUDIO_DEVICE` then
 * answers `SIPRAL_STATUS_NOT_SUPPORTED` and the application pumps the
 * frames as it always has. On Android the answer is the phone's, read
 * when asked, not the build's.
 *
 * This crate's own answer rather than the facade's: the engine sits
 * beside the facade, not under it, so the facade has nothing to say.
 */
export const SIPRAL_FEATURE_AUDIO_DEVICE = 2048;

/**
 * See SIPRAL_FEATURE_DTMF. Who is calling and how the call asked to
 * be answered, on every call event: the asserted identity behind the
 * account's `trusted_peers` (RFC 3325), `verstat`, `Privacy`,
 * `Diversion` and `History-Info`, `Answer-Mode` and `Alert-Info`;
 * why a call ended (`cause_sip`, `cause_q850`, RFC 3326) and
 * `sipral_call_hangup_for` to say why this end is ending one;
 * `sipral_call_redirect`; and an account's `privacy` and
 * `session_timer`.
 */
export const SIPRAL_FEATURE_CALLER_IDENTITY = 4096;

/**
 * See SIPRAL_FEATURE_DTMF. A call in progress moves with the
 * network under it: `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` names each
 * call whose media address is gone, and `sipral_call_media_readdress`
 * offers it at the socket the application bound on the new network.
 */
export const SIPRAL_FEATURE_CALL_READDRESS = 8192;

/**
 * See SIPRAL_FEATURE_DTMF. The engine's log through a callback,
 * with levels, rate-limited and redacted (`sipral_stack_log`), and a
 * snapshot of a stack's state for a crash report
 * (`sipral_stack_state_text`). Set in every build of this library, which
 * always carries the redaction both depend on; a bit so that a binding
 * asks before it shows a "send diagnostics" control.
 */
export const SIPRAL_FEATURE_LOGGING = 16384;

/**
 * See SIPRAL_FEATURE_DTMF. The ceilings a stack is created with
 * (`max_dialogs`, `max_server_transactions`, `diagnostic_decisions`,
 * `diagnostic_records` in `sipral_stack_config_t`, read back through
 * `sipral_stack_settings_t`), `SIPRAL_STATUS_LIMIT_REACHED` for a call
 * placed past `max_dialogs`, and the counters of what went out again,
 * what timed out and what was refused at a limit in
 * `sipral_counters_t`.
 */
export const SIPRAL_FEATURE_LIMITS = 32768;

/**
 * See SIPRAL_FEATURE_DTMF. STIR/SHAKEN (RFC 8224, RFC 8588): an
 * account given a key and a certificate URL signs every call it places
 * (`stir_key`, `stir_certificate_url` in `sipral_account_config_t`), and
 * a stack given trust anchors (`sipral_stack_stir`) verifies who is
 * calling before the phone rings — `SIPRAL_EVENT_KIND_CALLER_VERIFICATION`,
 * `sipral_call_stir_certificate`, and the verdict on every call event.
 * Behind a compile-time feature, on by default. ABI 0.31.
 */
export const SIPRAL_FEATURE_STIR = 65536;

/**
 * See SIPRAL_FEATURE_DTMF. An SRTP policy and suites per account
 * (`srtp`, `srtp_suites` in `sipral_account_config_t`), the policy that
 * falls back from DTLS-SRTP to SDES (`SIPRAL_SRTP_DTLS_OR_SDES`), calls
 * refused by it with `SIPRAL_STATUS_SECURITY_POLICY`, and the
 * encryption report of every call (`sipral_media_encryption_at`). ABI
 * 0.31.
 */
export const SIPRAL_FEATURE_SRTP_POLICY = 131072;

/**
 * See SIPRAL_FEATURE_DTMF. What a call carries inside its audio:
 * keypad digits heard in the far end's audio
 * (`sipral_stack_config_t::dtmf_detection`,
 * `sipral_call_dtmf_detection`, `SIPRAL_EVENT_KIND_IN_BAND_DIGIT`) and
 * written into this end's (`SIPRAL_DTMF_IN_BAND`, and `SIPRAL_DTMF_RTP`
 * on a call with no telephone event), call-progress tones, who answered
 * and the machine's beep (`sipral_call_detect_progress`,
 * `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`), and the beep that says a call
 * is recorded (`sipral_call_consent_tone`).
 */
export const SIPRAL_FEATURE_IN_BAND_SIGNALS = 262144;

/**
 * See SIPRAL_FEATURE_DTMF. A recording written as
 * `sipral_recording_options_t` says (`sipral_media_record_start_with`):
 * mixed or stereo, WAV growing into RF64, at a rate of its own and
 * checkpointed against a crash, and Ogg Opus where
 * SIPRAL_FEATURE_OPUS is set too. And L16 as a codec, at 8 and 16
 * kHz, which `sipral_codec_at` lists.
 */
export const SIPRAL_FEATURE_RECORDING_FORMATS = 524288;

/**
 * See SIPRAL_FEATURE_DTMF. A call recorded to a recording server
 * (SIPREC, RFC 7866): `sipral_call_record_to` places the recording
 * session, and `sipral_media_poll_recording` hands out the copies of
 * the call's audio.
 */
export const SIPRAL_FEATURE_SIPREC = 1048576;

/**
 * See SIPRAL_FEATURE_DTMF. The conference package kept for the
 * application (RFC 4575, `sipral_subscription_conference`), a focus
 * known by its `isfocus` (RFC 4579, `sipral_call_conference_uri`), and
 * presence published (RFC 3903, `sipral_account_publish_presence`) and
 * watched (RFC 3856, `SIPRAL_EVENT_KIND_PRESENCE_CHANGED`).
 */
export const SIPRAL_FEATURE_CONFERENCE = 2097152;

/**
 * See SIPRAL_FEATURE_DTMF. Real-time text in a call (RFC 4103):
 * `text_address` on the call's configuration, `sipral_media_send_text`
 * and `SIPRAL_EVENT_KIND_TEXT_RECEIVED`.
 */
export const SIPRAL_FEATURE_REALTIME_TEXT = 4194304;

/**
 * See SIPRAL_FEATURE_DTMF. RTP/AVPF with Generic NACKs and
 * reduced-size RTCP (RFC 4585, RFC 5506): `feedback` on the call's
 * configuration, and what it agreed in `sipral_media_info_t`.
 */
export const SIPRAL_FEATURE_RTCP_FEEDBACK = 8388608;

/**
 * See SIPRAL_FEATURE_DTMF. A local conference of any number of
 * calls, each on its own codec and rate, with or without this end
 * (ABI 0.32): `sipral_local_conference_create` and
 * `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED`.
 */
export const SIPRAL_FEATURE_LOCAL_CONFERENCE = 16777216;

/**
 * The buffer a caller has to bring for one outgoing packet.
 *
 * Not a path MTU — RTP does not discover one — but the bound the session
 * itself builds against, so a payload larger than this is a payload no
 * codec in this build produces. It is checked before anything is encoded,
 * because a frame that was encoded and then had nowhere to go is a frame
 * lost from a stream whose timestamps have already moved past it.
 */
export const SIPRAL_MEDIA_PACKET_BYTES = 1500;

/**
 * The bound a datagram of control gets instead, on the way in.
 *
 * RTCP is compound: one report packet carries a sender or receiver report
 * for every source being heard, then the source description, then whatever
 * extended reports the session agreed on. A call between two ends stays
 * far inside the media bound, but nothing in RFC 3550 says it has to, and
 * what arrives is the peer's arithmetic rather than ours. So the media
 * bound stops being the reason a report is refused: an arriving datagram
 * that RFC 5761 §4 says is control gets this one, and everything else
 * still gets SIPRAL_MEDIA_PACKET_BYTES. It bounds the read, so it is
 * still a bound: a caller that says a megabyte is still refused.
 *
 * Sending is unchanged — what this stack builds is its own arithmetic, and
 * it fits in the media bound.
 */
export const SIPRAL_MEDIA_RTCP_BYTES = 8192;

/**
 * Room enough for any address this ABI writes, the NUL included:
 * `[2001:db8:0000:0000:0000:0000:0000:0001]:65535` and a byte to spare.
 */
export const SIPRAL_ADDRESS_BYTES = 64;

/**
 * The transport a stack is created with.
 *
 * Never retired: sipral_stack_transport_failed and
 * sipral_stack_stream_closed can still stop it carrying traffic, and
 * sipral_stack_transport_bind is still what brings it back, exactly
 * as when this was the only number a stack had. Zero on
 * `sipral_account_config_t::transport` and `sipral_call_config_t::transport`
 * means this one, so a caller that never binds a second transport fills
 * neither in and gets exactly what it always got.
 */
export const SIPRAL_TRANSPORT_MAIN = 0;

/**
 * The largest message that crosses in either direction.
 *
 * The bound the layer below parses to, which is what stops a hostile peer
 * from making the parser do unbounded work. A caller's read buffer wants
 * to be this big on a stream, where one read can hold the end of one
 * message and the start of another, and 1500 bytes or so on a datagram
 * socket, where anything larger was fragmented on the way.
 */
export const SIPRAL_MESSAGE_BYTES = 65535;

/**
 * The longest `sipral_transport_failure_t::detail` this library takes.
 *
 * A platform's sentence about a refused certificate is a line, not a
 * document; one longer than this is refused rather than cut, since a
 * sentence cut short can say something else.
 */
export const SIPRAL_TRANSPORT_DETAIL_BYTES = 1024;

/**
 * The answer that lets an INVITE through, and the reason it is a status
 * code rather than a flag.
 *
 * A policy answers with what it wants said: 200 to let the call arrive,
 * or the status to refuse it with. Making acceptance 200 rather than
 * zero is the whole safety property of this mechanism — zero is what a
 * binding hands back when the application's listener threw, and what a
 * caller who filled nothing in leaves behind, and neither of those may
 * mean "let the stranger in".
 */
export const SIPRAL_SCREEN_ACCEPT = 200;

/**
 * The burst a stack starts with: ten INVITEs from one address at once.
 *
 * With SIPRAL_INVITE_LIMIT_EVERY_MS, the floor every stack has from
 * `sipral_stack_create` on. An INVITE past it is answered 480 and
 * counted in `sipral_counters_t::screened_refused_by_rate`; nothing is
 * raised for it.
 */
export const SIPRAL_INVITE_LIMIT_BURST = 10;

/**
 * The interval a stack starts with: one more INVITE every two seconds.
 */
export const SIPRAL_INVITE_LIMIT_EVERY_MS = 2000;

/**
 * The voice-agent preset's burst: a hundred and twenty-eight at once.
 *
 * For a headless service that takes every call from one trunk or proxy,
 * where the default's ten-then-one-every-two-seconds answers a
 * campaign's twelfth caller 480. Handed to `sipral_stack_invite_limit`
 * with SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS. The burst is the
 * default `max_dialogs`, so that a rush is turned away by the ceiling on
 * calls held, with a 503, before it is by the rate.
 */
export const SIPRAL_INVITE_LIMIT_VOICE_AGENT_BURST = 128;

/**
 * The voice-agent preset's interval: one more INVITE every fifty
 * milliseconds, twenty a second.
 */
export const SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS = 50;

/**
 * Bits of `sipral_call_event_t::privacy` and of
 * `sipral_account_config_t::privacy` (RFC 3323 §4.2): `header`, obscure
 * the fields that could identify the caller.
 */
export const SIPRAL_PRIVACY_HEADER = 1;

/**
 * `session`: hide the session description from the far end.
 */
export const SIPRAL_PRIVACY_SESSION = 2;

/**
 * `user`: user-level privacy.
 */
export const SIPRAL_PRIVACY_USER = 4;

/**
 * `id` (RFC 3325 §9.3): keep the asserted identity inside the trust
 * domain. What "withhold my number" asks for.
 */
export const SIPRAL_PRIVACY_ID = 8;

/**
 * `critical`: fail the call rather than go without the privacy asked
 * for.
 */
export const SIPRAL_PRIVACY_CRITICAL = 16;

/**
 * `none`: no privacy, stated. Read only; an account asks for none by
 * leaving every bit clear.
 */
export const SIPRAL_PRIVACY_NONE = 32;

/**
 * The longest text sipral_stack_state_text writes, its NUL included: a
 * buffer of this many bytes always has room.
 */
export const SIPRAL_STATE_TEXT_MAX = 16384;

/**
 * The result of a call across the C ABI.
 *
 * The numbers are part of the ABI. A value keeps its meaning for the life of
 * the ABI's major version, and a new one is only ever added at the end.
 *
 * 17 is a permanent hole: it was passed over when ABI 0.31 numbered its
 * statuses, and it stays reserved, never used and never to be given to a
 * status. No build returns it and `sipral_status_name` has no name for it.
 *
 * The one signed number in the ABI, and the only enumeration typed
 * `int32_t`: zero is success, every failure is positive, and no build
 * returns a negative one. A binding that treats it as unsigned loses
 * nothing. A newer library may return a status an older binding has no
 * name for; read it as a failure, with the last error for the sentence.
 */
export const SipralStatus = Object.freeze({
  /**
   * The call did what it was asked to.
   */
  Ok: 0,
  /**
   * A pointer was null where one is required, a length disagreed with what
   * it describes, or a value was outside what the call accepts.
   */
  InvalidArgument: 1,
  /**
   * The handle never came from this library, or it came from a stack
   * other than the one it was used with.
   */
  InvalidHandle: 2,
  /**
   * The handle came from this library and what it named is gone: a use
   * after free, or a second free.
   */
  StaleHandle: 3,
  /**
   * A versioned struct declared a size this build cannot work with, or a
   * binding asked for an ABI this library does not provide.
   */
  UnsupportedVersion: 4,
  /**
   * The buffer supplied is too small. The length needed has been written to
   * the out parameter, and nothing was written to the buffer.
   */
  BufferTooSmall: 5,
  /**
   * The object is already in use by another call, including one further
   * down the same call stack. Nothing was done, and nothing blocked.
   */
  Busy: 6,
  /**
   * There is no room for another one: the library's table of objects
   * of this kind is full (256 stacks, say), the stack's RTP port range
   * is spent, or a queue a call feeds is full — the DTMF digits waiting
   * to go out, the dynamic payload types an offer can number, the
   * real-time text not yet sent. Nothing was done. Room comes back as
   * objects are released, ports given back, or the queue drains; which
   * of those the last error says. Not the same as
   * `SIPRAL_STATUS_LIMIT_REACHED`, which is a ceiling the application
   * set itself.
   */
  Exhausted: 7,
  /**
   * A panic was caught at the boundary. The call did not finish, and the
   * last error carries whatever the panic said.
   */
  Panic: 8,
  /**
   * What was asked for cannot be done where the object is: answering a call
   * this end placed, holding one that is not up, sending DTMF before there
   * is a dialog to send it in. Not an argument that was wrong; a moment
   * that was.
   */
  WrongState: 9,
  /**
   * The request could not be assembled or handed to a transport. Nothing
   * went out, and nothing about the call changed.
   */
  NotSent: 10,
  /**
   * The value is one this ABI has a word for and this build has no code
   * behind. Nothing was applied, and asking again will not change that.
   *
   * The third of the three answers a configuration call may give, and the
   * one that has to be told apart from the other two by a machine.
   * SIPRAL_STATUS_INVALID_ARGUMENT says the value is wrong and a
   * corrected one would be taken; this says the value is right and there is
   * nothing here to take it. SIPRAL_STATUS_UNSUPPORTED_VERSION is about
   * the shape of what crossed the boundary, not about what was set in it.
   *
   * It exists so that "accepted and ignored" is not a thing this library
   * can do. An application that gets it turns the control off, because the
   * control is genuinely dead in this build; one that gets a silence
   * instead ships a control that does nothing and finds out from a
   * customer.
   */
  NotSupported: 11,
  /**
   * A byte stream carried something no message this library reads
   * starts with. Nothing in a stream marks where the next message
   * begins, so nothing arriving on it later can be read either: close
   * the connection. What rode on it is lost with it, and the call that
   * said so says what that was.
   */
  StreamBroken: 12,
  /**
   * An audio device id names nothing this stack's engine has ever
   * listed. Refused before any platform call is made;
   * `sipral_audio_device_at` says what the ids are.
   */
  NoSuchDevice: 13,
  /**
   * The audio device exists and cannot serve: it has no channels in
   * the direction asked, it is not plugged in, or the platform
   * refused to open it. The last error says which.
   */
  DeviceUnusable: 14,
  /**
   * The platform did not answer about its audio devices within
   * `sipral_stack_config_t::audio_probe_ms`: a driver is stuck, and
   * the engine is not waiting on it. What was asked was not done.
   */
  DeviceTimedOut: 15,
  /**
   * A limit the stack was created with refused new work: a call placed
   * while the calls this stack holds, has let in or has placed and
   * not yet heard back about already come to
   * `sipral_stack_config_t::max_dialogs`. Nothing went out. A call
   * that ends makes room; raising the limit means a new stack.
   */
  LimitReached: 16,
  /**
   * Refused by the account's security policy (ABI 0.31): a call that
   * would carry audio unencrypted where its account, or its own
   * configuration, requires SRTP, or that names a policy weaker than
   * its account's. An INVITE refused this way has been answered with
   * 488 Not Acceptable Here; a call being placed never left. The last
   * error says which.
   */
  SecurityPolicy: 18,
  /**
   * A recording's file would not take what was written to it: the disk
   * filled, the volume went away, the file was taken away underneath.
   * Not the path, which is `SIPRAL_STATUS_INVALID_ARGUMENT` before
   * anything is written. The recording has stopped; the file holds the
   * audio up to the last checkpoint it could write.
   */
  RecordingFailed: 19,
  /**
   * The call never agreed on what this asks for: text sent on a call
   * whose answer took no `m=text` stream, say. Nothing was done, and
   * only a new offer that the far end accepts changes it.
   */
  NotNegotiated: 20,
  /**
   * The far end of this call is not a conference focus: its Contact
   * never carried `isfocus` (RFC 4579 §4.1), so there is no
   * conference to name or subscribe to.
   */
  NotAFocus: 21,
  /**
   * The transport the request would leave on has failed or closed and
   * has not been bound again. Nothing went out. The failure was
   * reported as `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`; reconnect, tell
   * the stack with `sipral_stack_transport_bind`, and ask again.
   */
  TransportDown: 22,
  /**
   * A local conference would not take the call (ABI 0.32): it is
   * full, the call is already in a conference or joined into a pair
   * with `sipral_call_join`, or its codec hears at a rate the
   * conference does not mix. The last error says which.
   */
  ConferenceRefused: 23,
  /**
   * `now_ms` was more than fifty milliseconds behind the last reading
   * of the caller's clock this stack saw (ABI 0.33). Two threads that
   * read one clock a moment apart and race for the stack can disagree
   * by a little, not by that much. Nothing was done and the stack's
   * clock did not move: read the clock again and ask again. A caller
   * that keeps getting this has a clock that went backwards.
   */
  ClockBehind: 24,
  /**
   * The TLS server's certificate is not the one the account pins
   * (ABI 0.34): `sipral_account_check_certificate` compared its
   * SHA-256 fingerprint with `sipral_account_config_t::tls_pin_sha256`
   * and they differ. Refuse the handshake: with a pin, the
   * fingerprint is the whole verdict (`docs/22-tls.md`).
   */
  CertificateRefused: 25,
  /**
   * This end was about to advertise an address the peer cannot reach
   * it at (ABI 0.34): a loopback address, in a `Contact` or a session
   * description, handed to a peer that is not on this machine, or the
   * unspecified address in a `Contact`. Nothing was sent; the last
   * error names both addresses. Bind to, and advertise, the address
   * of the interface that routes to the peer —
   * `sipral_advertised_address` finds it.
   */
  UnreachableAddress: 26,
} as const);
koffi.alias('sipral_status_t', 'int32_t');

/**
 * What a stack speaks. Names for `sipral_stack_config_t::transport`.
 *
 * Zero is not one of them: a stack is told what it is speaking, because
 * guessing wrong in the direction of the plainest transport is how a caller
 * that meant TLS ends up on the wire in the clear.
 */
export const SipralTransport = Object.freeze({
  /**
   * UDP.
   */
  Udp: 1,
  /**
   * TCP.
   */
  Tcp: 2,
  /**
   * TLS over TCP.
   */
  Tls: 3,
  /**
   * WebSocket.
   */
  Ws: 4,
  /**
   * WebSocket over TLS.
   */
  Wss: 5,
} as const);
koffi.alias('sipral_transport_t', 'uint32_t');

/**
 * Why a transport could not deliver. Names for
 * sipral_stack_transport_failed's `error`.
 *
 * Coarse on purpose, and it is the layer below that is coarse: a client
 * transaction informs its user and terminates on every one of these (§17), and
 * the detail belongs in the caller's log, where the real message still is.
 */
export const SipralTransportError = Object.freeze({
  /**
   * Anything the caller could not classify. Zero, because a caller that
   * knows only that the write failed is telling the truth by saying nothing.
   */
  Other: 0,
  /**
   * Nothing is listening at the far end.
   */
  ConnectionRefused: 1,
  /**
   * An established connection was reset.
   */
  ConnectionReset: 2,
  /**
   * No route, or an ICMP unreachable.
   */
  Unreachable: 3,
  /**
   * The connection attempt or the write timed out.
   */
  TimedOut: 4,
  /**
   * The connection was closed and cannot be written to again.
   */
  Closed: 5,
} as const);
koffi.alias('sipral_transport_error_t', 'uint32_t');

/**
 * Why a TLS connection was refused, as the platform's TLS library said
 * it. Names for `sipral_transport_failure_t::tls` and
 * `sipral_transport_failed_event_t::tls`.
 *
 * Sipral links no TLS library (`docs/22-tls.md`), so these are the
 * application's words, mapped from its own library's error: the stack
 * only carries them to whoever reads the event, so that a user can be
 * told which of the four it was rather than "the connection closed".
 * A connection that was never answered is not one of them: that is
 * `SIPRAL_TRANSPORT_ERROR_CONNECTION_REFUSED` with this left at none.
 */
export const SipralTlsFailure = Object.freeze({
  /**
   * Not a TLS failure, or one the application could not classify.
   */
  None: 0,
  /**
   * No trusted authority stands behind the server's certificate: a
   * self-signed one, a private authority not handed over, or an
   * authority other than the one pinned.
   */
  Untrusted: 1,
  /**
   * The certificate is trusted and names another server.
   */
  NameMismatch: 2,
  /**
   * The certificate has expired, or is not valid yet.
   */
  Expired: 3,
  /**
   * The handshake itself failed: no protocol version or cipher in
   * common, an alert from the server, or a server that does not speak
   * TLS on that port.
   */
  HandshakeRefused: 4,
} as const);
koffi.alias('sipral_tls_failure_t', 'uint32_t');

/**
 * The three answers a setting can give in a struct that starts out zeroed.
 *
 * A boolean cannot carry them. Zero is what a caller who filled nothing in
 * leaves behind, so a plain `0`/`1` setting has no way to say "off" that is
 * not also "I said nothing", and the difference is the whole of B2: the
 * library must not turn a control off because the caller never touched it.
 */
export const SipralToggle = Object.freeze({
  /**
   * Nothing was said; whatever this build defaults to.
   */
  Default: 0,
  /**
   * On.
   */
  On: 1,
  /**
   * Off.
   */
  Off: 2,
} as const);
koffi.alias('sipral_toggle_t', 'uint32_t');

/**
 * What a call or a stack says about SRTP. Names for
 * `sipral_stack_config_t::srtp` (the stack's default) and
 * `sipral_call_config_t::srtp` (a per-call override).
 *
 * Zero is not one of them, and it is not the same absence on the two
 * structs: on the stack it means this build's own built-in default,
 * which is SIPRAL_SRTP_NOT_OFFERED; on a call it means the stack's own
 * setting, whatever that came to. `docs/05-media.md` says what each
 * value writes and what each answers.
 */
export const SipralSrtp = Object.freeze({
  /**
   * Do not offer it, but answer an offer that arrives on the secure
   * profile with keys anyway.
   */
  NotOffered: 1,
  /**
   * Offer it, and answer a plain offer plainly.
   */
  Offered: 2,
  /**
   * Offer it, and let no stream on this call carry audio unencrypted.
   */
  Required: 3,
  /**
   * Offer DTLS-SRTP (RFC 5764) on
   * `UDP/TLS/RTP/SAVP`, and answer a plain offer plainly.
   *
   * What `Offered` is for SDES, with the difference that matters: the
   * key never travels in the body, so this is the one policy here that
   * is sound over a SIP transport somebody else can read. The cost is
   * a round trip of silence at the start of every call while the
   * handshake runs, and an application that names it **must** drain
   * sipral_media_poll_transmit — a handshake whose records never
   * leave is a call that is up, silent, and reports no error.
   *
   * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
   * `SIPRAL_FEATURE_DTLS_SRTP`.
   */
  Dtls: 4,
  /**
   * Offer DTLS-SRTP, and let no stream on
   * this call carry audio any other way — an answer carrying
   * `a=crypto` included, since that key travelled in a body this
   * policy exists to avoid trusting.
   */
  DtlsRequired: 5,
  /**
   * DTLS-SRTP, falling back to SDES for a
   * peer that has no DTLS, and never unencrypted. The offer is one
   * `RTP/SAVP` stream carrying both the fingerprint and the crypto
   * lines, and the answer decides which keys the call; an offer that
   * arrives is answered the way it was keyed, and a plain one is
   * refused with 488. ABI 0.31.
   *
   * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
   * `SIPRAL_FEATURE_DTLS_SRTP`.
   */
  DtlsOrSdes: 6,
  /**
   * Offer SDES on plain `RTP/AVP`: the call is encrypted when the
   * answer takes one of the `a=crypto` lines and plain when it takes
   * none — the "SRTP optional" of desk phones, for a server that may
   * or may not encrypt and answers an offer on `RTP/SAVP` with 488
   * when it does not. RFC 4568 writes the attribute for the secure
   * profiles, so this is interoperability rather than a standard.
   * Answering, an offer on `RTP/AVP` carrying a line this end takes
   * is answered with a key, and anything else as under `Offered`.
   * ABI 0.34.
   */
  BestEffort: 7,
} as const);
koffi.alias('sipral_srtp_t', 'uint32_t');

/**
 * What a call or a stack says about ICE. Names for
 * `sipral_stack_config_t::ice` (the stack's default) and
 * `sipral_call_config_t::ice` (a per-call override).
 *
 * Zero is not one of them, and it is not the same absence on the two
 * structs: on the stack it means this build's own built-in default,
 * which is SIPRAL_ICE_OFF; on a call it means the stack's own
 * setting, whatever that came to.
 *
 * A call that offers ICE also asks for RFC 5761 multiplexing, whatever
 * `offer_rtcp_mux` says, because an ICE stream with a second component
 * needs a second address and this ABI names one.
 */
export const SipralIce = Object.freeze({
  /**
   * Do not offer it, and do not answer a peer that
   * does. The default, and `docs/06-nat.md` says why at length.
   */
  Off: 1,
  /**
   * Offer it, and use it against a peer that
   * offers it back.
   *
   * A peer that does not — an Asterisk with `ice_support=no`, which is
   * its default — is answered without it and the call runs on the
   * signalled address and symmetric RTP, exactly as it would have. An
   * application that names this **must** drain
   * sipral_media_poll_transmit: a check that never leaves is a
   * call that never chooses a path.
   *
   * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
   * `SIPRAL_FEATURE_ICE`.
   */
  Offered: 2,
  /**
   * Offer it, and let no stream on this call
   * carry audio on a path ICE did not check.
   *
   * Each of the three ways a peer can fail to do ICE ends the call's
   * media with `SIPRAL_EVENT_KIND_MEDIA_FAILED` instead of falling
   * back. That is the whole difference between this and `Offered`.
   */
  Required: 3,
  /**
   * Be an ICE-lite endpoint (RFC 8445 §2.5) —
   * write `a=ice-lite` and one host candidate, answer the checks a
   * full peer sends, and put the audio on the pair it nominates.
   *
   * **Only for a server reachable at the address it advertises**: the
   * media socket's own, or the public address a one-to-one NAT in
   * front of it forwards (`sipral_stack_nat_map`'s mapping, when that
   * is what STUN reports). A WebRTC gateway or any other full-ICE peer
   * calling a voice agent in a data centre is the case it is for. RFC
   * 8445 Appendix A says ICE "will not function when a lite
   * implementation is placed behind a NAT", and a peer told this end
   * is lite stops doing the work that would have found another path —
   * so a softphone never names it. A peer that does no ICE, or is lite
   * itself, gets the call on the signalled address, as under
   * `Offered`; the application drains `sipral_media_poll_transmit`
   * for the answers to the checks exactly as it does for a full
   * agent's.
   *
   * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
   * `SIPRAL_FEATURE_ICE`.
   */
  Lite: 4,
} as const);
koffi.alias('sipral_ice_t', 'uint32_t');

/**
 * One codec this ABI has a number for. Names for every member that says
 * which.
 *
 * A value here is permanent, and that is all it is: a number that has left
 * this header is spent for good, so a binding compiled against one keeps
 * working whatever a later build contains. Whether *this* build can produce
 * the codec is a different question, and `SIPRAL_FEATURE_*` together with
 * `sipral_codec_at` are what answer it. A settings screen that offers this
 * list unfiltered is a settings screen with controls that do nothing, which
 * is the mistake `sipral_capabilities` exists to prevent.
 */
export const SipralCodec = Object.freeze({
  /**
   * No codec: the call has none, or the event is not about one.
   */
  Unknown: 0,
  /**
   * G.711 mu-law, payload type 0.
   */
  Pcmu: 1,
  /**
   * G.711 A-law, payload type 8.
   */
  Pcma: 2,
  /**
   * G.722, wideband at the price of a narrowband stream.
   */
  G722: 3,
  /**
   * Opus. Declared in every build, whether or not this one linked
   * libopus, for the reason the enumeration above gives. Whether the
   * codec is here is `SIPRAL_FEATURE_OPUS` and the list
   * `sipral_codec_at` enumerates, never the presence of this name.
   */
  Opus: 4,
  /**
   * G.729 with Annex A, payload type 18: eight kilobits of narrowband
   * speech. In every build and in no default offer: a call offers it
   * only when a codec order names `G729`. It offers `annexb=yes`,
   * answers with the offer's `annexb`, and uses Annex B's silence
   * compression where both descriptions allow it.
   */
  G729: 5,
  /**
   * L16 at 8 kHz, one channel: the samples themselves, on a dynamic
   * payload type as `L16/8000`. In every build and in no default
   * offer: a call offers it only when a codec order names `L16/8000`.
   */
  L16Narrowband: 6,
  /**
   * L16 at 16 kHz, one channel, as `L16/16000`: wideband with nothing
   * lost, offered only when a codec order names `L16/16000`.
   */
  L16Wideband: 7,
} as const);
koffi.alias('sipral_codec_t', 'uint32_t');

/**
 * What became of one codec this call's catalogue could have used. Names
 * for sipral_codec_candidate_t::outcome.
 *
 * D5's codec half: a negotiation that ends in G.711 when the site
 * configured Opus is a support call, and the answer to it is a list
 * saying which of the two things happened — the far end never named
 * Opus, or it named it and something ahead of it in this end's order
 * won.
 */
export const SipralCodecOutcome = Object.freeze({
  /**
   * Not an outcome: either the candidate is from a build this ABI has
   * no number for, or the struct was never filled in.
   */
  Unknown: 0,
  /**
   * This is what the call agreed on. Exactly one candidate carries it,
   * and it names the same codec as `sipral_media_info_t::codec`.
   */
  Chosen: 1,
  /**
   * The far end's description did not name it, so it was never in the
   * running. The commonest answer, and the one that says the question
   * is about the far end's configuration rather than this one's.
   */
  NotNamed: 2,
  /**
   * The far end named it and this end had something better: the codec
   * in `outranked_by` came first in this call's order.
   */
  Outranked: 3,
} as const);
koffi.alias('sipral_codec_outcome_t', 'uint32_t');

/**
 * Whether a sipral_path_candidate_t is a candidate pair or a relay.
 */
export const SipralPathKind = Object.freeze({
  /**
   * Not a kind: the struct was never filled in.
   */
  Unknown: 0,
  /**
   * A candidate pair the call's ICE checklist held (RFC 8445
   * §6.1.2).
   */
  Pair: 1,
  /**
   * An allocation on a TURN server the call's agent held (RFC 8656).
   */
  Relay: 2,
} as const);
koffi.alias('sipral_path_kind_t', 'uint32_t');

/**
 * The kind of an ICE candidate (RFC 8445 §5.1.1). Names for
 * sipral_path_candidate_t::local_kind and `remote_kind`.
 */
export const SipralCandidateKind = Object.freeze({
  /**
   * Not known: a relay's server, which is no candidate, or the far
   * end of a pair a lite end took from a nomination and never learned
   * the kind of.
   */
  Unknown: 0,
  /**
   * An address a socket of the host's own is bound to.
   */
  Host: 1,
  /**
   * The address a NAT maps the host's socket to, as a STUN or TURN
   * server saw it.
   */
  ServerReflexive: 2,
  /**
   * An address a connectivity check revealed (RFC 8445 §7.3.1.3).
   */
  PeerReflexive: 3,
  /**
   * An address on a TURN server that relays for the host.
   */
  Relayed: 4,
} as const);
koffi.alias('sipral_candidate_kind_t', 'uint32_t');

/**
 * What became of one path a call's ICE agent tried. Names for
 * sipral_path_candidate_t::outcome.
 *
 * D5's transport and NAT half: a call that ended up relayed when a
 * direct path was expected, or found no path at all, is a support call,
 * and the answer to it is which of these happened to each pair.
 */
export const SipralPathOutcome = Object.freeze({
  /**
   * Not an outcome: either the path is from a build this ABI has no
   * number for, or the struct was never filled in.
   */
  Unknown: 0,
  /**
   * The path the call's media takes: the selected pair (RFC 8445
   * §8.1.2), or the relay it runs through.
   */
  Selected: 1,
  /**
   * A pair whose check succeeded, with nothing selected yet.
   */
  Valid: 2,
  /**
   * Nothing has decided it yet: a pair frozen, waiting its turn or
   * with its check on the wire; a relay still being allocated.
   */
  Waiting: 3,
  /**
   * A pair whose check succeeded, with a pair of higher priority
   * selected over it.
   */
  Outranked: 4,
  /**
   * A pair another was nominated ahead of: its check had not finished
   * when the selection took it off the checklist (RFC 8445 §8.1.2),
   * or it succeeded after a lower one was nominated.
   */
  NominatedElsewhere: 5,
  /**
   * A pair whose check was never answered (RFC 8489 §6.2.1).
   */
  TimedOut: 6,
  /**
   * A pair the far end refused; `code` is the STUN error code (RFC
   * 8445 §7.2.5.2.4).
   */
  Refused: 7,
  /**
   * A pair whose answer came from an address other than the one its
   * check went to (RFC 8445 §7.2.5.2.1): a NAT between rewriting it.
   */
  NotSymmetric: 8,
  /**
   * A pair whose answer named no address to form a valid pair from.
   */
  Unusable: 9,
  /**
   * A relayed pair the relay would not let the far end through for,
   * or a relay whose allocation the server refused; `code` is the
   * TURN server's error code, zero when it gave none (RFC 8656 §9,
   * §7.3).
   */
  RelayRefused: 10,
  /**
   * A pair never checked: the pair limit discarded it (RFC 8445
   * §6.1.2.5), or its checklist ended before its turn came.
   */
  NotChecked: 11,
  /**
   * A relay held, that no selected pair runs through — or none yet.
   */
  Held: 12,
  /**
   * A relay given back: ICE concluded on a pair that does not use it
   * (RFC 8445 §8.3.1), or this branch of a forked call let go of it.
   */
  Released: 13,
  /**
   * A relay the server took back; `code` is its error code, zero when
   * a refresh went unanswered (RFC 8656 §8).
   */
  Lost: 14,
} as const);
koffi.alias('sipral_path_outcome_t', 'uint32_t');

/**
 * Which way audio may flow, as seen from here. Names for every `direction`.
 */
export const SipralDirection = Object.freeze({
  /**
   * Not negotiated.
   */
  Unknown: 0,
  /**
   * Both ways.
   */
  SendRecv: 1,
  /**
   * This end sends and does not receive, which is what holding the far end
   * looks like from here.
   */
  SendOnly: 2,
  /**
   * This end receives and does not send.
   */
  RecvOnly: 3,
  /**
   * Neither way, and the stream stays in the session.
   */
  Inactive: 4,
} as const);
koffi.alias('sipral_direction_t', 'uint32_t');

/**
 * Where control traffic goes. Names for sipral_media_info_t::rtcp.
 */
export const SipralRtcp = Object.freeze({
  /**
   * Not negotiated.
   */
  Unknown: 0,
  /**
   * One port carries both (RFC 5761), which happens only where both ends
   * asked for it.
   */
  Muxed: 1,
  /**
   * A port of its own at each end.
   */
  SeparatePort: 2,
  /**
   * None at all: the peer said it is not using RTCP.
   */
  Off: 3,
} as const);
koffi.alias('sipral_rtcp_t', 'uint32_t');

/**
 * Why media failed. Names for `sipral_media_event_t::fault`.
 *
 * The sentence beside it says which case of the kind it was; this is the part
 * a machine acts on, and the two are never the same thing.
 */
export const SipralMediaFault = Object.freeze({
  /**
   * Nothing failed.
   */
  None: 0,
  /**
   * The negotiation settled on something this build cannot encode or
   * decode, which means the peer answered with a format that was not in the
   * offer.
   */
  UnsupportedCodec: 1,
  /**
   * The two descriptions agree on nothing that can carry audio.
   */
  NoCommonCodec: 2,
  /**
   * One end refused the stream with a port of zero. The call is up and
   * carries no audio, which is a thing a peer is allowed to want.
   */
  StreamRefused: 3,
  /**
   * There is no session description to work from.
   */
  NoDescription: 4,
  /**
   * A description could not be read.
   */
  BadDescription: 5,
  /**
   * The recording stopped writing: the disk filled, the file went away.
   */
  Recording: 6,
  /**
   * The codec refused a frame.
   */
  Codec: 7,
  /**
   * Something else the layer below reported and this ABI has no word for.
   */
  Other: 8,
  /**
   * ICE could not carry this call: the far end described none this
   * stack could use and the policy was `SIPRAL_ICE_REQUIRED`, the far
   * end took `a=rtcp-mux` out of an answer to an ICE offer, or consent
   * to send on the pair that was chosen was withdrawn part-way through
   * (RFC 7675 §5).
   *
   * A code of its own because it is the one an application can act on
   * differently: the call is up and the signalling is sound, and what
   * changed is only that no path could be checked. A deployment with a
   * non-ICE profile to fall back to falls back here.
   */
  Ice: 9,
  /**
   * The call's SRTP policy refused what the far end described: a plain
   * answer to a call that requires SRTP, which this end then hangs up
   * with a `Reason` of 488, or a plain re-offer inside one, refused
   * with 488 and the call left on the keys it had. ABI 0.31.
   */
  SecurityPolicy: 10,
} as const);
koffi.alias('sipral_media_fault_t', 'uint32_t');

/**
 * What a datagram handed to sipral_media_receive turned out to be.
 */
export const SipralArrival = Object.freeze({
  /**
   * Something this ABI has no word for.
   */
  Unknown: 0,
  /**
   * Audio, held for playout.
   */
  Queued: 1,
  /**
   * Audio that was not used: malformed, late, duplicated, from the wrong
   * address, or on a payload type nobody negotiated. The counters in
   * sipral_stream_stats_t say which, over the call.
   */
  Dropped: 2,
  /**
   * A reception or sender report, folded into the statistics.
   */
  Control: 3,
  /**
   * The far end says it is leaving the session (RFC 3550 §6.6). Audio will
   * stop; the call has not ended until signalling says so.
   */
  Goodbye: 4,
  /**
   * Control traffic that was not believed: from the wrong address, or not a
   * well-formed compound packet.
   */
  ControlRefused: 5,
  /**
   * A record of the DTLS-SRTP handshake that keys this call, which has
   * been taken. Whatever it owes the far end in reply is waiting in
   * sipral_media_poll_transmit, and this is the signal to drain it.
   */
  Handshake: 6,
  /**
   * Something arrived on a call that agreed to be encrypted and has no
   * keys yet, so there was nothing to verify it with. The ordinary way
   * this happens is a peer that starts sending the moment its own half
   * of the handshake finishes, which is before ours does.
   */
  NotKeyed: 7,
} as const);
koffi.alias('sipral_arrival_t', 'uint32_t');

/**
 * The SRTP transform a call is running. Names for
 * `sipral_media_event_t::suite`.
 */
export const SipralSrtpSuite = Object.freeze({
  /**
   * No transform: the event is not about one, or the call is not
   * encrypted.
   */
  Unknown: 0,
  /**
   * `AES_CM_128_HMAC_SHA1_80`, the one every implementation has.
   */
  AesCm80: 1,
  /**
   * `AES_CM_128_HMAC_SHA1_32`, the same cipher with a shorter tag.
   */
  AesCm32: 2,
  /**
   * `F8_128_HMAC_SHA1_80`, which is what 3GPP asks for. Reachable by
   * SDES only; RFC 5764 §4.1.2 defines no DTLS-SRTP profile for it.
   */
  AesF8: 3,
  /**
   * `AES_256_CM_HMAC_SHA1_80` (RFC 6188): `AesCm80` with a 256-bit
   * key. Reachable by SDES only, like `AesF8`: no DTLS-SRTP profile
   * names it.
   */
  Aes256Cm80: 4,
  /**
   * `AES_256_CM_HMAC_SHA1_32` (RFC 6188): `AesCm32` with a 256-bit
   * key. SDES only, as `Aes256Cm80`.
   */
  Aes256Cm32: 5,
  /**
   * `AEAD_AES_128_GCM` (RFC 7714): AES-GCM, one transform for both
   * confidentiality and integrity. DTLS-SRTP profile 0x0007.
   */
  AeadAes128Gcm: 6,
  /**
   * `AEAD_AES_256_GCM` (RFC 7714): the same with a 256-bit key, and
   * what two ends of this stack settle on over DTLS-SRTP. Profile
   * 0x0008.
   */
  AeadAes256Gcm: 7,
} as const);
koffi.alias('sipral_srtp_suite_t', 'uint32_t');

/**
 * Where the frame sipral_media_playback just produced came from.
 */
export const SipralPlayback = Object.freeze({
  /**
   * Something this ABI has no word for.
   */
  Unknown: 0,
  /**
   * A packet the far end sent.
   */
  Packet: 1,
  /**
   * One it sent and this end did not get, filled in by the concealment.
   */
  Concealed: 2,
  /**
   * Comfort noise, from an RFC 3389 payload the far end sent instead of
   * audio.
   */
  ComfortNoise: 3,
  /**
   * Nothing was due: the buffer is still filling, or the far end has
   * stopped.
   */
  Silence: 4,
} as const);
koffi.alias('sipral_playback_t', 'uint32_t');

/**
 * Which way a digit goes to the far end. Names for
 * sipral_call_send_dtmf's `via`.
 *
 * The choice is per send, not per call, because it is a fact about the peer
 * rather than about this end, and the way to find out which one a peer takes
 * is to try. A carrier that ignores one of these ignores it silently.
 */
export const SipralDtmf = Object.freeze({
  /**
   * In the media, as an RFC 4733 named telephone event. What to reach for:
   * it is the only one carried end to end by every gateway on the path, and
   * the only one whose timing survives transcoding.
   *
   * It is one rather than zero on purpose. Zero is what a caller who
   * filled nothing in leaves behind, and the way a digit travels is the
   * one setting here that a peer can ignore in silence: a call that
   * meant INFO and sent nothing at all looks, from this end, exactly
   * like a call that sent it. So zero names no form and is refused.
   */
  Rtp: 1,
  /**
   * An INFO per digit carrying `application/dtmf-relay`, which states the
   * signal and how long it was held.
   */
  InfoRelay: 2,
  /**
   * An INFO per digit carrying `application/dtmf`, whose whole body is the
   * character. Some switches take only this one.
   */
  InfoPlain: 3,
  /**
   * In the media, as the two tones of each key written into the audio in
   * place of the microphone, whatever the negotiation settled on: for
   * the far end that negotiated a telephone event and then listens only
   * to the audio. `SIPRAL_DTMF_RTP` does this by itself on a call that
   * negotiated no telephone event.
   */
  InBand: 4,
} as const);
koffi.alias('sipral_dtmf_t', 'uint32_t');

/**
 * What an event is about.
 *
 * The numbers are part of the ABI and are only ever added to. A binding
 * that meets a kind it does not know must ignore that event rather than
 * refuse it, which is what makes adding one safe.
 *
 * Numbers already spent on features this build does not have:
 * - 16: held for the set of audio devices changed (A2), which shipped as 43 in the wave that allocated its number; spent all the same
 * - 44: held for a second audio device event, which the audio engine did not need; spent all the same
 */
export const SipralEventKind = Object.freeze({
  /**
   * The stack is running on this thread.
   *
   * The first event on every stack, delivered by the first poll and never
   * again. A binding that has a callback to hand out, a queue to open or a
   * thread to name has somewhere definite to do it, before anything that
   * matters can arrive.
   */
  Started: 1,
  /**
   * A registration moved: it went out, it took, it is being refreshed, it
   * was given up, or it failed. `payload.registration` says which, and
   * `account` says whose.
   */
  RegistrationChanged: 2,
  /**
   * Somebody is calling. Answer, ring, or reject it.
   */
  IncomingCall: 3,
  /**
   * A call this end placed is getting somewhere short of an answer.
   */
  CallProgress: 4,
  /**
   * A proxy forked the INVITE and a second phone is ringing.
   * `payload.call.other` is the branch that has just appeared.
   */
  CallForked: 5,
  /**
   * The call is up.
   */
  CallConfirmed: 6,
  /**
   * The session inside a live call changed: a hold, a resume, or an offer
   * either end made and had accepted.
   */
  SessionChanged: 7,
  /**
   * The far end offered a change this stack has no policy for. The
   * transaction is held open: answer it or refuse it, or the call ends.
   */
  SessionOffered: 8,
  /**
   * A change this end offered was refused. The session stands as it was.
   */
  SessionChangeFailed: 9,
  /**
   * The far end asked this one to call somebody else.
   */
  TransferRequested: 10,
  /**
   * A transfer this end asked for is under way.
   */
  TransferProgress: 11,
  /**
   * And how it ended: the final status the far end reported, a 2xx
   * hanging this call up. A REFER the far end refused outright
   * (4xx–6xx, RFC 3515 §2.4.2) ends here too, with the refusal's
   * status, and so does one that went unanswered, as a 408, or whose
   * transport failed, as a 503 (ABI 1.2); either way the call stays
   * as it was.
   */
  TransferDone: 12,
  /**
   * A call arrived carrying a `Replaces` and took over one already up.
   * `payload.call.other` is the one being replaced.
   */
  CallReplaced: 13,
  /**
   * The call is over, and its handle is stale from here on.
   *
   * `message` is the refusal when a response ended it, and the BYE
   * or the CANCEL when the far end did (ABI 1.2), so that a header
   * field of the far end's own on it can be read with
   * `sipral_message_header`; null otherwise.
   */
  CallEnded: 14,
  /**
   * A subscription moved: it was asked for, granted, put on probation,
   * scheduled for another attempt, or ended.
   *
   * A1. `payload.subscription` says which one and where it is now, and
   * `reason` why it is not live when it is not. Not sent on every
   * refresh — a lamp does not move because a refresh was scheduled —
   * and not sent for a notification arriving, which is
   * SIPRAL_EVENT_KIND_NOTIFIED instead.
   */
  SubscriptionChanged: 15,
  /**
   * What one call's media cost, delivered once, after
   * `SIPRAL_EVENT_KIND_CALL_ENDED`.
   *
   * A6's second consumer. `payload.media.statistics` points at the
   * completed record; it is the library's and lives as long as the callback
   * does. The stream is gone by the time this arrives, which is why the
   * numbers travel in the event rather than behind a lookup that would now
   * fail.
   */
  MediaStatistics: 17,
  /**
   * A request grew too large for a datagram (RFC 3261 §18.1.1) and this
   * stack has no stream transport open to the destination it names.
   * `payload.transport_wanted` says where it was going, over what
   * protocol, and how it measured against the datagram it did not fit.
   *
   * B1. The call that asked for the request — placing a call,
   * registering — was refused with `SIPRAL_STATUS_NOT_SENT`, and
   * nothing went on the wire. Answered with
   * sipral_stack_transport_bind:
   * once the application has bound a transport to that destination,
   * asking again sends the request on it, and this ABI raises nothing
   * further about it — there is no "it went" event, the same way there
   * is none for an ordinary request that fit the first time.
   */
  TransportWanted: 18,
  /**
   * Nothing has arrived on the media path for longer than the configured
   * threshold, while signalling is perfectly happy.
   *
   * B5. `payload.media.silent_for_ms` says how long. The call is untouched:
   * whether to hang up over silence is a decision with a person on the other
   * end of it.
   */
  MediaStalled: 19,
  /**
   * A call a push announced never arrived.
   *
   * C2, and not an error. A wake-up chain has a notification service,
   * a proxy, a bucket timer and a radio in it, and when a call does not
   * come through it this is the only place that says which end gave up:
   * the push was delivered, this device woke, refreshed its binding,
   * and no INVITE followed. `payload.announce` says which announcement
   * and how long it was waited for; the screen the application raised
   * can come down.
   */
  AnnouncedCallMissing: 20,
  /**
   * Audio is running: the negotiation settled and an RTP session is open.
   *
   * A4's reporting half and the first half of D5: `payload.media.codec` is
   * what the two ends agreed on. This is the moment to mint the call's
   * media handle with `sipral_call_media`, and `sipral_media_info` on it
   * says the rest.
   */
  MediaStarted: 21,
  /**
   * The session changed under a live call: a hold, a resume, a peer that
   * moved its media address, or a re-negotiation onto another codec.
   */
  MediaChanged: 22,
  /**
   * Packets are arriving again. `payload.media.silent_for_ms` says how long
   * the gap turned out to be.
   */
  MediaResumed: 23,
  /**
   * Media could not be started or could not be kept. The call itself is
   * untouched; `payload.media.fault` and `payload.media.reason` say why.
   */
  MediaFailed: 24,
  /**
   * A recording stopped on its own, part-way through: the disk filled, the
   * file went away, the volume was unmounted.
   *
   * Never an abort. `payload.media.recorded_ms` says how much audio reached
   * the file before it stopped, and the call carries on without it.
   */
  RecordingStopped: 25,
  /**
   * The far end pressed a key: an RFC 4733 named telephone event, or an
   * INFO carrying `application/dtmf-relay` or `application/dtmf`.
   *
   * One per keypress, not one per packet: an RFC 4733 digit goes out as
   * a run of updates and then its closing packet three times, and the
   * layer below collapses them on the timestamp that identifies the
   * event; an INFO is one request. `payload.media.digit` is the
   * character, `event_code` the number behind it for the events no
   * keypad has a key for, `held_ms` how long it lasted, and `source`
   * a `SIPRAL_DIGIT_SOURCE` naming which of the two reported it.
   * `held_ms` zero means either of two different facts: an
   * `application/dtmf` INFO never carries a duration at all, and a
   * peer using the other form may have said `Duration=0` and held the
   * key for no time at all — this C ABI does not tell the two apart.
   */
  DigitReceived: 26,
  /**
   * An INFO this end sent for `sipral_call_send_dtmf` reached a final
   * answer. `payload.call.digit` is the character and
   * `payload.call.status_code` what the far end answered — a 415 from
   * a switch that does not take this `Content-Type` included, so the
   * application learns which of the two INFO forms to try without
   * guessing from silence. A digit that waited behind another and whose
   * own INFO could then not be sent at all is reported the same way,
   * with 503: nothing reached the far end for that one, and no digit
   * after it is sent.
   */
  DtmfSent: 27,
  /**
   * The lifecycle machine settled: a registrar answered again and
   * proved a path this stack had stopped believing in, or every rung
   * of a recovery ladder was climbed and none of them worked.
   * `payload.recovery` says which, and carries what the ladder that
   * got there actually knows. `crates/sipral-ffi/src/lifecycle.rs`
   * and `docs/16-lifecycle.md` are the ladder this reports on.
   */
  Recovery: 28,
  /**
   * A dialog's next hop is a name, and this library does not look
   * names up.
   *
   * RFC 3263 §4's TARGET, before any NAPTR, SRV or A lookup: the
   * route set and the remote target say where this dialog's requests
   * should go, and what they say is not where they are going. Nothing
   * here owns a resolver — nothing here owns a socket either — so the
   * answer is the application's, through
   * sipral_stack_resolved,
   * with `payload.resolve.dialog` as the handle it takes.
   *
   * **Ignoring it is legitimate and is the common case.** The dialog
   * keeps the flow its first message travelled on, which §8.1.2 allows
   * as an alternate address and which is the only thing that survives
   * a NAT. Nothing times out, nothing retries, and no second event
   * says the first went unanswered.
   */
  ResolveNeeded: 29,
  /**
   * A notification arrived on a subscription, and has been answered.
   *
   * A1's other half. The NOTIFY is in `message`, whole and unparsed,
   * which is where every package this ABI has no reader for is read
   * from. `payload.subscription.has_dialog_info` says the body was
   * `application/dialog-info+xml` and could be read, and the picture it
   * updated is behind
   * sipral_subscription_dialog_count.
   * A body that could not be read arrives here all the same, with that
   * member zero and the request whole: a lamp showing what was last
   * known beats one showing what a malformed document happened to
   * contain.
   */
  Notified: 30,
  /**
   * The INVITE for a call a push had already announced has arrived
   * (RFC 8599).
   *
   * C2's other half. Queued immediately before the
   * SIPRAL_EVENT_KIND_INCOMING_CALL naming the same call, and never
   * without one, so that an application reading its events in order
   * knows which screen the call belongs to before it is told there is a
   * call at all. That is the whole point: on a phone the ringing screen
   * exists first, and a stack that reports the INVITE without saying
   * which announcement it answers has made the application guess.
   *
   * `call` is the call, and `payload.announce.announcement` what
   * announced it. That announcement is spent: it is not waited for any
   * more, and `sipral_announcement_forget` on it answers
   * `SIPRAL_STATUS_WRONG_STATE` rather than taking a screen down twice.
   */
  CallAnnounced: 31,
  /**
   * The handshake that keys a call finished, and audio can move
   * (RFC 5764).
   *
   * Only DTLS-SRTP produces it, and it is the moment the call becomes
   * what it agreed to be: between `SIPRAL_EVENT_KIND_MEDIA_STARTED`
   * and this one the stream exists, has an address and a codec, and
   * carries nothing in either direction. An application that draws a
   * padlock draws it here.
   *
   * `call` is the call and `payload.media.suite` is the transform the
   * handshake chose — the signalling does not, which is why there is
   * an event for it at all. A call keyed by SDES never produces one,
   * because such a call is keyed before its session is opened.
   *
   * A handshake that does not finish produces
   * `SIPRAL_EVENT_KIND_MEDIA_FAILED` instead, and the call is left up:
   * whether to hang it up is a decision with a person on the other end
   * of it.
   */
  MediaSecured: 32,
  /**
   * `sipral_media_event_t`: ICE chose the path this call's media takes
   * (RFC 8445 §8.1.1), and audio can move.
   *
   * The moment the connectivity checks stop, and the answer to "why is
   * this call sending to an address the signalling never named" —
   * which, behind a NAT, is the ordinary outcome rather than a fault.
   * It arrives again if a nomination of higher priority replaces the
   * pair part-way through the call.
   *
   * The two addresses of the pair are deliberately not carried here,
   * for the reason `SIPRAL_EVENT_KIND_MEDIA_SECURED` gives about its
   * own: every packet `sipral_media_capture` and
   * `sipral_media_poll_transmit` hand back already names the
   * destination to send it to, so an application that puts this
   * stack's media on a socket at all has the address the moment it
   * matters. `sipral_media_statistics` does not repeat it either.
   *
   * A call not using ICE never emits it, and that is most calls: the
   * policy is `SIPRAL_ICE_OFF` unless something asked otherwise.
   */
  MediaPathChosen: 33,
  /**
   * A MESSAGE arrived (RFC 3428 §7) and has already been answered:
   * 200, because this stack delivers rather than relays.
   * `payload.message` carries the body, and `account`/`call` on
   * `sipral_event_t` say where it was addressed and whether it rode
   * inside a call's dialog.
   */
  MessageReceived: 34,
  /**
   * A MESSAGE `sipral_account_message` sent reached its final answer,
   * or never will. `payload.message.status_code` is 200, a 202 from a
   * relay, a refusal, or the 408/503 this stack reports for one that
   * timed out or lost its transport.
   */
  MessageSent: 35,
  /**
   * A `message-summary` `NOTIFY` reported the state of a mailbox
   * (RFC 3842 §3.9). `payload.message` carries the counts of the
   * `voice-message` class, the one a phone's message-waiting light is
   * about.
   */
  MessagesWaiting: 36,
  /**
   * The account this call belongs to asked for an RFC 6035 voice
   * quality report and the attempt to publish it has now been made,
   * once, after `SIPRAL_EVENT_KIND_CALL_ENDED`.
   *
   * `payload.media.quality_report_sent` says whether the PUBLISH
   * left this end — not whether a collector accepted it, which this
   * stack never waits to learn. Raised only when the account named
   * a collector to publish to at all
   * (`sipral_account_config_t::quality_report_uri`); a call whose
   * account named none raises nothing here, since nothing was ever
   * attempted.
   */
  QualityReportSent: 37,
  /**
   * The call this one was joined to has ended, taking the local
   * conference of two down with it.
   *
   * `sipral_call_join` paired the two calls and neither one ever
   * called `sipral_call_leave` — the partner's own call simply ended
   * first, the same way any call does, and this is the half of that
   * this call has to be told: the pairing does not outlive either
   * side of it. `call` is the survivor; its own session is untouched
   * and carries on exactly as an unjoined call always has, on
   * whatever `sipral_media_playback`/`sipral_media_capture` it is
   * next given directly rather than through `sipral_media_mix`.
   */
  MediaUnjoined: 38,
  /**
   * A STUN server said where one of this end's sockets appears from,
   * said it has moved, or never answered (RFC 8489). Only on a stack
   * created with `SIPRAL_NAT_STUN`.
   *
   * `payload.nat` says which socket and what it came to. For a
   * signalling socket the work is already done by the time this
   * arrives: every account whose `Contact` named the socket names the
   * public address now, and each one holding a binding has sent the
   * REGISTER that says so. For a media socket
   * `sipral_stack_nat_map` named, this is the moment a call can be
   * placed, rung or answered on it — before it, that is
   * `SIPRAL_STATUS_WRONG_STATE`. A socket the server never answered
   * for is described by its own address, as it would have been with
   * no STUN at all. `account` and `call` are `SIPRAL_HANDLE_NONE`:
   * a socket is neither.
   */
  NatMapping: 39,
  /**
   * A TURN server allocated a relay for a media socket
   * `sipral_stack_nat_map` named, or gave none (RFC 8656). Only on a
   * stack created with a `turn_server`.
   *
   * `payload.relay` says which socket and what it came to. Allocated,
   * it is the moment a call can be placed, rung or answered on the
   * socket with the relay as its relayed ICE candidate — before it,
   * that is `SIPRAL_STATUS_WRONG_STATE`, as it is while the STUN
   * answer is awaited. Failed, the call goes without one. `account`
   * and `call` are `SIPRAL_HANDLE_NONE`: a socket is neither.
   */
  NatRelay: 40,
  /**
   * A REFER outside any dialog asked this end to place a call (RFC
   * 3515): click-to-dial from a switchboard, a CRM or an operator
   * console. Only on a stack created with
   * `sipral_stack_config_t::referrals` on, and only for one the same
   * screening an INVITE meets let through.
   *
   * `call` is the referral's handle: a handle of the call kind that
   * names this request rather than a call — `sipral_call_state`
   * answers `SIPRAL_STATUS_WRONG_STATE` about it, and nothing but the
   * two calls below takes it. `account` is the line it arrived for,
   * which the call it asks for is placed from; `message` is the REFER.
   * `payload.referral` says who to call, whether that is an attended
   * transfer's target, and who the sender says is asking.
   *
   * Take it with `sipral_call_accept_transfer`, which answers 202,
   * places the call exactly as it does for a transfer inside a call and
   * writes the placed call's handle; refuse it with
   * `sipral_call_reject_transfer`. Either spends the handle. **Taking
   * it is the application's decision each time**: a peer that can make
   * a phone dial can make it dial anything, and `referred_by` is what
   * the sender wrote, never proof of who it is.
   *
   * Raised a second time, with `payload.referral.status_code` set and
   * nothing else, when the application answered neither before the
   * REFER's transaction ran out: the stack answered it with that status
   * and the handle is stale from here on.
   */
  Referral: 41,
  /**
   * A media socket's connection to a TURN server reached over TCP or
   * TLS (`turn_transport`, RFC 8656 §3.1) is to be opened, or closed.
   * Only on a stack created with one.
   *
   * `payload.turn_stream` says which socket, which server, over what,
   * and which of the two. `SIPRAL_TURN_STREAM_OPEN` follows
   * `sipral_stack_nat_map`: open the connection from the socket to the
   * server — TLS with the platform's own stack, the certificate
   * checked against the server's name — and say so with
   * `sipral_stack_turn_connected`, then hand everything it carries to
   * `sipral_stack_turn_receive` for as long as it is open, and its
   * closing to `sipral_stack_turn_closed`. What is written on it comes
   * out of `sipral_stack_poll_stun`, `sipral_media_poll_transmit`,
   * `sipral_media_capture`, `sipral_media_poll_rtcp` and
   * `sipral_stack_poll_farewell`, each marked with its `protocol`.
   * `SIPRAL_TURN_STREAM_CLOSE` says nothing more will be: write what
   * is still queued for it, and close it. `account` and `call` are
   * `SIPRAL_HANDLE_NONE`: a socket is neither.
   */
  TurnStream: 42,
  /**
   * The audio engine's devices moved: a device arrived or left, the
   * system's default changed, a role was put on a device, lost the
   * one it was on, or was reopened on another. Only on a stack
   * created with `sipral_stack_config_t::audio` set to
   * `SIPRAL_AUDIO_DEVICE`.
   *
   * `payload.audio` says what changed and who changed it —
   * `SIPRAL_AUDIO_ORIGIN_SYSTEM` for the operating system,
   * `SIPRAL_AUDIO_ORIGIN_ENGINE` for this library doing what the
   * application asked or what a loss made it do — so that an
   * application can note the first and need not re-apply its own
   * choice on hearing the second. `account` and `call` are
   * `SIPRAL_HANDLE_NONE`: a device is neither.
   */
  AudioDevicesChanged: 43,
  /**
   * The network changed under this call and the address its media
   * was described at is gone: the far end is still sending its audio
   * there.
   *
   * One for every call that can still be offered a new description,
   * raised by `sipral_stack_network_changed` when it answers
   * `SIPRAL_RECOVERY_REBUILD`. Answer it by binding a media socket on
   * the new network and handing its address to
   * `sipral_call_media_readdress`, after `sipral_account_rebind`, so
   * that the re-INVITE carries the new `Contact` as well as the new
   * `c=` and port. `call` is the call; the payload is
   * `payload.call`, as for every other call event.
   */
  CallAddressWanted: 45,
  /**
   * The STUN server a stack asks changed, or every one of them failed.
   * Only on a stack created with `SIPRAL_NAT_STUN`, or given servers by
   * `sipral_stack_stun_servers`.
   *
   * `payload.stun_server` says which:
   * `SIPRAL_STUN_SERVER_STATE_CHANGED` when the server in use moved --
   * the one before it failed, one earlier in the list answered again,
   * or the list was replaced -- and
   * `SIPRAL_STUN_SERVER_STATE_ALL_FAILED` when every server in
   * `stun_server` and `stun_fallbacks` has failed and none is left to
   * turn to. A server fails when it does not answer in five and a half
   * seconds, or answers without an address, and is then passed over
   * for thirty seconds, twice as long each time it fails again, up to
   * ten minutes. Nothing is asked of the application: the sockets move
   * to the next server by themselves, and
   * `SIPRAL_EVENT_KIND_NAT_MAPPING` says what each one learns there.
   * `account` and `call` are `SIPRAL_HANDLE_NONE`: a server is
   * neither.
   */
  StunServer: 46,
  /**
   * Who is calling, as a signature says (RFC 8224, RFC 8588): the
   * stack's verification service at work on an INVITE for an account
   * that verifies its callers. ABI 0.31.
   *
   * `payload.verification.stage` says which half.
   * `SIPRAL_VERIFICATION_STAGE_CERTIFICATE_WANTED`: the certificate at
   * `certificate_url` is needed; fetch it and hand it to
   * `sipral_call_stir_certificate`, or hand over nothing if it cannot
   * be had. The call waits, and the application has not been told of
   * it yet — `call` names it all the same, for the answer.
   * `SIPRAL_VERIFICATION_STAGE_VERIFIED`: the verdict, queued just
   * before the `SIPRAL_EVENT_KIND_INCOMING_CALL` naming the same call,
   * whose call events carry it too; or, with `refused` set, before the
   * `SIPRAL_EVENT_KIND_CALL_ENDED` of a call its strict account
   * refused with `response_code`. `message` is the INVITE.
   */
  CallerVerification: 47,
  /**
   * A keypad digit heard in the far end's audio, as the two tones
   * themselves, on a call listening for them:
   * `sipral_stack_config_t::dtmf_detection` and
   * `sipral_call_dtmf_detection` say when. One per press, reported as
   * it ends; on a call that also negotiated named events, a press the
   * far end sent both ways is reported once, as
   * `SIPRAL_EVENT_KIND_DIGIT_RECEIVED`, and one heard only in the audio
   * waits a quarter of a second before it is reported here.
   *
   * `payload.media` carries it the way it carries every digit:
   * `digit` is the key's character, `event_code` its RFC 4733 code,
   * `held_ms` how long it sounded and `source`
   * `SIPRAL_DIGIT_SOURCE_IN_BAND`.
   */
  InBandDigit: 48,
  /**
   * What was heard on a call told to listen with
   * `sipral_call_detect_progress`: a call-progress tone of its network
   * on early media, the special information tone, who answered, or
   * the beep an answering machine plays before it records.
   * `payload.progress` says which, and what was measured.
   */
  ProgressDetected: 49,
  /**
   * A `conference` subscription's picture of the conference changed,
   * or the conference ended (RFC 4575 §4.6).
   *
   * `payload.conference` says which subscription and what happened:
   * `SIPRAL_CONFERENCE_UPDATE_APPLIED` for a document merged into the
   * picture, with the version it is at and how many users it holds,
   * and `SIPRAL_CONFERENCE_UPDATE_ENDED` for a conference the focus
   * deleted, after which the subscription is being given up. The
   * picture itself is read with `sipral_subscription_conference` and
   * `sipral_subscription_conference_user_at`. A document that was late
   * or repeated raises nothing, and one that followed a lost one is
   * answered by the stack asking for full state again. `account` and
   * `call` are `SIPRAL_HANDLE_NONE`; the NOTIFY itself arrived just
   * before, as `SIPRAL_EVENT_KIND_NOTIFIED`.
   */
  ConferenceChanged: 50,
  /**
   * The far end typed something on the call's real-time text stream
   * (RFC 4103), in the order it typed it.
   *
   * `call` is the call; `payload.text` holds the text, UTF-8: an
   * erasure of the last character as BACKSPACE (U+0008), a new line
   * as LINE SEPARATOR (U+2028), an alert as BELL (U+0007), and a
   * REPLACEMENT CHARACTER (U+FFFD) for each block of text that was
   * lost and no redundant copy recovered (RFC 4103 §5.3), counted in
   * `payload.text.missing`.
   */
  TextReceived: 51,
  /**
   * Presence moved: a `presence` subscription was told about the
   * presentity (RFC 3856), or the state this account publishes (RFC
   * 3903) was published, refreshed, removed, lapsed or refused.
   *
   * `payload.presence.kind` says which. For a subscription,
   * `payload.presence.subscription` names it and the rest is what the
   * PIDF document said: open or closed, the first RPID activity, the
   * first note and the entity; the NOTIFY itself arrived just before,
   * as `SIPRAL_EVENT_KIND_NOTIFIED`. For a publication, `account`
   * names the account and
   * `payload.presence.publication_state` says what became of it, with
   * the SIP status, the lifetime the compositor granted and when the
   * stack refreshes it.
   */
  PresenceChanged: 52,
  /**
   * A transport this stack signals on stopped carrying traffic: the
   * application said it failed (`sipral_stack_transport_failed`,
   * `sipral_stack_transport_failed_with`) or closed
   * (`sipral_stack_stream_closed`), or a stream carried bytes no
   * message starts with (`sipral_stack_receive_stream`), or a stream
   * that had answered a keep-alive ping left the next one unanswered
   * for ten seconds (RFC 5626 §4.4.1, `SIPRAL_TRANSPORT_ERROR_TIMED_OUT`:
   * the stack has let the connection go, and the socket is the
   * application's to close).
   *
   * Raised by the next poll, before what the loss did to the
   * registrations and calls on it. `payload.transport_failed` says
   * which transport, what it spoke, what went wrong and — when TLS
   * refused the connection — why, as the application's TLS library
   * said it: untrusted, a name that does not match, expired, or a
   * handshake refused, with the library's own sentence beside it.
   * Nothing is sent on the transport until
   * `sipral_stack_transport_bind` brings it back; a request asked for
   * meanwhile is `SIPRAL_STATUS_TRANSPORT_DOWN`. `account` and `call`
   * are `SIPRAL_HANDLE_NONE`: a transport is neither.
   */
  TransportFailed: 53,
  /**
   * A local conference changed (ABI 0.32): a member joined or left, who
   * is talking changed, or its recording stopped by itself.
   *
   * `payload.local_conference` says which conference and what
   * happened: `member` is the call that joined or left — or the
   * conference's own handle for this end — `departure` why it left,
   * and `members`, `talkers` and `loudest` how the conference stands
   * now. The talkers themselves are read with
   * `sipral_local_conference_talker_at`. `account` and `call` are
   * `SIPRAL_HANDLE_NONE`: a conference is neither.
   */
  LocalConferenceChanged: 54,
  /**
   * A DNS lookup is wanted to locate an account's server by RFC 3263
   * (ABI 0.34): the account named its registrar or its outbound proxy
   * with `server_uri` rather than an address.
   *
   * `payload.locate` names the query: `name`, and `record`, what to
   * ask it for. Ask the platform's resolver and hand the answer to
   * `sipral_account_looked_up` — every one, a failure included, since
   * the procedure waits for each. Several may be outstanding at once,
   * one per host an SRV answer named. `account` is the account.
   */
  LookupWanted: 55,
  /**
   * An account's server was located, or located again once the last
   * answer's time-to-live ran out (ABI 0.34): `payload.locate.targets`
   * is every address the answer named, first the one the account's
   * requests go to now. `account` is the account.
   */
  Located: 56,
  /**
   * A lookup of an account's server named no address (ABI 0.34):
   * `payload.locate.failure` says why, and `retry_in_ms` when the name
   * is looked up again. A REGISTER that was waiting for it is reported
   * failed as well, and backs off; an address an earlier answer named
   * stays in use meanwhile. `account` is the account.
   */
  LocateFailed: 57,
  /**
   * A request of an account's was challenged by somebody its
   * password is not for, and the challenge was not answered (ABI
   * 0.36): RFC 3261 §22.1 gives each protection domain its own
   * password, and every answer is material for an offline search of
   * it by whoever chose the nonce.
   *
   * `payload.challenge` says why — `refusal` — and who asked:
   * `server`, where the challenged request went, and `realms`, what
   * it was challenged for. Raised before the refusal settles the way
   * any unanswered challenge does — a call ending with the 401 or
   * 407, a registration failing with `BAD_CREDENTIALS`, a request
   * inside a call refused — so the application knows why first. A
   * server that answers under a realm the account was never told of
   * is what `sipral_account_config_t::realms` is for. `account` is
   * the account.
   */
  ChallengeDeclined: 58,
  /**
   * An account's own server takes an OAuth 2.0 access token (RFC
   * 8898) and the account has none it would accept: none was
   * supplied, or the one supplied was refused — expired or revoked,
   * which `error` says as `SIPRAL_TOKEN_ERROR_INVALID_TOKEN` (ABI 1.2).
   *
   * `payload.token` says where a token comes from: `authz_server`, an
   * `https` URI RFC 8898 §2.1.1 says to check against the
   * authorization servers the application trusts before going near
   * it, and `scope`, what the token has to cover. Fetching it is the
   * application's; hand it over with `sipral_account_set_access_token`.
   * The refusal settles meanwhile the way an unanswered challenge does
   * — a registration failing with `BAD_CREDENTIALS`, a call ending
   * with the 401 or 407 — and `sipral_account_register` registers
   * again at once with the new token. `account` is the account.
   */
  TokenRequired: 59,
  /**
   * A network test `sipral_stack_network_test` started has every
   * answer it is going to get (ABI 1.2). `payload.network_test` holds
   * each part and the verdict; `account` is the account whose server
   * was probed and `call` the echo call, when the test had them.
   */
  NetworkTest: 60,
} as const);
koffi.alias('sipral_event_kind_t', 'uint32_t');

/**
 * Where a registration is. Names for `sipral_registration_event_t::state`.
 */
export const SipralRegistrationState = Object.freeze({
  /**
   * The account is gone, or has never been asked about.
   */
  Unknown: 0,
  /**
   * Configured and not registered. Nothing has been sent.
   */
  Idle: 1,
  /**
   * A REGISTER is in flight and there is no binding yet.
   */
  Registering: 2,
  /**
   * The registrar holds a binding.
   */
  Registered: 3,
  /**
   * A refresh is in flight. The binding stands until it is answered.
   */
  Refreshing: 4,
  /**
   * Something recoverable went wrong and the next attempt is scheduled.
   */
  Retrying: 5,
  /**
   * The binding was given up on purpose.
   */
  Unregistered: 6,
  /**
   * The registrar refused in a way that trying again cannot fix.
   */
  Failed: 7,
  /**
   * A binding a registrar really granted, over a transport that has since
   * been suspended or lost, which nothing has proved since.
   *
   * Not registered, because it is no longer evidence; not failed, because
   * nothing refused it. A monotonic clock does not advance while a machine
   * sleeps, so a stack that slept eight hours comes back believing eight
   * milliseconds passed and every binding still valid — this is the state
   * that says otherwise, and an application that shows a line as ready on
   * the strength of it will show it ready when it is not.
   */
  Unverified: 8,
  /**
   * A binding read back from a snapshot rather than granted in this
   * process. It has not been proved either.
   */
  Restored: 9,
  /**
   * The account was configured with no registrar and never registers:
   * a trunk that knows this end by its address. It starts here and
   * stays here, and `sipral_account_register` refuses it. Not idle,
   * which is one `sipral_account_register` away from a binding.
   */
  NotRegistering: 10,
} as const);
koffi.alias('sipral_registration_state_t', 'uint32_t');

/**
 * Why a registration is not live. Names for
 * `sipral_registration_event_t::failure`.
 */
export const SipralRegistrationFailure = Object.freeze({
  /**
   * Nothing failed.
   */
  None: 0,
  /**
   * The registrar refused, and will refuse the same request again.
   */
  Rejected: 1,
  /**
   * The password was wrong, or there was none to answer with.
   */
  BadCredentials: 2,
  /**
   * The registrar is not answering, or says it cannot serve this now.
   */
  Unreachable: 3,
  /**
   * The registrar moved. Following it needs an address, which is the
   * caller's to resolve.
   */
  Redirected: 4,
  /**
   * The account's `Contact` names an address the registrar cannot
   * reach this end at — loopback, to a registrar that is not, or the
   * unspecified address — and nothing was sent (ABI 0.34). Trying
   * again cannot help until the account is given one it can:
   * `sipral_account_rebind`, with an address `sipral_advertised_address`
   * found.
   */
  UnreachableContact: 5,
} as const);
koffi.alias('sipral_registration_failure_t', 'uint32_t');

/**
 * Where a call is. Names for `sipral_call_event_t::state`, and what
 * `sipral_call_state` writes.
 */
export const SipralCallState = Object.freeze({
  /**
   * The call is gone, or has never been asked about.
   */
  Unknown: 0,
  /**
   * The INVITE has gone and nothing has come back.
   */
  Calling: 1,
  /**
   * Somebody is calling and this end has not answered.
   */
  Incoming: 2,
  /**
   * The far end is ringing, or this end said it is.
   */
  Ringing: 3,
  /**
   * There is audio before anybody answered.
   */
  EarlyMedia: 4,
  /**
   * Up.
   */
  Confirmed: 5,
  /**
   * Up, in order to be transferred: the second leg of an attended transfer.
   */
  Consulting: 6,
  /**
   * A CANCEL or a BYE has gone and is not answered yet.
   */
  Terminating: 7,
  /**
   * Over.
   */
  Terminated: 8,
} as const);
koffi.alias('sipral_call_state_t', 'uint32_t');

/**
 * Why a call is over. Names for `sipral_call_event_t::end_reason`.
 */
export const SipralCallEndReason = Object.freeze({
  /**
   * The call is not over.
   */
  None: 0,
  /**
   * This end hung up.
   */
  LocalHangup: 1,
  /**
   * The far end hung up.
   */
  RemoteHangup: 2,
  /**
   * The far end refused it: busy, declined, not found.
   */
  Refused: 3,
  /**
   * Given up before it was answered, from either end.
   */
  Cancelled: 4,
  /**
   * Nothing came back, or the transport died.
   */
  Unreachable: 5,
  /**
   * Another branch of the same fork was kept and this one was not.
   */
  ForkLost: 6,
  /**
   * The branch was still ringing when the answer window closed.
   */
  Abandoned: 7,
  /**
   * The session timer ran out and no refresh arrived.
   */
  Expired: 8,
} as const);
koffi.alias('sipral_call_end_reason_t', 'uint32_t');

/**
 * Which of the ways this stack accepts a digit reported the one
 * SIPRAL_EVENT_KIND_DIGIT_RECEIVED or SIPRAL_EVENT_KIND_IN_BAND_DIGIT
 * carries. Names for `sipral_media_event_t::source`.
 */
export const SipralDigitSource = Object.freeze({
  /**
   * RFC 4733: a named telephone event in the RTP stream.
   */
  Rtp: 0,
  /**
   * RFC 3261's INFO method (RFC 6086), carrying `application/dtmf-relay`
   * or `application/dtmf`.
   */
  Info: 1,
  /**
   * The two tones themselves, heard in the far end's audio, for
   * SIPRAL_EVENT_KIND_IN_BAND_DIGIT.
   */
  InBand: 2,
} as const);
koffi.alias('sipral_digit_source_t', 'uint32_t');

/**
 * What a SIPRAL_EVENT_KIND_RECOVERY reports happened, for
 * `payload.recovery.state`: the two ways a recovery settles — a
 * registrar answered again, or the ladder ran out of rungs.
 */
export const SipralRecoveryOutcome = Object.freeze({
  /**
   * Never written by this build.
   */
  Unknown: 0,
  /**
   * A registrar answered again: what was distrusted is proved.
   */
  Running: 1,
  /**
   * Every rung was climbed and none of them worked.
   */
  GaveUp: 2,
} as const);
koffi.alias('sipral_recovery_outcome_t', 'uint32_t');

/**
 * The last rung a recovery ladder tried before it gave up, for
 * SIPRAL_EVENT_KIND_RECOVERY's `payload.recovery.rung`. Meaningful
 * only when `payload.recovery.state` is
 * SIPRAL_RECOVERY_OUTCOME_GAVE_UP. The ladder's own last step, giving
 * up, has no name here: what is reported is the rung before it that
 * asked for something and went unanswered.
 */
export const SipralRecoveryRung = Object.freeze({
  /**
   * The ladder did not give up.
   */
  None: 0,
  /**
   * Nothing was believed any more, and nothing was sent.
   */
  Distrust: 1,
  /**
   * A REGISTER, and a re-SUBSCRIBE for what was demoted alongside it,
   * went out or could not.
   */
  Reregister: 2,
  /**
   * The application was asked for a transport.
   */
  WantTransport: 3,
  /**
   * The application was asked for an address.
   */
  WantAddress: 4,
} as const);
koffi.alias('sipral_recovery_rung_t', 'uint32_t');

/**
 * Why a recovery ladder gave up, for SIPRAL_EVENT_KIND_RECOVERY's
 * `payload.recovery.reason`.
 */
export const SipralRecoveryFailure = Object.freeze({
  /**
   * The ladder did not give up.
   */
  None: 0,
  /**
   * Every REGISTER that could be sent was sent and none of them was
   * answered.
   */
  Unreachable: 1,
  /**
   * A transport was asked for and the application did not bind one.
   */
  NoTransport: 2,
  /**
   * An address was asked for and the application did not supply one.
   */
  Unresolved: 3,
} as const);
koffi.alias('sipral_recovery_failure_t', 'uint32_t');

/**
 * What kind of link the application is on. Names for `from_link` and
 * `to_link` on sipral_stack_network_changed.
 *
 * Coarse on purpose: nothing here changes what is sent, and the one
 * value that changes what is *done* is SIPRAL_LINK_DOWN. The rest is
 * carried so that a change of kind over an unchanged address — a tunnel
 * coming up, a phone moving from Wi-Fi to a mobile network that kept the
 * address — is visible as a change at all.
 */
export const SipralLink = Object.freeze({
  /**
   * There is no usable interface.
   */
  Down: 0,
  /**
   * Cable.
   */
  Wired: 1,
  /**
   * Wireless local network.
   */
  Wifi: 2,
  /**
   * A mobile network.
   */
  Cellular: 3,
  /**
   * A tunnel over one of the others.
   */
  Tunnel: 4,
} as const);
koffi.alias('sipral_link_t', 'uint32_t');

/**
 * What a change of network is worth doing about. Names for
 * sipral_stack_network_changed's `out_recovery`.
 *
 * Returned from the call itself, so an application does not have to read
 * an event to find out whether anything happened: a laptop that flips
 * between two access points all day gets SIPRAL_RECOVERY_NOTHING
 * every time and never sends a REGISTER over it.
 */
export const SipralRecovery = Object.freeze({
  /**
   * Never written by this build.
   */
  Unknown: 0,
  /**
   * Nothing this stack uses is different. Nothing is done and nothing
   * is sent.
   */
  Nothing: 1,
  /**
   * The address still stands, so the transports do. What is upstream
   * of it may not.
   */
  Reregister: 2,
  /**
   * A wake: the transport already there is used first, and a new one
   * is asked for only once it turns out to be dead. Never returned by
   * this entry point; it is what sipral_stack_resumed starts.
   */
  Reprove: 3,
  /**
   * The address is gone. Everything bound to it is unusable and the
   * application has to open a transport again.
   */
  Rebuild: 4,
  /**
   * Packets can leave and names cannot be turned into addresses.
   */
  Resolve: 5,
  /**
   * There is no interface. Nothing is tried until there is one.
   */
  Detach: 6,
} as const);
koffi.alias('sipral_recovery_t', 'uint32_t');

/**
 * What a stack does about a NAT in front of it. Names for
 * `sipral_stack_config_t::nat`.
 *
 * Zero is not one of them: it means this build's own built-in default,
 * which is SIPRAL_NAT_OFF. `docs/06-nat.md` says why that is the
 * default and what `rport` and symmetric RTP already carry without it.
 */
export const SipralNat = Object.freeze({
  /**
   * Ask nobody. Every address this stack writes is the one the
   * application gave it.
   */
  Off: 1,
  /**
   * Ask the STUN server `sipral_stack_config_t::stun_server` names
   * where each socket appears from, and write that instead: the
   * signalling socket's in the `Contact`, a media socket's in `c=` and
   * `m=`.
   *
   * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
   * `SIPRAL_FEATURE_STUN`.
   */
  Stun: 2,
} as const);
koffi.alias('sipral_nat_t', 'uint32_t');

/**
 * What a socket's mapping came to. Names for
 * `sipral_nat_event_t::mapping`.
 */
export const SipralNatMapping = Object.freeze({
  /**
   * The first answer: the socket appears at `public`.
   */
  Learned: 1,
  /**
   * A later answer named another address: the NAT let the mapping go
   * and made a new one, or the network under the socket changed.
   * `previous` is what it was. About a signalling socket, or a media
   * socket still waiting for its call.
   */
  Moved: 2,
  /**
   * The server did not answer, in five and a half seconds, or refused.
   * The socket is described by its own address, exactly as it would
   * have been with `SIPRAL_NAT_OFF`; a signalling socket asks again at
   * its next refresh.
   */
  Unanswered: 3,
} as const);
koffi.alias('sipral_nat_mapping_t', 'uint32_t');

/**
 * What a media socket's relay came to. Names for
 * `sipral_nat_relay_event_t::outcome`.
 */
export const SipralNatRelay = Object.freeze({
  /**
   * The TURN server allocated a relay for the socket: `relayed` is
   * the address it relays from. A call placed, rung or answered on
   * the socket from now on offers it as its relayed ICE candidate.
   */
  Allocated: 1,
  /**
   * There is no relay for the socket: the server refused (`code` says
   * with what), did not answer in thirty-nine and a half seconds, or
   * took back an allocation it had made. A call on the socket goes
   * without one, and ICE finds what path it can on the rest.
   */
  Failed: 2,
} as const);
koffi.alias('sipral_nat_relay_t', 'uint32_t');

/**
 * What a media socket's connection to the TURN server is to do. Names
 * for `sipral_turn_stream_event_t::state`.
 */
export const SipralTurnStream = Object.freeze({
  /**
   * Open a connection from the media socket `local` to the TURN
   * server at `server`, over `protocol` — TCP, or TLS with the
   * server's certificate checked by the platform's own stack — and
   * say so with `sipral_stack_turn_connected` once it is open, or
   * `sipral_stack_turn_closed` if it cannot be. The socket's relay is
   * allocated over it; a call on the socket before that answers
   * `SIPRAL_STATUS_WRONG_STATE`.
   */
  Open: 1,
  /**
   * Nothing more will be written for the connection from `local`:
   * its relay was given back or lost, or the call it carried has
   * ended. Write what the queues still hold for it —
   * `sipral_stack_poll_farewell` and `sipral_stack_poll_stun` — and
   * close it.
   */
  Close: 2,
} as const);
koffi.alias('sipral_turn_stream_t', 'uint32_t');

/**
 * What happened to the STUN servers a stack asks. Names for
 * `sipral_stun_server_event_t::state`.
 */
export const SipralStunServerState = Object.freeze({
  /**
   * The server in use is another one now: `previous` failed and
   * `server`, the next in the list, took over; a refresh found
   * `server`, earlier in the list, answering again; or
   * `sipral_stack_stun_servers` named another list.
   */
  Changed: 1,
  /**
   * Every server in the list has failed and each is backing off:
   * `server` is the last one that did. The sockets keep what they
   * learned, or are described by their own address, and a
   * signalling socket's refresh goes on asking. Said once until a
   * server answers again.
   */
  AllFailed: 2,
} as const);
koffi.alias('sipral_stun_server_state_t', 'uint32_t');

/**
 * Where a subscription is. Names for
 * `sipral_subscription_event_t::state` and for
 * sipral_subscription_state's `out_state`.
 */
export const SipralSubscriptionState = Object.freeze({
  /**
   * The handle names nothing: never minted here, or ended and let go.
   */
  Unknown: 0,
  /**
   * A SUBSCRIBE is on its way and nothing has answered it yet.
   */
  Requesting: 1,
  /**
   * The notifier has it and has not decided. RFC 6665 §4.1.3's
   * `pending` is "insufficient policy information to grant or deny the
   * subscription yet", and nothing is known about the watched thing
   * until this becomes SIPRAL_SUBSCRIPTION_STATE_ACTIVE.
   */
  Pending: 2,
  /**
   * Granted, and notifications are arriving.
   */
  Active: 3,
  /**
   * Not live, and a fresh attempt is scheduled. The handle stays
   * valid: §4.1.2.2's new attempt is "an unrelated initial SUBSCRIBE
   * request with a freshly generated Call-ID and a new, unique From
   * tag", and this ABI keeps one name over both of them.
   */
  Retrying: 4,
  /**
   * Over, with nothing more coming. The handle names nothing from
   * here on.
   */
  Ended: 5,
} as const);
koffi.alias('sipral_subscription_state_t', 'uint32_t');

/**
 * Why a subscription is not live. Names for
 * `sipral_subscription_event_t::reason`.
 *
 * Zero unless the state is SIPRAL_SUBSCRIPTION_STATE_RETRYING or
 * SIPRAL_SUBSCRIPTION_STATE_ENDED. The first nine are what a
 * `Subscription-State: terminated` said in its `reason` parameter (RFC
 * 6665 §4.1.3), and the rest are what happened here instead.
 */
export const SipralSubscriptionEnd = Object.freeze({
  /**
   * Never written by this build.
   */
  Unknown: 0,
  /**
   * `deactivated`: the notifier wants this subscription started again
   * at once.
   */
  Deactivated: 1,
  /**
   * `probation`: started again, but not immediately.
   */
  Probation: 2,
  /**
   * `rejected`: the notifier will not serve it, and asking again is
   * pointless.
   */
  Rejected: 3,
  /**
   * `timeout`: it ran out rather than being refreshed.
   */
  Timeout: 4,
  /**
   * `giveup`: the notifier could not decide and stopped trying.
   */
  GaveUp: 5,
  /**
   * `noresource`: what was being watched does not exist any more.
   */
  NoResource: 6,
  /**
   * `invariant`: the watched thing cannot change, so there is nothing
   * to notify about.
   */
  Invariant: 7,
  /**
   * `terminated` with no reason parameter at all.
   */
  Unstated: 8,
  /**
   * This end gave it up: sipral_subscription_end. It wins over
   * whatever the notifier's closing notification said its own reason
   * was, because the application asked for this one to stop and that
   * is the answer to why it is not live.
   */
  Unsubscribed: 9,
  /**
   * The notifier answered 489: it does not know this event package.
   */
  BadEvent: 10,
  /**
   * The notifier refused the SUBSCRIBE with a status trying again
   * cannot fix.
   */
  Refused: 11,
  /**
   * The SUBSCRIBE was redirected, and following a redirect for one is
   * not something this stack does by itself.
   */
  Redirected: 12,
  /**
   * Nothing answered: the notifier could not be reached at all.
   */
  Unreachable: 13,
  /**
   * The SUBSCRIBE was answered and the first NOTIFY never arrived
   * (§4.1.2.4's timer N, 64·T1).
   */
  NoNotify: 14,
  /**
   * What the notifier granted ran out with no refresh answered.
   */
  Expired: 15,
} as const);
koffi.alias('sipral_subscription_end_t', 'uint32_t');

/**
 * What one watched dialog is doing, and what a lamp is lit from. Names
 * for `sipral_watched_dialog_t::phase` and for
 * sipral_subscription_lamp's `out_phase`.
 *
 * RFC 4235 §3.7.1's states, with the order they rank in for a lamp:
 * anything ringing beats anything settled, which is §3.7.2's virtual
 * state machine over every dialog of one resource.
 */
export const SipralDialogPhase = Object.freeze({
  /**
   * Nothing is going on: no dialog, or every one of them terminated.
   * This is what an idle lamp shows.
   */
  Idle: 0,
  /**
   * A request went out and nothing has answered.
   */
  Trying: 1,
  /**
   * Something answered without ringing yet.
   */
  Proceeding: 2,
  /**
   * Ringing.
   */
  Early: 3,
  /**
   * A call is up.
   */
  Confirmed: 4,
  /**
   * This dialog is over. Never sipral_subscription_lamp's answer,
   * which is SIPRAL_DIALOG_PHASE_IDLE when every dialog has ended.
   */
  Terminated: 5,
  /**
   * The notifier named a state this build has no number for.
   */
  Unknown: 6,
} as const);
koffi.alias('sipral_dialog_phase_t', 'uint32_t');

/**
 * Which end started a watched dialog. Names for
 * `sipral_watched_dialog_t::direction`.
 */
export const SipralDialogDirection = Object.freeze({
  /**
   * The notifier did not say.
   */
  Unknown: 0,
  /**
   * The watched end placed the call.
   */
  Locally: 1,
  /**
   * The watched end was called.
   */
  Remotely: 2,
} as const);
koffi.alias('sipral_dialog_direction_t', 'uint32_t');

/**
 * How a watched dialog ended. Names for
 * `sipral_watched_dialog_t::ended`, and zero while it has not.
 */
export const SipralDialogEnded = Object.freeze({
  /**
   * It has not ended, or the notifier did not say how.
   */
  Unknown: 0,
  /**
   * The caller gave up before it was answered.
   */
  Cancelled: 1,
  /**
   * The called end refused it.
   */
  Rejected: 2,
  /**
   * A `Replaces` took it over.
   */
  Replaced: 3,
  /**
   * The watched end hung up.
   */
  LocalBye: 4,
  /**
   * The far end hung up.
   */
  RemoteBye: 5,
  /**
   * Something went wrong with it.
   */
  Error: 6,
  /**
   * Nothing answered in time.
   */
  Timeout: 7,
} as const);
koffi.alias('sipral_dialog_ended_t', 'uint32_t');

/**
 * Which piece of text sipral_subscription_dialog_text is being asked
 * for.
 *
 * Every one of them is what the notifier wrote, unparsed: a display name
 * is whatever it put there, and an identity is a URI in the form it sent
 * it in.
 */
export const SipralDialogText = Object.freeze({
  /**
   * Never asked for.
   */
  Unknown: 0,
  /**
   * The notifier's own name for this dialog, which is what it will
   * keep using for it.
   */
  Id: 1,
  /**
   * The dialog's `Call-ID`, when the notifier sent one.
   */
  CallId: 2,
  /**
   * Who the watched end is, as a URI.
   */
  LocalIdentity: 3,
  /**
   * And the display name beside it.
   */
  LocalDisplay: 4,
  /**
   * Who the other end is, as a URI. This is the one a lamp shows
   * beside a ringing extension.
   */
  RemoteIdentity: 5,
  /**
   * And the display name beside it.
   */
  RemoteDisplay: 6,
  /**
   * Where requests for the watched end would be sent.
   */
  LocalTarget: 7,
  /**
   * And for the other end.
   */
  RemoteTarget: 8,
} as const);
koffi.alias('sipral_dialog_text_t', 'uint32_t');

/**
 * Who pumps a stack's audio: `sipral_stack_config_t::audio`.
 *
 * Zero is application mode because zero is what a configuration
 * written against any earlier header says, and a caller that pumps its
 * own frames must go on pumping them when the library underneath it is
 * updated. The idiomatic layers each choose their own default.
 */
export const SipralAudio = Object.freeze({
  /**
   * The application opens the devices and pumps the frames through
   * `sipral_media_capture` and `sipral_media_playback`. What every
   * stack was before device mode existed.
   */
  Application: 0,
  /**
   * The library opens the platform's devices and pumps every
   * managed call itself; the packets it encodes reach the
   * application's socket through `audio_transmit_callback`.
   * `SIPRAL_STATUS_NOT_SUPPORTED` on a platform this build has no
   * backend for, which `SIPRAL_FEATURE_AUDIO_DEVICE` says first.
   */
  Device: 1,
} as const);
koffi.alias('sipral_audio_t', 'uint32_t');

/**
 * When the devices are opened, in device mode:
 * `sipral_stack_config_t::audio_activation`.
 */
export const SipralAudioActivation = Object.freeze({
  /**
   * With the first managed call's media, or the first ring; closed
   * with the last. What a desktop softphone wants.
   */
  Automatic: 0,
  /**
   * Only between `sipral_audio_activate` and `sipral_audio_deactivate`,
   * whatever the calls do. What CallKit and the telecom framework
   * want: they say when the audio session is this application's,
   * and a device opened before they do is a device that does not work.
   */
  Manual: 1,
} as const);
koffi.alias('sipral_audio_activation_t', 'uint32_t');

/**
 * What a device is used for.
 */
export const SipralAudioRole = Object.freeze({
  /**
   * The call's microphone.
   */
  Microphone: 1,
  /**
   * The call's loudspeaker or earpiece.
   */
  Speaker: 2,
  /**
   * Where an incoming call is announced, which need not be where it
   * is answered: the room's speaker for the ring, the headset for
   * the call.
   */
  Ringer: 3,
} as const);
koffi.alias('sipral_audio_role_t', 'uint32_t');

/**
 * Which way audio flows, for gain, mute and the meter.
 */
export const SipralAudioDirection = Object.freeze({
  /**
   * From the microphone. Its gain is the microphone gain.
   */
  Input: 1,
  /**
   * To the loudspeaker. Its gain is the volume.
   */
  Output: 2,
} as const);
koffi.alias('sipral_audio_direction_t', 'uint32_t');

/**
 * What changed, on `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`.
 */
export const SipralAudioChange = Object.freeze({
  /**
   * A device arrived or left; the list has been refreshed, and
   * `sipral_audio_device_at` reads the new one. Every id that was
   * valid still is: a device that left keeps its row, marked absent.
   */
  ListChanged: 1,
  /**
   * The system's default for `direction` moved. A role the
   * application put on a device stays there; one on the system's
   * route follows, and says so with `SIPRAL_AUDIO_CHANGE_REOPENED`.
   */
  DefaultChanged: 2,
  /**
   * `role` is on `device` because `sipral_audio_select` said so.
   */
  Selected: 3,
  /**
   * The device `role` was running on went away. The engine reopens
   * the role on its fallback and reports that separately.
   */
  Lost: 4,
  /**
   * `role` is running on `device` again.
   */
  Reopened: 5,
  /**
   * `role` could not be opened on anything; that direction is
   * silence until a device arrives.
   */
  Unavailable: 6,
} as const);
koffi.alias('sipral_audio_change_t', 'uint32_t');

/**
 * Who made a change: the operating system, or this library doing what
 * the application asked or what a loss made it do. An application
 * notes the first and acts on neither by re-applying its own choice.
 */
export const SipralAudioOrigin = Object.freeze({
  /**
   * The operating system, or a person at a socket.
   */
  System: 1,
  /**
   * The engine.
   */
  Engine: 2,
} as const);
koffi.alias('sipral_audio_origin_t', 'uint32_t');

/**
 * The verdict a terminating network reached on the caller's number
 * (3GPP TS 24.229's `verstat`, the mark STIR/SHAKEN leaves). Names for
 * `sipral_call_event_t::verstat`.
 */
export const SipralVerstat = Object.freeze({
  /**
   * Nothing said, or said by a peer the account does not trust.
   */
  None: 0,
  /**
   * `TN-Validation-Passed`.
   */
  Passed: 1,
  /**
   * `TN-Validation-Failed`.
   */
  Failed: 2,
  /**
   * `No-TN-Validation`.
   */
  NotValidated: 3,
  /**
   * Some other value.
   */
  Other: 4,
} as const);
koffi.alias('sipral_verstat_t', 'uint32_t');

/**
 * `Answer-Mode` and `Priv-Answer-Mode` (RFC 5373 §3). Names for
 * `sipral_call_event_t::answer_mode` and `priv_answer_mode`.
 */
export const SipralAnswerMode = Object.freeze({
  /**
   * The INVITE carried no such field.
   */
  None: 0,
  /**
   * `Manual`: wait for the user.
   */
  Manual: 1,
  /**
   * `Auto`: answer without waiting for the user.
   */
  Auto: 2,
  /**
   * Any other value, which RFC 5373 has ignored.
   */
  Other: 3,
} as const);
koffi.alias('sipral_answer_mode_t', 'uint32_t');

/**
 * Where the ring says the caller is. Names for
 * `sipral_call_event_t::ring_source`.
 */
export const SipralRingSource = Object.freeze({
  /**
   * Nothing said.
   */
  Unknown: 0,
  /**
   * Another extension of the same switch.
   */
  Internal: 1,
  /**
   * The outside world.
   */
  External: 2,
} as const);
koffi.alias('sipral_ring_source_t', 'uint32_t');

/**
 * Which list, and which piece of each entry, sipral_call_identity_count
 * and sipral_call_identity_text are asked about.
 */
export const SipralIdentityText = Object.freeze({
  /**
   * Never asked for.
   */
  Unknown: 0,
  /**
   * `P-Asserted-Identity`: the URI of each asserted party.
   */
  Asserted: 1,
  /**
   * And each one's display name.
   */
  AssertedDisplay: 2,
  /**
   * `Remote-Party-ID`: the URI of each party named.
   */
  RemoteParty: 3,
  /**
   * And each one's display name.
   */
  RemotePartyDisplay: 4,
  /**
   * `Diversion`, most recent first: who the call was diverted from.
   */
  Diversion: 5,
  /**
   * And the display name beside it.
   */
  DiversionDisplay: 6,
  /**
   * And why: `no-answer`, `user-busy`, `unconditional` and the rest.
   */
  DiversionReason: 7,
  /**
   * `History-Info`: the URI of each target the request was sent to.
   */
  History: 8,
  /**
   * And each entry's `index`.
   */
  HistoryIndex: 9,
  /**
   * Every `Alert-Info` URI.
   */
  AlertInfo: 10,
  /**
   * Every `info=` value on `Alert-Info`.
   */
  AlertName: 11,
  /**
   * The calling number this stack's verification found a valid
   * PASSporT signed for (RFC 8224 §6.2), canonical: one entry, or none
   * when nothing verified. ABI 0.31.
   */
  VerifiedOrig: 12,
  /**
   * Its origination identifier (RFC 8588 §5), a UUID.
   */
  VerifiedOrigid: 13,
  /**
   * The URL of the certificate it was verified against, or that could
   * not be had.
   */
  VerificationCertificate: 14,
  /**
   * Why it did not verify, in words, for a log.
   */
  VerificationDetail: 15,
} as const);
koffi.alias('sipral_identity_text_t', 'uint32_t');

/**
 * How an account's calls ask for a session timer (RFC 4028). Names for
 * `sipral_account_config_t::session_timer`.
 */
export const SipralSessionTimer = Object.freeze({
  /**
   * The stack's default: thirty minutes, RFC 4028 §4's recommendation.
   */
  Default: 0,
  /**
   * Ask for none. A far end that insists on one is still honoured.
   */
  Off: 1,
  /**
   * Ask for `session_interval_seconds`, at least 90 (§5's floor).
   */
  Interval: 2,
} as const);
koffi.alias('sipral_session_timer_t', 'uint32_t');

/**
 * How loud a log line is, for sipral_stack_log and
 * sipral_log_record_t::level. Higher is more detailed: a stack logging
 * at `SIPRAL_LOG_LEVEL_INFO` delivers errors, warnings and information.
 */
export const SipralLogLevel = Object.freeze({
  /**
   * Nothing: the log is off. What a stack starts with.
   */
  Off: 0,
  /**
   * Something failed and the application is likely to see the effect.
   */
  Error: 1,
  /**
   * Something went wrong that the stack worked around, or is about to
   * matter: a registration refused, audio that stopped arriving.
   */
  Warn: 2,
  /**
   * What an operator wants in a log file: a registration granted, a
   * call arriving, confirmed or ending, media starting.
   */
  Info: 3,
  /**
   * Every event the stack raises, every decision its diagnostic record
   * writes down, and every call into this ABI it refused.
   */
  Debug: 4,
  /**
   * Every SIP message in and out, whole and redacted.
   */
  Trace: 5,
} as const);
koffi.alias('sipral_log_level_t', 'uint32_t');

/**
 * How a stream's SRTP keys were exchanged. Names for
 * `sipral_stream_encryption_t::key_exchange` and
 * `sipral_media_event_t::key_exchange`.
 */
export const SipralKeyExchange = Object.freeze({
  /**
   * None: the stream was never meant to be encrypted, or the event is
   * not about one.
   */
  None: 0,
  /**
   * In the session description (RFC 4568's `a=crypto`): as protected
   * as the signalling transport that carried it.
   */
  Sdes: 1,
  /**
   * By a DTLS handshake on the media path (RFC 5764), the far end's
   * certificate checked against the fingerprint its signalling named.
   */
  Dtls: 2,
} as const);
koffi.alias('sipral_key_exchange_t', 'uint32_t');

/**
 * What a stream carries. Names for `sipral_stream_encryption_t::media`.
 */
export const SipralMediaKind = Object.freeze({
  /**
   * Something this ABI has no word for.
   */
  Unknown: 0,
  /**
   * `m=audio`.
   */
  Audio: 1,
} as const);
koffi.alias('sipral_media_kind_t', 'uint32_t');

/**
 * What an account does with the `Identity` header fields of the calls
 * it receives (RFC 8224 §6.2). Names for
 * `sipral_account_config_t::stir_verification`.
 */
export const SipralStirVerification = Object.freeze({
  /**
   * This build's default, which is `REPORT`.
   */
  Default: 0,
  /**
   * Verify nothing.
   */
  Off: 1,
  /**
   * Verify, report the verdict on the call, and deliver every call
   * whatever it says. In force once the stack has trust anchors
   * (`sipral_stack_stir`); without any, nothing is fetched or
   * verified.
   */
  Report: 2,
  /**
   * Verify, and refuse a call that does not verify with the response
   * RFC 8224 §6.2.2 prescribes: 428 with no `Identity`, 436 for a
   * certificate that cannot be had, 437 for one nobody trusted, 438
   * for a signature that does not hold, 403 "Stale Date". In force
   * with or without trust anchors: with none, nothing verifies.
   */
  Strict: 3,
} as const);
koffi.alias('sipral_stir_verification_t', 'uint32_t');

/**
 * The attestation level of a SHAKEN PASSporT (RFC 8588 §4). Names for
 * `sipral_account_config_t::stir_attestation`,
 * `sipral_verification_event_t::attestation` and
 * `sipral_call_event_t::attestation`.
 */
export const SipralAttestation = Object.freeze({
  /**
   * None said: on an account, full attestation; on a verdict, a
   * PASSporT with no SHAKEN claims, or no valid one.
   */
  None: 0,
  /**
   * Full: the signer knows the caller and that the number is theirs.
   */
  A: 1,
  /**
   * Partial: the signer knows the caller, not the number.
   */
  B: 2,
  /**
   * Gateway: the signer knows only where the call entered its
   * network.
   */
  C: 3,
} as const);
koffi.alias('sipral_attestation_t', 'uint32_t');

/**
 * What a verification came to. Names for
 * `sipral_verification_event_t::outcome` and
 * `sipral_call_event_t::verification`.
 */
export const SipralVerificationOutcome = Object.freeze({
  /**
   * Nothing was verified: the account does not verify, or the stack
   * has no trust anchors and the account only reports.
   */
  None: 0,
  /**
   * A PASSporT signed by a certificate with authority over the calling
   * number, fresh, for the numbers the request names.
   */
  Valid: 1,
  /**
   * One was there and does not hold: `failure` says why.
   */
  Invalid: 2,
  /**
   * Nothing this end could verify: no `Identity`, or only ones naming
   * a PASSporT extension it does not support.
   */
  Absent: 3,
} as const);
koffi.alias('sipral_verification_outcome_t', 'uint32_t');

/**
 * Why a verification did not hold. Names for
 * `sipral_verification_event_t::failure` and
 * `sipral_call_event_t::verification_failure`.
 */
export const SipralVerificationFailure = Object.freeze({
  /**
   * Nothing failed.
   */
  None: 0,
  /**
   * No `Identity` header field.
   */
  NoIdentity: 1,
  /**
   * Only ones naming a `ppt` this end does not support.
   */
  UnsupportedPpt: 2,
  /**
   * The header field or its PASSporT is not well formed.
   */
  Malformed: 3,
  /**
   * Signed with an algorithm other than ES256.
   */
  UnsupportedAlgorithm: 4,
  /**
   * `iat` outside the freshness window.
   */
  Stale: 5,
  /**
   * The certificate could not be fetched, or did not arrive in time.
   */
  CertificateUnavailable: 6,
  /**
   * What the `info` URL yielded is not a chain this end can read.
   */
  CertificateUnreadable: 7,
  /**
   * The chain leads to no trust anchor.
   */
  Untrusted: 8,
  /**
   * A certificate in it is outside its validity period.
   */
  Expired: 9,
  /**
   * The chain breaks a rule of path validation.
   */
  InvalidChain: 10,
  /**
   * The signature does not verify.
   */
  BadSignature: 11,
  /**
   * The certificate has no authority over the calling number.
   */
  NumberNotCovered: 12,
  /**
   * Signed for another calling number than the request names.
   */
  OrigMismatch: 13,
  /**
   * Signed for another called number.
   */
  DestMismatch: 14,
} as const);
koffi.alias('sipral_verification_failure_t', 'uint32_t');

/**
 * Which half of a caller's verification an event reports. Names for
 * `sipral_verification_event_t::stage`.
 */
export const SipralVerificationStage = Object.freeze({
  /**
   * Never sent.
   */
  Unknown: 0,
  /**
   * The certificate at `certificate_url` is wanted: fetch it and hand
   * it to `sipral_call_stir_certificate`, or hand over nothing to say
   * it could not be had. The call waits, unannounced, until then or
   * until `certificate_wait_ms` runs out.
   */
  CertificateWanted: 1,
  /**
   * The verdict is in. `SIPRAL_EVENT_KIND_INCOMING_CALL` follows, or,
   * when `refused` is set, `SIPRAL_EVENT_KIND_CALL_ENDED`.
   */
  Verified: 2,
} as const);
koffi.alias('sipral_verification_stage_t', 'uint32_t');

/**
 * What a SIPRAL_EVENT_KIND_PROGRESS_DETECTED heard. Names for
 * `sipral_progress_event_t::what`.
 */
export const SipralProgressKind = Object.freeze({
  /**
   * Never written by this build.
   */
  Unknown: 0,
  /**
   * A call-progress tone of the configured network: `tone` says which
   * and `at_ms` when its first burst began, from the first frame
   * listened to.
   */
  Tone: 1,
  /**
   * The special information tone: the call failed, and an
   * announcement usually follows. `sit_hz_1` to `sit_hz_3` and
   * `sit_ms_1` to `sit_ms_3` are what was measured, `at_ms` when the
   * first of the three began.
   */
  SpecialInformation: 2,
  /**
   * Who answered: `verdict`, `reason`, `at_ms` after answer,
   * `initial_silence_ms`, `greeting_ms` and `words`.
   */
  AnsweredBy: 3,
  /**
   * The beep a machine plays before it records: `frequency_hz`,
   * `at_ms` when it ended after answer — when the machine starts
   * recording — and `length_ms`.
   */
  Beep: 4,
} as const);
koffi.alias('sipral_progress_kind_t', 'uint32_t');

/**
 * A call-progress tone. Names for `sipral_progress_event_t::tone`.
 */
export const SipralProgressTone = Object.freeze({
  /**
   * Not a tone, or one this build has no name for.
   */
  Unknown: 0,
  /**
   * The exchange is ready for digits.
   */
  Dial: 1,
  /**
   * The far end is being alerted.
   */
  Ringback: 2,
  /**
   * The far end is busy.
   */
  Busy: 3,
  /**
   * The network is congested: congestion, or reorder.
   */
  Congestion: 4,
  /**
   * A second call is waiting.
   */
  CallWaiting: 5,
  /**
   * The special information tone.
   */
  SpecialInformation: 6,
} as const);
koffi.alias('sipral_progress_tone_t', 'uint32_t');

/**
 * Who answered. Names for `sipral_progress_event_t::verdict`.
 */
export const SipralAmdVerdict = Object.freeze({
  /**
   * Not a verdict.
   */
  Unknown: 0,
  /**
   * A person.
   */
  Human: 1,
  /**
   * An answering machine or a voice mailbox.
   */
  Machine: 2,
  /**
   * The evidence does not say.
   */
  NotSure: 3,
} as const);
koffi.alias('sipral_amd_verdict_t', 'uint32_t');

/**
 * Which rule decided who answered. Names for
 * `sipral_progress_event_t::reason`.
 */
export const SipralAmdReason = Object.freeze({
  /**
   * Not a verdict.
   */
  None: 0,
  /**
   * A short greeting, then silence: somebody said hello and waits.
   */
  ShortGreeting: 1,
  /**
   * More words than a person answers with.
   */
  TooManyWords: 2,
  /**
   * A greeting longer than a person gives.
   */
  LongGreeting: 3,
  /**
   * Nobody spoke.
   */
  InitialSilence: 4,
  /**
   * No rule decided in the time allowed.
   */
  Timeout: 5,
} as const);
koffi.alias('sipral_amd_reason_t', 'uint32_t');

/**
 * When a call listens for keypad digits in the far end's audio. Names
 * for `sipral_stack_config_t::dtmf_detection` and
 * sipral_call_dtmf_detection's `mode`.
 */
export const SipralDtmfDetection = Object.freeze({
  /**
   * On a call whose negotiation settled on no telephone event payload
   * type: the far end then has no other way to send a digit. Zero, so
   * that a stack that says nothing gets it.
   */
  Auto: 0,
  /**
   * Never. Digits arrive only as RFC 4733 events or by INFO.
   */
  Off: 1,
  /**
   * On every call. A press the far end sends both as an event and in
   * the audio is reported once, as the event.
   */
  Always: 2,
} as const);
koffi.alias('sipral_dtmf_detection_t', 'uint32_t');

/**
 * Whose call-progress tones to listen for. Names for
 * `sipral_progress_config_t::region`.
 */
export const SipralToneRegion = Object.freeze({
  /**
   * The 425 Hz tones common to the CEPT administrations.
   */
  Europe: 0,
  /**
   * The United States and Canada.
   */
  NorthAmerica: 1,
  /**
   * The United Kingdom.
   */
  UnitedKingdom: 2,
} as const);
koffi.alias('sipral_tone_region_t', 'uint32_t');

/**
 * The file format of a recording. Names for
 * `sipral_recording_options_t::format`.
 */
export const SipralRecordingFormat = Object.freeze({
  /**
   * Sixteen-bit PCM in RIFF/WAVE, becoming RF64 past four gibibytes.
   */
  Wav: 0,
  /**
   * Opus in Ogg (RFC 7845), where `SIPRAL_FEATURE_OPUS` says the build
   * has the encoder; `SIPRAL_STATUS_NOT_SUPPORTED` where it does not.
   */
  OggOpus: 1,
} as const);
koffi.alias('sipral_recording_format_t', 'uint32_t');

/**
 * How the two directions of a call share a recording. Names for
 * `sipral_recording_options_t::layout`.
 */
export const SipralRecordingLayout = Object.freeze({
  /**
   * One channel: both directions, each at half level, summed.
   */
  Mixed: 0,
  /**
   * Two channels: this end on the left, the far end on the right.
   */
  Stereo: 1,
} as const);
koffi.alias('sipral_recording_layout_t', 'uint32_t');

/**
 * What one conference document did. Names for
 * `sipral_conference_event_t::update`.
 */
export const SipralConferenceUpdate = Object.freeze({
  /**
   * Never written by this build.
   */
  Unknown: 0,
  /**
   * It was merged into the picture.
   */
  Applied: 1,
  /**
   * The focus deleted the conference: the picture is empty, and the
   * subscription is being given up (RFC 4575 §4.6).
   */
  Ended: 2,
} as const);
koffi.alias('sipral_conference_update_t', 'uint32_t');

/**
 * Where one endpoint of a conference is (RFC 4575 §5.7.2). Names for
 * `sipral_conference_user_t::status`.
 */
export const SipralEndpointStatus = Object.freeze({
  /**
   * The focus did not say, or said something the schema does not
   * list.
   */
  Unknown: 0,
  /**
   * `pending`: waiting for policy or for the focus.
   */
  Pending: 1,
  /**
   * `dialing-out`: the focus is calling it.
   */
  DialingOut: 2,
  /**
   * `dialing-in`: it is calling the focus.
   */
  DialingIn: 3,
  /**
   * `alerting`: it is ringing.
   */
  Alerting: 4,
  /**
   * `on-hold`.
   */
  OnHold: 5,
  /**
   * `connected`: it is in the conference.
   */
  Connected: 6,
  /**
   * `muted-via-focus`: in, and muted by the focus.
   */
  MutedViaFocus: 7,
  /**
   * `disconnecting`.
   */
  Disconnecting: 8,
  /**
   * `disconnected`: it has left.
   */
  Disconnected: 9,
} as const);
koffi.alias('sipral_endpoint_status_t', 'uint32_t');

/**
 * Which piece of text sipral_subscription_conference_text is being
 * asked for. The first three are about the conference and ignore
 * `index`; the rest are about the user at `index`.
 *
 * Every one of them is what the focus wrote.
 */
export const SipralConferenceText = Object.freeze({
  /**
   * Never asked for.
   */
  Unknown: 0,
  /**
   * The conference's URI, the `entity` of `conference-info`.
   */
  Entity: 1,
  /**
   * Its `subject`.
   */
  Subject: 2,
  /**
   * Its `display-text`.
   */
  DisplayText: 3,
  /**
   * A user's `entity`: the address of record it takes part as.
   */
  UserEntity: 4,
  /**
   * A user's `display-text`.
   */
  UserDisplayText: 5,
  /**
   * The `entity` of a user's first endpoint: the device it is on.
   */
  UserEndpoint: 6,
} as const);
koffi.alias('sipral_conference_text_t', 'uint32_t');

/**
 * What a SIPRAL_EVENT_KIND_PRESENCE_CHANGED is about.
 * Names for `sipral_presence_event_t::kind`.
 */
export const SipralPresenceKind = Object.freeze({
  /**
   * Never written by this build.
   */
  Unknown: 0,
  /**
   * A `presence` subscription was told about the presentity.
   */
  Watched: 1,
  /**
   * This account's own published presence moved.
   */
  Publication: 2,
} as const);
koffi.alias('sipral_presence_kind_t', 'uint32_t');

/**
 * Whether a presentity can be reached: PIDF's `basic` (RFC 3863
 * §4.1.4). Names for `sipral_presence_t::basic` and
 * `sipral_presence_event_t::basic`.
 */
export const SipralBasic = Object.freeze({
  /**
   * Not said. A document published with this is refused, since
   * §4.1.3 wants one.
   */
  Unknown: 0,
  /**
   * Reachable.
   */
  Open: 1,
  /**
   * Not reachable.
   */
  Closed: 2,
} as const);
koffi.alias('sipral_basic_t', 'uint32_t');

/**
 * What the person behind a presentity is doing: the RPID activities
 * (RFC 4480 §3.2) phones show. Names for `sipral_presence_t::activity`
 * and `sipral_presence_event_t::activity`.
 */
export const SipralActivity = Object.freeze({
  /**
   * None said. Published, the document carries no person at all.
   */
  None: 0,
  /**
   * `away`.
   */
  Away: 1,
  /**
   * `busy`.
   */
  Busy: 2,
  /**
   * `on-the-phone`.
   */
  OnThePhone: 3,
  /**
   * `meeting`.
   */
  Meeting: 4,
  /**
   * `vacation`.
   */
  Vacation: 5,
  /**
   * Another activity, which this ABI has no number for.
   */
  Other: 6,
} as const);
koffi.alias('sipral_activity_t', 'uint32_t');

/**
 * What became of this account's published presence. Names for
 * `sipral_presence_event_t::publication_state`.
 */
export const SipralPublicationState = Object.freeze({
  /**
   * Not a publication event.
   */
  Unknown: 0,
  /**
   * The compositor holds it: published, modified or refreshed.
   */
  Published: 1,
  /**
   * It was taken away (`sipral_account_unpublish_presence`).
   */
  Removed: 2,
  /**
   * Its lifetime ran out with no refresh; the next publish starts it
   * afresh.
   */
  Expired: 3,
  /**
   * The compositor refused, or never answered.
   */
  Failed: 4,
} as const);
koffi.alias('sipral_publication_state_t', 'uint32_t');

/**
 * Why a publication failed. Names for `sipral_presence_event_t::failure`.
 */
export const SipralPublishFailure = Object.freeze({
  /**
   * Nothing failed.
   */
  None: 0,
  /**
   * 489: the compositor does not know the `presence` package. Nothing
   * more is sent.
   */
  BadEvent: 1,
  /**
   * 423 with no `Min-Expires` this stack could meet.
   */
  IntervalTooBrief: 2,
  /**
   * A 2xx without the `SIP-ETag` every one must carry.
   */
  NoEntityTag: 3,
  /**
   * Any other refusal, a challenge nothing could answer among them;
   * `status_code` says which.
   */
  Refused: 4,
  /**
   * No answer at all.
   */
  Unreachable: 5,
} as const);
koffi.alias('sipral_publish_failure_t', 'uint32_t');

/**
 * What a `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` says happened.
 * Names for `sipral_local_conference_event_t::change`.
 */
export const SipralLocalConferenceChange = Object.freeze({
  /**
   * Never written by this build.
   */
  Unknown: 0,
  /**
   * `member` joined: a call added, or this end when the conference was
   * made with it.
   */
  Joined: 1,
  /**
   * `member` left, for the reason `departure` gives.
   */
  Left: 2,
  /**
   * Who is talking changed: `talkers` and `loudest` say who now, and
   * `sipral_local_conference_talker_at` lists them, loudest first.
   */
  Talkers: 3,
  /**
   * The conference's recording stopped by itself: the file would not
   * take what was written. It holds the audio up to its last
   * checkpoint.
   */
  RecordingStopped: 4,
} as const);
koffi.alias('sipral_local_conference_change_t', 'uint32_t');

/**
 * Why a member left. Names for
 * `sipral_local_conference_event_t::departure`.
 */
export const SipralDeparture = Object.freeze({
  /**
   * Nobody left.
   */
  None: 0,
  /**
   * `sipral_local_conference_remove` took it out.
   */
  Removed: 1,
  /**
   * Its call's media ended.
   */
  Ended: 2,
  /**
   * Its call moved to a codec whose rate or frame the conference
   * cannot mix.
   */
  Incompatible: 3,
} as const);
koffi.alias('sipral_departure_t', 'uint32_t');

/**
 * Which kind of DNS record a lookup asks for. Names for
 * `sipral_locate_event_t::record` and `sipral_account_looked_up`'s
 * `record`.
 */
export const SipralDnsRecordType = Object.freeze({
  /**
   * Not a lookup: the value on a `SIPRAL_EVENT_KIND_LOCATED` or a
   * `SIPRAL_EVENT_KIND_LOCATE_FAILED`.
   */
  None: 0,
  /**
   * RFC 3403: which services a domain offers, and under which names.
   */
  Naptr: 1,
  /**
   * RFC 2782: which hosts, at which ports, serve one service.
   */
  Srv: 2,
  /**
   * An IPv4 address.
   */
  A: 3,
  /**
   * An IPv6 address.
   */
  Aaaa: 4,
} as const);
koffi.alias('sipral_dns_record_type_t', 'uint32_t');

/**
 * What the application's resolver said to a lookup. Names for
 * `sipral_account_looked_up`'s `answer`.
 */
export const SipralDnsAnswer = Object.freeze({
  /**
   * The records it returned, in `records`. None at all reads as
   * `SIPRAL_DNS_ANSWER_NOTHING`.
   */
  Records: 1,
  /**
   * The name has no record of that kind, or does not exist at all.
   * Also the right answer from a resolver that cannot ask for the
   * kind: a platform lookup that only knows addresses answers every
   * NAPTR and SRV query with this, and the host's own addresses are
   * asked for next.
   */
  Nothing: 2,
  /**
   * The resolver could not answer: no server reachable, a timeout, a
   * server failure.
   */
  Failed: 3,
} as const);
koffi.alias('sipral_dns_answer_t', 'uint32_t');

/**
 * Why a lookup of an account's server named no address. Names for
 * `sipral_locate_event_t::failure`.
 */
export const SipralLocateFailure = Object.freeze({
  /**
   * Nothing failed.
   */
  None: 0,
  /**
   * The DNS answered, and what it answered names no address of the
   * family the account's transport can reach: no record, or an SRV
   * target of `.`.
   */
  NotFound: 1,
  /**
   * The resolver failed on every lookup that could have given an
   * address.
   */
  Unanswered: 2,
  /**
   * The transport has no RFC 3263 procedure: WebSocket names no SRV
   * service and no default port, so only a numeric host, or a host
   * with a port, can be located for it.
   */
  Unsupported: 3,
} as const);
koffi.alias('sipral_locate_failure_t', 'uint32_t');

/**
 * Why an account's password did not answer a challenge. Names for
 * `sipral_challenge_event_t::refusal`.
 */
export const SipralChallengeRefusal = Object.freeze({
  /**
   * Never written by this build.
   */
  Unknown: 0,
  /**
   * The challenged request went somewhere other than the account's
   * own server — its registrar, or the outbound proxy of an account
   * that does not register — so whoever asked is the far end of a
   * call, or a peer reached directly.
   */
  NotTheAccountsServer: 1,
  /**
   * The account's server asked for a realm that is not the
   * account's: not one of `sipral_account_config_t::realms`, or, with
   * none named, neither the one its server first challenged with nor
   * one its REGISTERs were challenged with. A proxy passing on a far
   * end's own challenge looks like this, and so does an SBC that
   * challenges calls under a realm of its own.
   */
  NotTheAccountsRealm: 2,
} as const);
koffi.alias('sipral_challenge_refusal_t', 'uint32_t');

/**
 * What an account's server said was wrong with the access token it
 * was given (RFC 6750 §3.1, RFC 8898 §4). Names for
 * `sipral_token_event_t::error`.
 */
export const SipralTokenError = Object.freeze({
  /**
   * The server named no error: no token was offered yet.
   */
  None: 0,
  /**
   * `invalid_request`: the request was malformed.
   */
  InvalidRequest: 1,
  /**
   * `invalid_token`: the token is expired, revoked, malformed or
   * otherwise invalid. A new one is needed.
   */
  InvalidToken: 2,
  /**
   * `insufficient_scope`: the token does not cover what was asked;
   * `scope` says what would.
   */
  InsufficientScope: 3,
  /**
   * `invalid_scope`.
   */
  InvalidScope: 4,
  /**
   * Another code, as written in `error_code`.
   */
  Other: 5,
} as const);
koffi.alias('sipral_token_error_t', 'uint32_t');

/**
 * What a network test, or one part of it, comes to. Names for
 * `sipral_network_test_event_t::verdict` and `echo_verdict`.
 */
export const SipralNetworkVerdict = Object.freeze({
  /**
   * Nothing was tested.
   */
  Unknown: 0,
  /**
   * Calls should work and sound right.
   */
  Good: 1,
  /**
   * Calls should work, and may not everywhere or may not sound their
   * best.
   */
  Acceptable: 2,
  /**
   * Calls are likely to fail or to sound bad.
   */
  Poor: 3,
} as const);
koffi.alias('sipral_network_verdict_t', 'uint32_t');

/**
 * Whether a part of a network test was tried, and how it went. Names
 * for `sipral_network_test_event_t::stun`, `turn` and `echo`.
 */
export const SipralNetworkProbe = Object.freeze({
  /**
   * Not part of this test.
   */
  NotTested: 0,
  /**
   * The server answered as hoped; for the echo, audio came back and
   * was measured.
   */
  Succeeded: 1,
  /**
   * It did not.
   */
  Failed: 2,
} as const);
koffi.alias('sipral_network_probe_t', 'uint32_t');

/**
 * What a STUN answer says about the NAT in front of this end. Names for
 * `sipral_network_test_event_t::nat`. Approximate: one answer shows
 * whether the address and the port were translated, and nothing about
 * how the NAT filters what arrives (RFC 4787).
 */
export const SipralNatKind = Object.freeze({
  /**
   * No answer to read.
   */
  Unknown: 0,
  /**
   * No translation: the server saw the socket's own address.
   */
  Open: 1,
  /**
   * The address was translated and the port kept.
   */
  PortPreserved: 2,
  /**
   * The port was changed too.
   */
  PortChanged: 3,
} as const);
koffi.alias('sipral_nat_kind_t', 'uint32_t');

/**
 * What the account's server did with the test's `OPTIONS`. Names for
 * `sipral_network_test_event_t::server`.
 */
export const SipralServerReach = Object.freeze({
  /**
   * Not part of this test.
   */
  NotTested: 0,
  /**
   * It answered: `server_status` with what, `server_round_trip_ms`
   * after how long. Any final answer is a server that is there.
   */
  Answered: 1,
  /**
   * No answer before the request, or the test, timed out.
   */
  TimedOut: 2,
  /**
   * The transport refused the request or failed under it.
   */
  TransportFailed: 3,
} as const);
koffi.alias('sipral_server_reach_t', 'uint32_t');

/**
 * What a party this end holds is sent:
 * `sipral_stack_config_t::held_audio`.
 */
export const SipralHeldAudio = Object.freeze({
  /**
   * Silence, in either mode.
   */
  Default: 0,
  /**
   * Silence: the party on hold hears nothing of the room it was put
   * on hold from.
   */
  Silence: 1,
  /**
   * The frames the application hands over, as they are.
   */
  Application: 2,
} as const);
koffi.alias('sipral_held_audio_t', 'uint32_t');

/**
 * The version of the ABI this library provides.
 *
 * Set `size` to `sizeof(sipral_abi_version_t)` before the call.
 */
export interface SipralAbiVersion {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * Nothing built against another major version will work.
   */
  major: number;
  /**
   * A build with a higher minor has everything a lower one had.
   */
  minor: number;
  /**
   * A fix that changed no declaration.
   */
  patch: number;
  /**
   * Zero. Rounds the struct up to a whole multiple of its alignment on
   * every target, so that a member a later version appends starts at or
   * past the length a caller built against this header declares, never
   * in padding inside it. The library writes zero here and reads nothing
   * from it.
   */
  reserved: number;
}
koffi.struct('sipral_abi_version_t', {
  size: 'size_t',
  major: 'uint32_t',
  minor: 'uint32_t',
  patch: 'uint32_t',
  reserved: 'uint32_t',
});

/**
 * What this build of the library can do: codecs compiled in, transports
 * this ABI carries signalling over, and which optional features are
 * present.
 *
 * Nothing here is configuration — this answers "can this build ever do X",
 * never "is X turned on for this stack". `sipral_stack_settings` answers
 * that once a stack exists, and `sipral_codec_count` /
 * `sipral_stack_codec_order` already enumerate the codecs this reports only
 * the count of, so this does not repeat what they say.
 *
 * Set `size` to `sizeof(sipral_capabilities_t)` before the call.
 */
export interface SipralCapabilities {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * How many codecs this build contains. `sipral_codec_count` gives the
   * same number; `sipral_codec_at` says which, and in what order they are
   * offered by default.
   */
  codec_count: number;
  /**
   * Which transports this build carries signalling over, as the bits
   * named `SIPRAL_TRANSPORT_BIT_*`.
   */
  transports: number;
  /**
   * Which optional features this build has compiled in, as the bits named
   * `SIPRAL_FEATURE_*`.
   */
  features: number;
}
koffi.struct('sipral_capabilities_t', {
  size: 'size_t',
  codec_count: 'size_t',
  transports: 'uint32_t',
  features: 'uint32_t',
});

/**
 * D3's flat set of health counters for one stack, since it was created.
 *
 * Every member here is monotonic except `active_calls`, which is a gauge:
 * it can be read as smaller than an earlier reading, and none of the others
 * ever will be. Set `size` to `sizeof(sipral_counters_t)` before the call.
 */
export interface SipralCounters {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * A REGISTER went out, counted once per attempt including a retry.
   */
  registrations_attempted: Wide;
  /**
   * The registrar granted a binding.
   */
  registrations_succeeded: Wide;
  /**
   * The registrar refused, and will refuse the same request again.
   */
  registrations_failed_rejected: Wide;
  /**
   * The password was wrong, or there was none to answer a challenge with.
   */
  registrations_failed_bad_credentials: Wide;
  /**
   * The registrar did not answer, or said it could not serve this now.
   */
  registrations_failed_unreachable: Wide;
  /**
   * The registrar moved.
   */
  registrations_failed_redirected: Wide;
  /**
   * This end hung up.
   */
  calls_ended_local_hangup: Wide;
  /**
   * The far end hung up.
   */
  calls_ended_remote_hangup: Wide;
  /**
   * The far end refused it: busy, declined, not found.
   */
  calls_ended_refused: Wide;
  /**
   * Given up before it was answered, from either end.
   */
  calls_ended_cancelled: Wide;
  /**
   * Nothing came back, or the transport died.
   */
  calls_ended_unreachable: Wide;
  /**
   * Another branch of the same fork was kept and this one was not.
   */
  calls_ended_fork_lost: Wide;
  /**
   * The branch was still ringing when the answer window closed.
   */
  calls_ended_abandoned: Wide;
  /**
   * The session timer ran out and no refresh arrived.
   */
  calls_ended_expired: Wide;
  /**
   * How many times inbound audio stopped for longer than the configured
   * threshold while signalling stayed healthy (B5).
   */
  media_gaps: Wide;
  /**
   * How many times a call's jitter buffer had to shrink or stretch the
   * stream to keep its delay where it was aiming.
   */
  jitter_buffer_events: Wide;
  /**
   * How many times a request would not fit a datagram and there was no
   * stream to the destination to put it on, so the stack asked for one
   * (RFC 3261 §18.1.1, B1).
   *
   * A request promoted onto a connection that already existed does not
   * raise it; those are in the diagnostic record instead.
   */
  stream_transport_wanted: Wide;
  /**
   * Calls with media running right now. The one gauge in this struct: it
   * moves both ways, and it is what every other member here is not.
   */
  active_calls: Wide;
  /**
   * Events a poll raised and had nowhere to queue, because the
   * callback had not kept up and the outbox was already at its ceiling
   * (task 8.4.21).
   */
  events_dropped: Wide;
  /**
   * RTCP goodbyes dropped, oldest first, because the application had
   * not called `sipral_stack_poll_farewell` and the queue behind it
   * was already at its ceiling.
   */
  farewells_dropped: Wide;
  /**
   * INVITEs a `sipral_stack_screen` policy refused (A8, D7).
   */
  screened_refused_by_policy: Wide;
  /**
   * INVITEs refused because their source was offering them faster
   * than `sipral_stack_invite_limit` allows.
   */
  screened_refused_by_rate: Wide;
  /**
   * INVITEs refused because every seat this stack keeps for a source
   * it is watching belonged to one still spending, and this source
   * could not be limited either — a flood from many addresses at
   * once rather than one calling too fast.
   */
  screened_refused_by_crowding: Wide;
  /**
   * INVITEs refused 403 for naming a call they had no standing to
   * replace (RFC 3891 §3).
   */
  screened_refused_by_replaces: Wide;
  /**
   * Requests this stack sent again because nothing answered in time
   * (RFC 3261 timers A and E), and ACKs sent again because the 2xx
   * they acknowledge arrived again. Only ever over UDP: nothing
   * retransmits over a stream. A figure that climbs while calls still
   * connect is a path losing packets before it loses calls.
   */
  requests_retransmitted: Wide;
  /**
   * Responses sent again: timer G, a reliable provisional response's
   * own timer, and the last answer repeated because the far end sent
   * its request again, which is what it does when that answer did not
   * reach it.
   */
  responses_retransmitted: Wide;
  /**
   * Transactions that ended because the far end never answered or
   * never acknowledged: timers B, F, H and L, and a reliable
   * provisional response never PRACKed.
   */
  transactions_timed_out: Wide;
  /**
   * Requests answered `503` because the stack was at
   * `max_server_transactions`, or an INVITE was at `max_dialogs`.
   */
  requests_refused_at_limit: Wide;
}
koffi.struct('sipral_counters_t', {
  size: 'size_t',
  registrations_attempted: 'uint64_t',
  registrations_succeeded: 'uint64_t',
  registrations_failed_rejected: 'uint64_t',
  registrations_failed_bad_credentials: 'uint64_t',
  registrations_failed_unreachable: 'uint64_t',
  registrations_failed_redirected: 'uint64_t',
  calls_ended_local_hangup: 'uint64_t',
  calls_ended_remote_hangup: 'uint64_t',
  calls_ended_refused: 'uint64_t',
  calls_ended_cancelled: 'uint64_t',
  calls_ended_unreachable: 'uint64_t',
  calls_ended_fork_lost: 'uint64_t',
  calls_ended_abandoned: 'uint64_t',
  calls_ended_expired: 'uint64_t',
  media_gaps: 'uint64_t',
  jitter_buffer_events: 'uint64_t',
  stream_transport_wanted: 'uint64_t',
  active_calls: 'uint64_t',
  events_dropped: 'uint64_t',
  farewells_dropped: 'uint64_t',
  screened_refused_by_policy: 'uint64_t',
  screened_refused_by_rate: 'uint64_t',
  screened_refused_by_crowding: 'uint64_t',
  screened_refused_by_replaces: 'uint64_t',
  requests_retransmitted: 'uint64_t',
  responses_retransmitted: 'uint64_t',
  transactions_timed_out: 'uint64_t',
  requests_refused_at_limit: 'uint64_t',
});

/**
 * What a stack is created with.
 *
 * Set `size` to `sizeof(sipral_stack_config_t)` and zero the rest before
 * filling anything in. Five members have to be filled: the callback, the
 * transport, the address this end is reachable at, the entropy, and the
 * media seed, which must differ from the entropy. Nothing here can be
 * guessed on the caller's behalf.
 */
export interface SipralStackConfig {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * Where events go. Required: a stack with nowhere to report to is a
   * stack whose failures are invisible.
   */
  event_callback: Pointer;
  /**
   * Handed back to the callback untouched. The library never reads it.
   */
  event_user_data: Pointer;
  /**
   * A sipral_transport_t.
   */
  transport: number;
  /**
   * The address the far end reaches this one at, as `host:port`, UTF-8 and
   * not NUL-terminated.
   *
   * It goes in every `Via`, so it is the address a response has to come
   * back to rather than whatever a wildcard socket was bound to. Nothing
   * here opens a socket or resolves a name.
   */
  bind_address: Pointer;
  /**
   * How many bytes of it.
   */
  bind_address_len: number;
  /**
   * What to put in `User-Agent` on every request this stack originates —
   * REGISTER and INVITE — or null for none.
   *
   * Not on responses, and not on a request sent inside a dialog: those are
   * written a layer below this one, which has no opinion about product
   * names. The field is optional on every method — §20 Table 3 marks it `o`
   * throughout — so a message that goes out without it is still well formed.
   */
  user_agent: Pointer;
  /**
   * How many bytes of it.
   */
  user_agent_len: number;
  /**
   * Thirty-two bytes of entropy, from the platform's own generator.
   *
   * Every branch parameter, tag and `Call-ID` is derived from it, and
   * §19.3 wants a tag unguessable — cryptographically random, not a
   * counter or a clock. Two stacks must never be given the same bytes.
   *
   * Not the media keys: those come from `media_seed`, a separate draw,
   * because what is drawn from this one goes on the wire in clear. A
   * replay recording carries neither: it carries a seed drawn for it
   * from a stream derived one way from this one, which says nothing
   * about these bytes (`sipral_stack_recording_start`).
   */
  entropy: Pointer;
  /**
   * How many bytes of it. Thirty-two.
   */
  entropy_len: number;
  /**
   * T1 in milliseconds, or zero for the 500 ms of §17.1.1.1.
   *
   * In force on every transport: 64·T1 is how long a transaction has to
   * finish, whether or not anything retransmits.
   */
  timer_t1_ms: Wide;
  /**
   * T2 in milliseconds, or zero for four seconds.
   *
   * The cap on the doubling that starts at T1, and therefore only a figure
   * on a transport that retransmits. Setting it on anything but UDP is
   * `SIPRAL_STATUS_INVALID_ARGUMENT` rather than a value nothing reads.
   */
  timer_t2_ms: Wide;
  /**
   * T4 in milliseconds, or zero for five seconds.
   *
   * How long a message lingers in the network, which is what timers I and K
   * wait out. Zero on a transport that delivers for us, so it is refused
   * there the same way T2 is.
   */
  timer_t4_ms: Wide;
  /**
   * The codecs to offer, in the order to offer them: their names, separated
   * by commas, as UTF-8 and not NUL-terminated. Null for everything this
   * build contains, quality first.
   *
   * A4. The order is the whole of the negotiation's outcome — RFC 3264 §6.1
   * has the peer's preference decide among what both ends list — and it is
   * configured per site rather than fixed, because a carrier that bills by
   * the minute wants the narrowband codec first and a company on its own
   * network wants the wideband one.
   *
   * A name this build has no encoder for is `SIPRAL_STATUS_NOT_SUPPORTED`
   * here, with the names it does have in the last error. It is never taken
   * and ignored: a setting that is accepted and then quietly dropped is the
   * failure neither end can see.
   */
  codecs: Pointer;
  /**
   * How many bytes of it.
   */
  codecs_len: number;
  /**
   * How long a frame is, in milliseconds, or zero for twenty.
   *
   * Twenty is what every peer expects and what every codec here cuts
   * cleanly. Opus has a fixed set of frame durations and encodes nothing
   * else, so an interval it has no size for is refused while Opus is one of
   * the codecs offered.
   */
  frame_ms: number;
  /**
   * Whether to offer RFC 4733 named events, as a `sipral_toggle_t`. On by
   * default: a phone that cannot send a digit cannot navigate a menu.
   */
  offer_dtmf: number;
  /**
   * Whether to ask for RFC 5761 multiplexing, as a `sipral_toggle_t`.
   *
   * Off by default. §5.1.1 only permits it where both ends asked, and the
   * equipment this stack is deployed against does not; asking unasked costs
   * a line in every offer and buys a port on the calls where nobody answers.
   */
  offer_rtcp_mux: number;
  /**
   * Whether to stop sending during silence, as a `sipral_toggle_t`.
   *
   * Off by default. It halves the bandwidth of a call in which one person is
   * listening, and it costs the far end's own stall watchdog a reason to
   * fire — this stack sends no comfort noise of its own to say the silence
   * is deliberate, so a gap looks the same from there as a stream that died.
   */
  silence_suppression: number;
  /**
   * Whether inbound audio that stops is reported, as a `sipral_toggle_t`. On by
   * default; this is B5.
   */
  media_stall_watchdog: number;
  /**
   * How long inbound audio may stop before that is reported, in
   * milliseconds, or zero for this build's own figure.
   *
   * Setting it with the watchdog switched off is
   * `SIPRAL_STATUS_INVALID_ARGUMENT` rather than a value nothing reads.
   */
  media_stall_ms: Wide;
  /**
   * What the wall clock read when the stack was created, as seconds since
   * 1 January 1970, or zero.
   *
   * The one number a stack that reads no clock cannot work out: RFC 3550
   * §6.4.1 has a sender report carry "the wall clock time when this report
   * was sent", and a monotonic instant is not one. Zero means the reports
   * take the wall clock `sipral_stack_stir` gives in `unix_seconds`, from
   * the moment it is given, and count from the Unix epoch until then:
   * the round trip the far end computes is a difference, not an
   * absolute, but the correlation of this call's media with anything
   * else's is not.
   */
  media_clock_unix_seconds: Wide;
  /**
   * Thirty-two more bytes of entropy, for the media keys, and **not
   * the same bytes as `entropy`**.
   *
   * Every SRTP master key this stack offers or answers with is derived
   * from these and from nothing else. They are a second draw rather
   * than a slice of the first because a replay recording writes
   * `entropy` into the file in clear: one generator for both would put
   * every key the stack will ever offer into every recording it makes.
   *
   * Handing the same bytes twice is refused rather than accepted
   * quietly. This is the only place in the library that can see both.
   */
  media_seed: Pointer;
  /**
   * How many bytes of it. Thirty-two.
   */
  media_seed_len: number;
  /**
   * What every call on this stack does about SRTP unless
   * `sipral_call_config_t::srtp` says otherwise for it: a
   * `sipral_srtp_t`, or zero for this build's own built-in default, which
   * is `SIPRAL_SRTP_NOT_OFFERED` — nothing here offers encryption
   * until it is asked to. Any other value is
   * `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
   */
  srtp: number;
  /**
   * What every call on this stack does about ICE unless
   * `sipral_call_config_t::ice` says otherwise for it: a `sipral_ice_t`,
   * or zero for this build's own built-in default, which is
   * `SIPRAL_ICE_OFF` — nothing here offers ICE until it is asked to,
   * for the reason `docs/06-nat.md` tabulates. Any other value is
   * `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
   */
  ice: number;
  /**
   * What this stack does about a NAT in front of it: a `sipral_nat_t`, or
   * zero for this build's own built-in default, which is
   * `SIPRAL_NAT_OFF`. `SIPRAL_NAT_STUN` asks `stun_server` where each
   * socket appears from and writes the answer where a far end reads
   * it — see `docs/06-nat.md`. Any other value is
   * `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
   */
  nat: number;
  /**
   * The STUN server `SIPRAL_NAT_STUN` asks, as `host:port`: an
   * address, not a name, since resolving one is the application's.
   * Required with `SIPRAL_NAT_STUN` and refused without it, since a
   * server nothing asks is a setting nothing reads. Copied; the
   * caller's buffer is its own again when this returns.
   */
  stun_server: Pointer;
  /**
   * How many bytes of it.
   */
  stun_server_len: number;
  /**
   * Whether G.729's Annex B — silence compression: SID frames and
   * nothing in a pause, and the comfort noise both ends make from
   * them — is allowed on this stack's calls, as a `sipral_toggle_t`. On
   * by default, which is what `G729` means with no parameter (RFC
   * 4856 §2.1.9): an offer says `annexb=yes`, and an answer says
   * `yes` only where the offer allowed it. Off, both say `annexb=no`,
   * which RFC 3551 §4.5.6 makes the far end's cue to send no SID
   * frames, and this end sends none either. A per-call codec order
   * keeps the stack's setting. Nothing changes for a call that does
   * not run G.729, so the setting is taken whatever `codecs` names:
   * a call's own order may name G.729 when the stack's does not.
   */
  g729_annex_b: number;
  /**
   * A TURN server (RFC 8656) to allocate a relay on for every media
   * socket `sipral_stack_nat_map` names, as `host:port`: an address,
   * not a name. The relay becomes the relayed ICE candidate of the call
   * placed, rung or answered on that socket — the path of last resort,
   * used only when no cheaper pair answers — and goes back to the
   * server when the call ends. See `docs/06-nat.md`.
   *
   * Optional, and only with `SIPRAL_NAT_STUN`, since it rides on the
   * same media-socket calls; it may be the same address as
   * `stun_server`. `turn_username` and `turn_password` are then
   * required: a TURN server that hands out relays to anyone is one
   * somebody else is already using. `SIPRAL_STATUS_NOT_SUPPORTED` in
   * a build without `SIPRAL_FEATURE_ICE`, which is the only thing that
   * can use a relay. Copied; the caller's buffer is its own again when
   * this returns.
   */
  turn_server: Pointer;
  /**
   * How many bytes of it.
   */
  turn_server_len: number;
  /**
   * The user name of the long-term credential the TURN server knows
   * this end by (RFC 8489 §9.2).
   */
  turn_username: Pointer;
  /**
   * How many bytes of it.
   */
  turn_username_len: number;
  /**
   * Its password. Copied into memory that is overwritten when the
   * stack is destroyed, and never written to a log, an event or an
   * error text.
   */
  turn_password: Pointer;
  /**
   * How many bytes of it.
   */
  turn_password_len: number;
  /**
   * Whether a REFER outside any dialog — somebody asking this end to
   * place a call it is not in, which is what click-to-dial from a
   * switchboard or a CRM sends (RFC 3515 §4.1) — reaches the
   * application, as a `sipral_toggle_t`. **Off by default**, and then
   * every one is refused 403 before anything reads it: a peer that can
   * make a phone dial is a peer that can make it dial a premium-rate
   * number, and this stack authenticates no peer to tell the two
   * apart. On, each one is screened as an INVITE is and then raised as
   * `SIPRAL_EVENT_KIND_REFERRAL`, and the application takes it with
   * `sipral_call_accept_transfer` or refuses it with
   * `sipral_call_reject_transfer`, one request at a time.
   */
  referrals: number;
  /**
   * Whether an account behind a NAT keeps its registrar's UDP flow
   * open, as a `sipral_toggle_t`. **On by default.** An account is
   * behind a NAT when `SIPRAL_NAT_STUN`'s answer about the signalling
   * socket named an address that is not the socket's own; each such
   * account on a UDP transport then sends a double CRLF, alone in a
   * datagram, to its registrar every `registrar_keepalive_ms`, while
   * its registration holds a binding or is getting one. A NAT that
   * filters by address and port (RFC 4787 §5) lets the registrar's
   * INVITE in only while it remembers this end sending to it, and the
   * STUN refresh goes to the STUN server; without this, a call that
   * arrives minutes after the REGISTER is dropped at the NAT.
   * Registrars ignore the datagram (RFC 3261 §7.5). Nothing is sent
   * while the stack is suspended (`sipral_stack_suspending`), for a
   * stack with `SIPRAL_NAT_OFF`, or for an account STUN found on its
   * own address; `docs/06-nat.md` has the reasons.
   */
  registrar_keepalive: number;
  /**
   * How often, in milliseconds, or zero for twenty-five seconds (RFC
   * 5626 §4.4.2's interval for UDP). Each interval is drawn between
   * 80% and 100% of it. From 1 000 to 120 000 — past two minutes a
   * NAT that keeps to RFC 4787 REQ-5 may already have let the flow go
   * — and anything else is `SIPRAL_STATUS_INVALID_ARGUMENT`, as is a
   * figure with `registrar_keepalive` off, a value nothing would read.
   */
  registrar_keepalive_ms: Wide;
  /**
   * How every media socket reaches `turn_server`, as a
   * `sipral_transport_t`: `SIPRAL_TRANSPORT_UDP`, or zero for it;
   * `SIPRAL_TRANSPORT_TCP` for the network that blocks UDP outright;
   * `SIPRAL_TRANSPORT_TLS` for the one that lets one port out — 5349
   * is TURN's (RFC 8656 §4.1) — or for an application that wants the
   * server's certificate checked. The relay speaks UDP to the peer
   * whichever it is (§3.1). Over TCP or TLS the application opens a
   * connection per media socket when `SIPRAL_EVENT_KIND_TURN_STREAM`
   * asks, with the platform's own TLS as it does for SIP. Anything
   * else, or a value other than zero with no `turn_server`, is
   * `SIPRAL_STATUS_INVALID_ARGUMENT`.
   */
  turn_transport: number;
  /**
   * Who pumps this stack's audio: a `sipral_audio_t`. Zero, and
   * `SIPRAL_AUDIO_APPLICATION`, is the application, through
   * `sipral_media_capture` and `sipral_media_playback`, as every
   * stack was before this member existed. `SIPRAL_AUDIO_DEVICE` has
   * the library open the platform's devices and pump every managed
   * call itself — see the `sipral_audio_*` entry points — and needs
   * `audio_transmit_callback`. `SIPRAL_STATUS_NOT_SUPPORTED` on a
   * platform this build has no backend for, which
   * `SIPRAL_FEATURE_AUDIO_DEVICE` says first.
   */
  audio: number;
  /**
   * When the devices are opened, in device mode: a
   * `sipral_audio_activation_t`, or zero for
   * `SIPRAL_AUDIO_ACTIVATION_AUTOMATIC`.
   */
  audio_activation: number;
  /**
   * Where the packets the engine encodes go, in device mode: called
   * on the engine's thread with one `sipral_audio_transmit_t` per
   * packet, to be sent from the call's media socket. Required with
   * `SIPRAL_AUDIO_DEVICE`, ignored otherwise.
   */
  audio_transmit_callback: Pointer;
  /**
   * Handed back to `audio_transmit_callback` unread.
   */
  audio_transmit_user_data: Pointer;
  /**
   * How long a platform call about the devices may block before the
   * engine reports it as stuck, in milliseconds; zero for the
   * engine's own default of three seconds. A driver that has stopped
   * answering is answered `SIPRAL_STATUS_DEVICE_TIMED_OUT`, on a
   * thread the engine walks away from, rather than waited for.
   */
  audio_probe_ms: Wide;
  /**
   * The rate the devices are asked to run at, in device mode; zero
   * for 48000. Every call is resampled between its own rate and
   * this one, and a platform that answers with another rate is
   * taken at its word.
   */
  audio_device_rate_hz: number;
  /**
   * The most calls this stack holds at once, in either direction, or
   * zero for 128: a softphone's ceiling, well past what one person
   * can hold and well short of what a flood would make it keep. A
   * call counts from its INVITE on — one that arrives from the
   * moment it is let in, one placed here from the moment it is sent
   * — until it ends or is refused.
   *
   * An INVITE that arrives past it is answered `503 Service
   * Unavailable` before it rings, with `Retry-After: 2`: RFC 3261
   * §21.5.4 has a client that gets no `Retry-After` act as if it got a
   * 500, where this stack is full rather than broken, and room comes
   * back the moment any call ends, so the delay a proxy then keeps
   * away for is short. A call placed past it is
   * `SIPRAL_STATUS_LIMIT_REACHED` and nothing goes out. A media server
   * built on this library raises it to what its machine can carry,
   * with `max_server_transactions` beside it; `docs/19-numbers.md` has
   * what a call costs.
   */
  max_dialogs: number;
  /**
   * The most requests from other ends this stack works on at once —
   * its server transactions, RFC 3261 §17.2 — or zero for 256. Past
   * it a request that would start another is answered `503` at once,
   * statelessly and with no `Retry-After`, and every one already
   * under way is still answered. A request inside a call is held to
   * that call's own share instead, and a BYE never is.
   */
  max_server_transactions: number;
  /**
   * D1: how many decisions each call's diagnostic record keeps, or
   * zero for 64. Past it the oldest go and the record counts them.
   */
  diagnostic_decisions: number;
  /**
   * D1: how many calls have a diagnostic record at once, or zero for
   * 32; the endpoint's own record is kept besides them. Past it the
   * record written longest ago goes, and the stack counts it. Neither
   * of the two refuses anything: they bound what the records cost, a
   * quarter of a megabyte at the defaults. Every decision written
   * looks through the records for its call, so this one is best kept
   * in the hundreds even on a stack holding thousands of calls: the
   * calls a support case is about are the ones written most recently.
   */
  diagnostic_records: number;
  /**
   * When a call listens for keypad digits in the far end's audio, as a
   * sipral_dtmf_detection_t: zero
   * on exactly the calls that negotiated no telephone event, which is
   * when such a far end has no other way to send one.
   * `sipral_call_dtmf_detection` changes it for one call.
   *
   * Here rather than after `rtp_port_max`, where it was appended: six
   * four-byte members in a row keep the struct free of padding at its
   * end on a 64-bit target and on 32-bit ARM alike.
   */
  dtmf_detection: number;
  /**
   * The STUN servers to turn to, in this order, when `stun_server`
   * fails: `host:port` addresses separated by commas, not names.
   * Optional, and only beside a `stun_server`. A server fails when it
   * does not answer in five and a half seconds, or answers without an
   * address; every socket asking it moves to the next one at once,
   * and the one that failed is passed over for thirty seconds, then
   * twice as long each time it fails again, up to ten minutes. Only a
   * signalling socket's refresh goes back to a better server once its
   * time is up, so a call waiting for its media socket's address is
   * never spent on finding out. `SIPRAL_EVENT_KIND_STUN_SERVER` says
   * when the server in use moves, and when every one has failed.
   * Copied; the caller's buffer is its own again when this returns.
   */
  stun_fallbacks: Pointer;
  /**
   * How many bytes of it.
   */
  stun_fallbacks_len: number;
  /**
   * The lowest port of the range this stack hands RTP ports out of
   * (`sipral_stack_rtp_port_reserve`), or zero with `rtp_port_max`
   * for no range: the application picks every media port itself.
   *
   * RTP takes an even port and its RTCP the odd one above it (RFC 3550
   * §11), so an odd `rtp_port_min` starts at the port above it and an
   * even `rtp_port_max` is never handed out. A range that holds no
   * such pair, one given upside down, or one bound given without the
   * other is `SIPRAL_STATUS_INVALID_ARGUMENT`.
   */
  rtp_port_min: number;
  /**
   * The highest port of that range, or zero with `rtp_port_min`.
   */
  rtp_port_max: number;
  /**
   * The SRTP suites every call on this stack offers and accepts,
   * unless its account names its own
   * (`sipral_account_config_t::srtp_suites`): the names RFC 4568
   * section 6.2 and RFC 7714 section 14.2 give them, separated by
   * commas, most preferred first. Null for this build's own order
   * (ABI 0.34).
   *
   * An SDES offer names these, in this order, and an answer takes
   * the offerer's first that is among them; a DTLS-SRTP handshake
   * offers the ones with a protection profile. Every `a=crypto` line
   * is in the INVITE, so past two or three suites an offer over UDP
   * needs a stream (RFC 3261 section 18.1.1). A name this library
   * does not run, or one named twice, is
   * `SIPRAL_STATUS_INVALID_ARGUMENT`.
   */
  srtp_suites: Pointer;
  /**
   * How many bytes of it.
   */
  srtp_suites_len: number;
  /**
   * The MTU of the path toward the server, in bytes, when the
   * deployment knows it; zero for unknown (ABI 0.34). RFC 3261
   * section 18.1.1 moves a request to a stream when it comes within
   * 200 bytes of the MTU, and with the MTU unknown past 1300 bytes: a
   * path known to carry more lets a larger request stay on UDP. Under
   * 576 is `SIPRAL_STATUS_INVALID_ARGUMENT` — an IPv4 host must take
   * that much (RFC 791).
   */
  path_mtu: number;
  /**
   * The largest request to send over UDP anyway, once no stream to
   * its server can be had, in bytes; zero for never (ABI 0.34).
   *
   * **A deliberate deviation from RFC 3261 section 18.1.1**, for a
   * server that takes SIP over UDP alone: such a PBX answers nothing
   * to a request it cannot receive over a stream, and takes a
   * 1,444-byte INVITE over UDP from every other phone on its network.
   * A request past the section's line asks for a stream as always
   * (`SIPRAL_EVENT_KIND_TRANSPORT_WANTED`); once the application says
   * none is coming (`sipral_stack_transport_failed` on the number it
   * was going to bind) or the wait runs out, what was waiting goes
   * over UDP up to this size, and each such request is written to the
   * call's diagnostic record as `transport.kept.datagram` with its
   * size and this limit. A stream bound later is preferred again. A
   * request past this size ends as it would without it. At most
   * 65 507, what one UDP datagram carries over IPv4; a figure not past
   * the section's own line changes nothing.
   */
  datagram_without_stream_bytes: number;
  /**
   * A salt the application keeps for the installation, keying the
   * pseudonyms this stack's log and state text write for users,
   * numbers and addresses, so that the same value has the same
   * pseudonym in every run and two runs' traces compare line by line
   * (ABI 0.34). At least 16 bytes, drawn once from the platform's
   * generator; null for pseudonyms keyed from `media_seed`, which are
   * fresh every run. It is a secret like a key: whoever holds it can
   * test a guessed address against a pseudonym. Copied.
   */
  pseudonym_salt: Pointer;
  /**
   * How many bytes of it.
   */
  pseudonym_salt_len: number;
  /**
   * A `sipral_toggle_t`: whether the log's trace writes SIP messages
   * whole, with the peer they went to, instead of pseudonymised; off
   * by default (ABI 0.34). For a diagnosis only: every user, display
   * name, number and address is then written as it went on the wire.
   * What is never written, in either mode, is a credential or a key:
   * every `Authorization` and `Proxy-Authorization` value, every
   * `a=crypto` `inline:` key, every `k=` key, every `a=key-mgmt`
   * payload and every `a=ice-pwd` is taken out first, a field whose
   * name a control byte or a bare CR line end disguises included
   * (ABI 0.35 for the last two). `sipral_stack_diagnostic_trace`
   * turns it on and off while the stack runs.
   */
  diagnostic_trace: number;
  /**
   * Zero.
   */
  reserved: number;
  /**
   * A `sipral_toggle_t`: whether a stack in device mode opens the
   * devices behind the platform's own echo cancellation, where the
   * platform lets it be turned off; on by default (ABI 0.35). Off,
   * macOS and iOS run the voice-processing unit with its processing
   * bypassed, Windows opens a communications stream raw, past the
   * endpoint's processing, and Android opens the microphone with the
   * voice-recognition preset rather than the voice-communication one;
   * Linux has nothing to turn off. For a headset, which has no echo
   * to cancel, or an application that cancels it on each call itself.
   * `sipral_audio_info_t::system_echo_cancellation` says what the
   * platform did. Read only in device mode.
   */
  system_echo_cancellation: number;
  /**
   * Zero.
   */
  reserved_35: number;
  /**
   * A sipral_held_audio_t: what a party this end holds is sent while
   * the hold lasts (ABI 0.36). RFC 3264 §8.4 leaves the held stream
   * `sendonly`, so something goes on being sent. Zero is silence in
   * either mode: in application mode the frames handed
   * `sipral_media_capture` may be a microphone's as well, and the
   * room a party was put on hold from is not sent unless asked for.
   * `SIPRAL_HELD_AUDIO_APPLICATION` sends the frames the application
   * hands over as they are, for a voice agent or an application
   * playing its own hold music or announcement to the held party.
   */
  held_audio: number;
  /**
   * Zero.
   */
  reserved_36: number;
}
koffi.struct('sipral_stack_config_t', {
  size: 'size_t',
  event_callback: 'void *',
  event_user_data: 'void *',
  transport: 'sipral_transport_t',
  bind_address: 'void *',
  bind_address_len: 'size_t',
  user_agent: 'void *',
  user_agent_len: 'size_t',
  entropy: 'void *',
  entropy_len: 'size_t',
  timer_t1_ms: 'uint64_t',
  timer_t2_ms: 'uint64_t',
  timer_t4_ms: 'uint64_t',
  codecs: 'void *',
  codecs_len: 'size_t',
  frame_ms: 'uint32_t',
  offer_dtmf: 'sipral_toggle_t',
  offer_rtcp_mux: 'sipral_toggle_t',
  silence_suppression: 'sipral_toggle_t',
  media_stall_watchdog: 'sipral_toggle_t',
  media_stall_ms: 'uint64_t',
  media_clock_unix_seconds: 'uint64_t',
  media_seed: 'void *',
  media_seed_len: 'size_t',
  srtp: 'sipral_srtp_t',
  ice: 'sipral_ice_t',
  nat: 'sipral_nat_t',
  stun_server: 'void *',
  stun_server_len: 'size_t',
  g729_annex_b: 'sipral_toggle_t',
  turn_server: 'void *',
  turn_server_len: 'size_t',
  turn_username: 'void *',
  turn_username_len: 'size_t',
  turn_password: 'void *',
  turn_password_len: 'size_t',
  referrals: 'sipral_toggle_t',
  registrar_keepalive: 'sipral_toggle_t',
  registrar_keepalive_ms: 'uint64_t',
  turn_transport: 'sipral_transport_t',
  audio: 'sipral_audio_t',
  audio_activation: 'sipral_audio_activation_t',
  audio_transmit_callback: 'void *',
  audio_transmit_user_data: 'void *',
  audio_probe_ms: 'uint64_t',
  audio_device_rate_hz: 'uint32_t',
  max_dialogs: 'uint32_t',
  max_server_transactions: 'uint32_t',
  diagnostic_decisions: 'uint32_t',
  diagnostic_records: 'uint32_t',
  dtmf_detection: 'sipral_dtmf_detection_t',
  stun_fallbacks: 'void *',
  stun_fallbacks_len: 'size_t',
  rtp_port_min: 'uint32_t',
  rtp_port_max: 'uint32_t',
  srtp_suites: 'void *',
  srtp_suites_len: 'size_t',
  path_mtu: 'uint32_t',
  datagram_without_stream_bytes: 'uint32_t',
  pseudonym_salt: 'void *',
  pseudonym_salt_len: 'size_t',
  diagnostic_trace: 'sipral_toggle_t',
  reserved: 'uint32_t',
  system_echo_cancellation: 'sipral_toggle_t',
  reserved_35: 'uint32_t',
  held_audio: 'sipral_held_audio_t',
  reserved_36: 'uint32_t',
});

/**
 * What one call to sipral_stack_poll did.
 *
 * Set `size` to `sizeof(sipral_poll_result_t)` before the call.
 */
export interface SipralPollResult {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * Events handed to the callback during this poll.
   */
  events_delivered: number;
  /**
   * Events the stack raised that this ABI has no word for yet.
   *
   * Counted rather than delivered: an event carrying nothing a binding can
   * act on is noise, and a number that is not zero is the honest measure of
   * how far this vocabulary is behind the stack's.
   */
  events_unclaimed: number;
  /**
   * Bytes the stack produced and this build had nowhere to send.
   *
   * Zero since `sipral_stack_poll_transmit` gave them somewhere to go: what the stack
   * writes waits in it until `sipral_stack_poll_transmit` takes it, and a
   * poll no longer empties the queue on its way past. The member stays
   * because a released one always does, and because a build that has to drop
   * a message again would have somewhere to say so.
   */
  transmits_discarded: number;
  /**
   * Whether there is a deadline at all. Zero means nothing is scheduled and
   * the next poll can wait for input.
   */
  has_deadline: number;
  /**
   * How long from `now_ms` until the stack has something to do, when
   * `has_deadline` says there is one. Zero means it is already due.
   */
  next_poll_in_ms: Wide;
}
koffi.struct('sipral_poll_result_t', {
  size: 'size_t',
  events_delivered: 'size_t',
  events_unclaimed: 'size_t',
  transmits_discarded: 'size_t',
  has_deadline: 'uint32_t',
  next_poll_in_ms: 'uint64_t',
});

/**
 * What a stack is actually running with.
 *
 * A configuration call that answers `SIPRAL_STATUS_OK` has applied what it was
 * given, and this is where the caller reads back what that came to. It matters
 * because a zero in the config means "the default": a caller that left the
 * timers alone has no other way to learn which figures it is retransmitting
 * on, and one that set them has no other way to be sure.
 *
 * Set `size` to `sizeof(sipral_stack_settings_t)` before the call.
 */
export interface SipralStackSettings {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * The sipral_transport_t this stack speaks.
   */
  transport: number;
  /**
   * Whether this stack retransmits anything itself.
   *
   * Zero on a transport that delivers for us, which is every one but UDP.
   * The two timers that only exist to pace a retransmission read as their
   * defaults there, and mean nothing.
   */
  retransmits: number;
  /**
   * T1 in milliseconds, with the default filled in.
   */
  timer_t1_ms: Wide;
  /**
   * T2 in milliseconds, with the default filled in.
   */
  timer_t2_ms: Wide;
  /**
   * T4 in milliseconds, with the default filled in.
   */
  timer_t4_ms: Wide;
  /**
   * How many codecs this stack offers. `sipral_stack_codec_order` says
   * which, and in what order.
   */
  codec_count: number;
  /**
   * How long a frame is, with the default filled in.
   */
  frame_ms: number;
  /**
   * Whether named events are offered, as a `sipral_toggle_t`. Never the
   * default value: this says what the setting came to, not what was passed.
   */
  offer_dtmf: number;
  /**
   * Whether RTCP multiplexing is asked for, as a `sipral_toggle_t`.
   */
  offer_rtcp_mux: number;
  /**
   * Whether sending stops during silence, as a `sipral_toggle_t`.
   */
  silence_suppression: number;
  /**
   * How long inbound audio may stop before it is reported, with the default
   * filled in. Zero when the watchdog is off, which is the one case where
   * there is no figure to give.
   */
  media_stall_ms: Wide;
  /**
   * Whether G.729's Annex B is allowed, as a `sipral_toggle_t`, with the
   * default filled in.
   */
  g729_annex_b: number;
  /**
   * Whether a REFER outside any dialog reaches the application, as a
   * `sipral_toggle_t`, with the default — off — filled in.
   */
  referrals: number;
  /**
   * How often an account behind a NAT sends to its registrar, in
   * milliseconds, with the default filled in. Zero when
   * `registrar_keepalive` was turned off, which is the one case where
   * there is no figure to give.
   */
  registrar_keepalive_ms: Wide;
  /**
   * The most calls the stack holds at once, with the default filled
   * in.
   */
  max_dialogs: number;
  /**
   * The most server transactions it works on at once, with the
   * default filled in.
   */
  max_server_transactions: number;
  /**
   * How many decisions a diagnostic record keeps, with the default
   * filled in.
   */
  diagnostic_decisions: number;
  /**
   * How many diagnostic records the stack keeps, with the default
   * filled in.
   */
  diagnostic_records: number;
  /**
   * The RTP port range, as given; both zero for none.
   */
  rtp_port_min: number;
  /**
   * See `rtp_port_min`.
   */
  rtp_port_max: number;
  /**
   * The path MTU as given, zero for unknown (ABI 0.34).
   */
  path_mtu: number;
  /**
   * The largest request sent over UDP once no stream is coming, as
   * given; zero for never (ABI 0.34).
   */
  datagram_without_stream_bytes: number;
  /**
   * How many SRTP suites the stack's calls offer and accept unless
   * their account names its own: the ones `srtp_suites` named, or
   * this build's own. `sipral_stack_srtp_suite_order` says which, in
   * order (ABI 0.35).
   */
  srtp_suite_count: number;
  /**
   * A `sipral_toggle_t`: whether the stack was given a `pseudonym_salt`,
   * so that its pseudonyms are the same from run to run. The salt
   * itself is never read back (ABI 0.35).
   */
  pseudonym_salted: number;
  /**
   * A `sipral_toggle_t`: whether the trace writes whole messages now,
   * as `diagnostic_trace` set it at creation or
   * `sipral_stack_diagnostic_trace` since (ABI 0.35).
   */
  diagnostic_trace: number;
  /**
   * A `sipral_toggle_t`: whether the platform's echo cancellation is
   * asked for, with the default filled in (ABI 0.35), as
   * `sipral_audio_set_system_echo_cancellation` left it (ABI 1.1).
   */
  system_echo_cancellation: number;
}
koffi.struct('sipral_stack_settings_t', {
  size: 'size_t',
  transport: 'sipral_transport_t',
  retransmits: 'uint32_t',
  timer_t1_ms: 'uint64_t',
  timer_t2_ms: 'uint64_t',
  timer_t4_ms: 'uint64_t',
  codec_count: 'size_t',
  frame_ms: 'uint32_t',
  offer_dtmf: 'sipral_toggle_t',
  offer_rtcp_mux: 'sipral_toggle_t',
  silence_suppression: 'sipral_toggle_t',
  media_stall_ms: 'uint64_t',
  g729_annex_b: 'sipral_toggle_t',
  referrals: 'sipral_toggle_t',
  registrar_keepalive_ms: 'uint64_t',
  max_dialogs: 'uint32_t',
  max_server_transactions: 'uint32_t',
  diagnostic_decisions: 'uint32_t',
  diagnostic_records: 'uint32_t',
  rtp_port_min: 'uint32_t',
  rtp_port_max: 'uint32_t',
  path_mtu: 'uint32_t',
  datagram_without_stream_bytes: 'uint32_t',
  srtp_suite_count: 'uint32_t',
  pseudonym_salted: 'sipral_toggle_t',
  diagnostic_trace: 'sipral_toggle_t',
  system_echo_cancellation: 'sipral_toggle_t',
});

/**
 * One header field an application hands over: a name and a value, UTF-8,
 * neither NUL-terminated.
 *
 * Always an element of an array whose length travels beside it, which is
 * why it carries no `size`: an array is strided by the length of its
 * element, so a member appended here would move every element after the
 * first. A header field is a name and a value, and this never grows.
 */
export interface SipralHeader {
  /**
   * The field name, `X-Conversation-Id`. A compact form is the field it
   * abbreviates.
   */
  name: Pointer;
  /**
   * How many bytes of it.
   */
  name_len: number;
  /**
   * The value, as it goes on the line after the colon. Null or empty
   * for a field with an empty value.
   */
  value: Pointer;
  /**
   * How many bytes of it.
   */
  value_len: number;
}
koffi.struct('sipral_header_t', {
  name: 'void *',
  name_len: 'size_t',
  value: 'void *',
  value_len: 'size_t',
});

/**
 * What an account is configured with.
 *
 * Set `size` to `sizeof(sipral_account_config_t)` and zero the rest before
 * filling anything in.
 */
export interface SipralAccountConfig {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * The address of record, `sip:alice@example.com`. UTF-8, not
   * NUL-terminated.
   */
  aor: Pointer;
  /**
   * How many bytes of it.
   */
  aor_len: number;
  /**
   * Where the REGISTER is addressed, `sip:example.com`, no user part.
   *
   * A `registrar_len` of zero makes an account that never registers: a
   * trunk that knows this end by the address its requests come from.
   * Its state is `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING` for as long
   * as it exists, and `sipral_account_register` refuses it.
   */
  registrar: Pointer;
  /**
   * How many bytes of it.
   */
  registrar_len: number;
  /**
   * Where this endpoint can be reached, as it goes in `Contact`.
   */
  contact: Pointer;
  /**
   * How many bytes of it.
   */
  contact_len: number;
  /**
   * Where this account's requests go, as `host:port`: the registrar's
   * address for an account that registers, and the outbound proxy for
   * one configured with no registrar. A call that names no destination
   * of its own goes here either way, so it is required unless
   * `server_uri` names the server instead. An address, not a name: a
   * server known by name is `server_uri`'s.
   */
  registrar_address: Pointer;
  /**
   * How many bytes of it.
   */
  registrar_address_len: number;
  /**
   * The display name that goes in `From`, or null for none.
   */
  display_name: Pointer;
  /**
   * How many bytes of it.
   */
  display_name_len: number;
  /**
   * The user name to answer a challenge with, or null for an account that
   * answers none.
   */
  auth_user: Pointer;
  /**
   * How many bytes of it.
   */
  auth_user_len: number;
  /**
   * The password that goes with it. Copied out of the caller's memory; what
   * happens to the caller's copy is the caller's.
   */
  auth_password: Pointer;
  /**
   * How many bytes of it.
   */
  auth_password_len: number;
  /**
   * The `+sip.instance` URN of RFC 5626 §4.1, or null for none.
   */
  instance_id: Pointer;
  /**
   * How many bytes of it.
   */
  instance_id_len: number;
  /**
   * How long a binding to ask for, or zero for an hour.
   *
   * A `delta-seconds`, so §20.19 bounds it at 2³²−1 and anything above that
   * is refused rather than sent as a number no registrar will read. What the
   * registrar grants wins over the request either way, and the granted
   * figure is what `sipral_registration_event_t::expires_ms` carries — that
   * is where the effective value is read back, not here.
   */
  expires_seconds: Wide;
  /**
   * Header fields to put on every REGISTER this account sends, in the
   * order given, or null for none.
   *
   * Checked when the account is added, as `sipral_call_config_t::headers`
   * is, against what the stack writes on a REGISTER: `Expires` is the
   * stack's there, because it is `expires_seconds`, and `Supported` is the
   * application's, because a registration asking for a GRUU has to say
   * so. Refused for an account with no registrar, which sends no REGISTER
   * to put them on.
   */
  headers: Pointer;
  /**
   * How many elements `headers` has.
   */
  headers_len: number;
  /**
   * Which transport this account's REGISTER and every request it
   * places go out on: SIPRAL_TRANSPORT_MAIN
   * for zero, which is what a caller that leaves this at zero already
   * gets, or a further number
   * sipral_stack_transport_bind
   * has bound. A number this stack has never bound is
   * `SIPRAL_STATUS_INVALID_ARGUMENT`, naming it.
   */
  transport: number;
  /**
   * The push notification service to be woken through, as its
   * registered name: `apns`, `fcm`, `webpush` (RFC 8599 §4.1.1). Null
   * for an account that is not woken by push, which is every account on
   * a machine that does not suspend.
   *
   * These four go on the `Contact` of this account's REGISTER and on no
   * other request, ever: §4.1 says so because a `pn-prid` in the
   * `Contact` of an INVITE hands the far end a token that wakes this
   * device whenever it likes. The de-registration that gives the binding
   * up leaves the identifier out, which §4.1.2 also requires.
   */
  push_provider: Pointer;
  /**
   * How many bytes of it.
   */
  push_provider_len: number;
  /**
   * The resource identifier the service issued for this installation —
   * the device token. Required when `push_provider` is given, and
   * refused without one.
   *
   * Whatever it holds is percent-escaped where the SIP grammar needs it
   * (§8.7), because an APNs token carries `=` and a Web Push identifier
   * is a whole URL.
   */
  push_prid: Pointer;
  /**
   * How many bytes of it.
   */
  push_prid_len: number;
  /**
   * The extra value a service needs beside the identifier: the
   * application bundle for Apple, the sender for Firebase. §4.1.1 makes
   * it mandatory "if required for the specific PNS", so it is optional
   * here and the service decides.
   */
  push_param: Pointer;
  /**
   * How many bytes of it.
   */
  push_param_len: number;
  /**
   * Nonzero to say this device can send a binding refresh without being
   * woken by a push, which §4.1.4 makes it declare with a
   * `+sip.pnsreg` media feature tag.
   *
   * It is the application's fact and not this library's to guess: a
   * process the operating system has suspended has no timer that runs,
   * and one that claims otherwise gets a registrar that stops sending
   * the wake-ups the device is relying on.
   */
  push_wakes_itself: number;
  /**
   * Where this account's end-of-call voice quality reports go (RFC
   * 6035, carried by a PUBLISH, RFC 3903), or null to send none.
   */
  quality_report_uri: Pointer;
  /**
   * How many bytes of it.
   */
  quality_report_uri_len: number;
  /**
   * A sipral_session_timer_t: how
   * this account's calls ask for a session timer (RFC 4028). Zero is
   * the stack's default, thirty minutes.
   */
  session_timer: number;
  /**
   * The interval to ask for under `SIPRAL_SESSION_TIMER_INTERVAL`, in
   * seconds: at least 90, RFC 4028 §5's floor. Read for nothing else.
   */
  session_interval_seconds: Wide;
  /**
   * `SIPRAL_PRIVACY_*` bits: place every call from this account
   * anonymously (RFC 3323), asking for these. `SIPRAL_PRIVACY_ID` is
   * "withhold my number". `From` becomes `"Anonymous"
   * <sip:anonymous@anonymous.invalid>`, `Privacy` carries the bits,
   * and the account's own identity goes in `P-Asserted-Identity` only
   * toward a peer in `trusted_peers`. Zero asks for none.
   */
  privacy: number;
  /**
   * The peers this account trusts (RFC 3325's trust domain), as IP
   * addresses separated by commas: usually the registrar or the trunk.
   * A call arriving from one of them has its asserted identity read
   * (`sipral_call_event_t::asserted_uri`); from anywhere else it is
   * left out. And once any are named, a call placed toward any other
   * peer carries no `P-Asserted-Identity` or `P-Preferred-Identity`,
   * whoever wrote it. Null and zero trusts nobody.
   */
  trusted_peers: Pointer;
  /**
   * How many bytes of it.
   */
  trusted_peers_len: number;
  /**
   * A `sipral_srtp_t`: what this account's calls do about SRTP, over the
   * stack's own `srtp` — offered, required, DTLS-SRTP, or DTLS-SRTP
   * falling back to SDES — or zero for the stack's. A call placed from
   * it may name a stricter policy of its own and never a looser one
   * (`SIPRAL_STATUS_SECURITY_POLICY`), and an INVITE it cannot answer
   * under it is refused with 488. ABI 0.31, like every member below.
   */
  srtp: number;
  /**
   * The SRTP suites this account's calls run, most preferred first,
   * as RFC 4568 §6.2 and RFC 7714 §14.2 name them and separated by
   * commas: `AEAD_AES_256_GCM,AES_CM_128_HMAC_SHA1_80`. The `a=crypto`
   * lines an SDES offer carries, the lines an SDES answer takes, and
   * the DTLS-SRTP profiles a handshake offers and accepts — GCM among
   * them only if named. Null for this build's own. Every line is in
   * the INVITE: past two or three over UDP it needs a stream.
   */
  srtp_suites: Pointer;
  /**
   * How many bytes of it.
   */
  srtp_suites_len: number;
  /**
   * A `sipral_stir_verification_t`: what this account does with the
   * `Identity` header fields of the calls it receives (RFC 8224 §6.2).
   * Zero reports, once `sipral_stack_stir` has given the stack trust
   * anchors.
   */
  stir_verification: number;
  /**
   * The P-256 private key this account signs its calls with (RFC 8224
   * §6.1): the bare 32-octet scalar, or an `EC PRIVATE KEY` or
   * `PRIVATE KEY` in DER or PEM. Null and zero signs nothing. Needs the
   * wall clock `sipral_stack_stir` gives the stack in `unix_seconds`;
   * `SIPRAL_STATUS_WRONG_STATE` without it.
   */
  stir_key: Pointer;
  /**
   * How many bytes of it.
   */
  stir_key_len: number;
  /**
   * Where the certificate chain for `stir_key` is published: the
   * `x5u` and `info` of every PASSporT this account signs. Required
   * with `stir_key`, and only with it.
   */
  stir_certificate_url: Pointer;
  /**
   * How many bytes of it.
   */
  stir_certificate_url_len: number;
  /**
   * The telephone number this account signs as, canonicalised by
   * RFC 8224 §8.3's first step, or null for the number in `aor`'s user
   * part.
   */
  stir_orig: Pointer;
  /**
   * How many bytes of it.
   */
  stir_orig_len: number;
  /**
   * The origination identifier every call it signs claims (RFC 8588
   * §5), a UUID, or null for one the stack draws for the account.
   */
  stir_origid: Pointer;
  /**
   * How many bytes of it.
   */
  stir_origid_len: number;
  /**
   * A `sipral_attestation_t`: the level it claims (RFC 8588 §4), zero for
   * full attestation, `A`.
   */
  stir_attestation: number;
  /**
   * A `sipral_toggle_t`: whether an encrypted call of this account may be
   * recorded to a recording server (`sipral_call_record_to`) in the
   * clear. Off by default: the copies of an encrypted call are offered
   * to the server as SRTP, with SDES keys in the recording session's
   * offer (RFC 4568), and a stream the server will not take that way
   * gets nothing (RFC 7866 §12.2). On, they go as plain RTP, as an
   * unencrypted call's always do. ABI 0.32.
   *
   * Sixty-four bits wide, where every other toggle takes thirty-two,
   * so that it starts past the 384 bytes of ABI 0.31: the last four
   * of those were padding, which a caller built against that header
   * may have left unwritten, and are never read.
   */
  recording_in_clear: Wide;
  /**
   * How often, in milliseconds, this account keeps its flow to its
   * registrar — to its outbound proxy, for one that never registers —
   * open, whatever STUN found; zero for never, which leaves it to
   * `sipral_stack_config_t::registrar_keepalive` (ABI 0.34).
   *
   * For a network whose NAT forgets a UDP flow sooner than the
   * REGISTER refresh comes round, with STUN off. On UDP a double CRLF
   * goes out alone in a datagram, which a registrar ignores (RFC 3261
   * §7.5); on TCP or TLS the connection is pinged at this interval
   * instead of the stack's own (RFC 5626 §4.4.1). Each interval is
   * drawn between 80% and 100% of it. From 1 000 to 120 000, and
   * anything else is `SIPRAL_STATUS_INVALID_ARGUMENT`.
   */
  keepalive_ms: Wide;
  /**
   * The server this account's requests go to, as a URI whose host RFC
   * 3263 locates — `sip:pbx.example.com`, `sips:example.com:5061` —
   * in place of `registrar_address`: exactly one of the two is given
   * (ABI 0.34). The registrar for an account that registers (usually
   * the same URI as `registrar`), the outbound proxy for one that
   * does not.
   *
   * The lookups are the application's resolver's, asked for with
   * `SIPRAL_EVENT_KIND_LOOKUP_WANTED` and answered with
   * `sipral_account_looked_up`; the order they go in, the SRV ranking
   * and the fallback to the host's own addresses are the stack's.
   * The first REGISTER waits for the first answer, and a call placed
   * before it with no `destination` of its own is
   * `SIPRAL_STATUS_WRONG_STATE`. A request outside a dialog — REGISTER,
   * INVITE, MESSAGE, SUBSCRIBE, PUBLISH — that times out, whose
   * transport fails or that is answered 503 moves to the next address
   * found at once (§4.3; every request but REGISTER from ABI 0.35);
   * the name is looked up again when the
   * answer's time-to-live runs out, and when the stack's recovery
   * asks for an address. A host with a port skips SRV, and a numeric
   * host asks nothing.
   */
  server_uri: Pointer;
  /**
   * How many bytes of it.
   */
  server_uri_len: number;
  /**
   * The SHA-256 fingerprint of the one TLS server certificate this
   * account trusts, in place of a trust anchor, for a PBX that serves
   * a certificate it signed itself (ABI 0.34): 64 hexadecimal digits,
   * either case, colons and spaces among them ignored, bare or after
   * `sha256 Fingerprint=` (what `openssl x509 -fingerprint -sha256`
   * prints, 3.x and 1.1), `sha-256 ` (RFC 8122) or `SHA256=`, each
   * prefix in any case (ABI 0.35 for the first and the spaces).
   * Anything else is `SIPRAL_STATUS_INVALID_ARGUMENT`. Null for none.
   *
   * TLS is the application's, so this is what its certificate
   * verifier asks, with `sipral_account_check_certificate`: with a
   * pin, the fingerprint is the whole verdict, and no chain, trust
   * anchor or host name is consulted (`docs/22-tls.md`).
   */
  tls_pin_sha256: Pointer;
  /**
   * How many bytes of it.
   */
  tls_pin_sha256_len: number;
  /**
   * A `sipral_toggle_t`: whether `server_uri`'s domain is asked for NAPTR
   * records before SRV (RFC 3263 §4.1). Off by default: most domains
   * publish none, and the account's transport is already chosen.
   * Refused without a `server_uri` (ABI 0.34).
   */
  server_naptr: number;
  /**
   * Zero.
   */
  reserved: number;
  /**
   * A sipral_transport_t: the protocol
   * of a connection of this account's own to its server, which the
   * stack asks the application to open, or zero for none (ABI 0.35).
   *
   * For an account on TCP or TLS to one server beside an account on
   * the stack's UDP transport to another, in one stack with one audio
   * engine. With `SIPRAL_TRANSPORT_TCP`, `_TLS`, `_WS` or `_WSS` the
   * stack raises `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` naming the
   * protocol and the server's address — `request_bytes` and
   * `limit_bytes` zero, since no request outgrew anything — and the
   * account's requests go over whichever transport of that protocol
   * the application binds to that address with
   * `sipral_stack_transport_bind`, under any number; one bound before
   * the account is added is used as it stands. Until then its
   * REGISTER waits; ten seconds after the question it fails as
   * unreachable and its retry, after the usual back-off, asks again.
   * An account that never registers asks when it is added, and any
   * account asks again at once when its connection fails or closes —
   * a registered one by registering again. A call placed before the
   * connection is bound is `SIPRAL_STATUS_TRANSPORT_DOWN`. Every
   * request inside the account's calls keeps the connection their
   * INVITE went over, and a request arriving over it is matched to
   * this account before any other with the same user. `transport` is
   * then where the account starts, and is replaced by the connection
   * once there is one. `SIPRAL_TRANSPORT_UDP` only says what
   * `transport` speaks.
   */
  stream_protocol: number;
  /**
   * Zero.
   */
  reserved_35: number;
  /**
   * The realms the password answers, each on a line of its own,
   * separated by line feeds (a realm may hold a comma, and never a
   * line break), or null for the default (ABI 0.36).
   *
   * The password answers the account's own server and nobody else
   * (RFC 3261 §22.1). With none named the account takes the realms
   * its server first challenges it with, and every realm its
   * registrar challenges a REGISTER with, and answers those and no
   * others: a proxy passing on a far end's own 401 under a realm of
   * its choosing gets nothing, and `SIPRAL_EVENT_KIND_CHALLENGE_DECLINED`
   * says so. A server whose calls are challenged under a realm its
   * REGISTERs never meet — an SBC or an outbound proxy at the
   * registrar's address with a realm of its own — needs both named
   * here; named, these and no others are answered, REGISTERs
   * included. An empty line is skipped; a realm is compared exactly,
   * case included, as RFC 3261 §22.1 compares it.
   */
  realms: Pointer;
  /**
   * How many bytes of it.
   */
  realms_len: number;
}
koffi.struct('sipral_account_config_t', {
  size: 'size_t',
  aor: 'void *',
  aor_len: 'size_t',
  registrar: 'void *',
  registrar_len: 'size_t',
  contact: 'void *',
  contact_len: 'size_t',
  registrar_address: 'void *',
  registrar_address_len: 'size_t',
  display_name: 'void *',
  display_name_len: 'size_t',
  auth_user: 'void *',
  auth_user_len: 'size_t',
  auth_password: 'void *',
  auth_password_len: 'size_t',
  instance_id: 'void *',
  instance_id_len: 'size_t',
  expires_seconds: 'uint64_t',
  headers: 'void *',
  headers_len: 'size_t',
  transport: 'uint32_t',
  push_provider: 'void *',
  push_provider_len: 'size_t',
  push_prid: 'void *',
  push_prid_len: 'size_t',
  push_param: 'void *',
  push_param_len: 'size_t',
  push_wakes_itself: 'uint32_t',
  quality_report_uri: 'void *',
  quality_report_uri_len: 'size_t',
  session_timer: 'sipral_session_timer_t',
  session_interval_seconds: 'uint64_t',
  privacy: 'uint32_t',
  trusted_peers: 'void *',
  trusted_peers_len: 'size_t',
  srtp: 'sipral_srtp_t',
  srtp_suites: 'void *',
  srtp_suites_len: 'size_t',
  stir_verification: 'sipral_stir_verification_t',
  stir_key: 'void *',
  stir_key_len: 'size_t',
  stir_certificate_url: 'void *',
  stir_certificate_url_len: 'size_t',
  stir_orig: 'void *',
  stir_orig_len: 'size_t',
  stir_origid: 'void *',
  stir_origid_len: 'size_t',
  stir_attestation: 'sipral_attestation_t',
  recording_in_clear: 'uint64_t',
  keepalive_ms: 'uint64_t',
  server_uri: 'void *',
  server_uri_len: 'size_t',
  tls_pin_sha256: 'void *',
  tls_pin_sha256_len: 'size_t',
  server_naptr: 'sipral_toggle_t',
  reserved: 'uint32_t',
  stream_protocol: 'sipral_transport_t',
  reserved_35: 'uint32_t',
  realms: 'void *',
  realms_len: 'size_t',
});

/**
 * What a call is placed with.
 *
 * Set `size` to `sizeof(sipral_call_config_t)` and zero the rest before
 * filling anything in.
 */
export interface SipralCallConfig {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * Who to call, as a URI. UTF-8, not NUL-terminated.
   */
  target: Pointer;
  /**
   * How many bytes of it.
   */
  target_len: number;
  /**
   * The session description to offer, for a call this stack manages no
   * audio for.
   *
   * Exactly one of this and `media_address` is set. Two descriptions of one
   * session is one too many, and neither is a call whose answer would have
   * to be written into the ACK.
   */
  sdp: Pointer;
  /**
   * How many bytes of it.
   */
  sdp_len: number;
  /**
   * Where to send the INVITE, as `host:port`, or null to send it where the
   * account registers — which is the outbound proxy for a registered line,
   * and the reason a phone behind a NAT works at all.
   */
  destination: Pointer;
  /**
   * How many bytes of it.
   */
  destination_len: number;
  /**
   * Whether to keep every branch a proxy forks the INVITE into. Zero keeps
   * the first that answers and hangs up the rest, which is what a telephone
   * does.
   */
  keep_all_forks: number;
  /**
   * Where this end will receive media, as `host:port`, for a call this
   * stack describes and runs the audio of.
   *
   * The application owns the socket, so it is the only one that can say. Set
   * it and the offer is written from this stack's codec order, the answer is
   * read, and the call gets a media session that the `sipral_media_*`
   * entry points reach. Leave it null and set `sdp` instead for a call
   * where the application describes its own session and runs its own RTP.
   */
  media_address: Pointer;
  /**
   * How many bytes of it.
   */
  media_address_len: number;
  /**
   * Header fields to put on the INVITE, in the order given, or null for
   * none.
   *
   * Each is checked before anything is built: the name a token, the value
   * one line of text, and not a field the stack writes on a call itself.
   * Those are listed in `docs/04-ua.md` with the reason for each, and
   * `User-Agent` joins them when `sipral_stack_config_t::user_agent` is
   * set. A refusal is `SIPRAL_STATUS_INVALID_ARGUMENT` naming the element,
   * and no call.
   */
  headers: Pointer;
  /**
   * How many elements `headers` has.
   */
  headers_len: number;
  /**
   * What this call does about SRTP, overriding
   * `sipral_stack_config_t::srtp` for it: a `sipral_srtp_t`, or zero to
   * take the stack's own setting. Any other value is
   * `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
   *
   * Read only for a call this stack describes the media of —
   * `media_address` set — and otherwise not this ABI's to act on: a
   * call placed with `sdp` is a session the application wrote, and
   * SRTP in it is the application's own line to write or not.
   */
  srtp: number;
  /**
   * Which transport the INVITE goes out on, read only together with
   * `destination`: SIPRAL_TRANSPORT_MAIN
   * for zero, or a further number
   * sipral_stack_transport_bind
   * has bound. Nonzero with `destination` null is
   * `SIPRAL_STATUS_INVALID_ARGUMENT`: a call with no destination
   * override already goes out on its account's own transport, and
   * there is nothing to combine this with.
   */
  transport: number;
  /**
   * What this call offers and in what order, overriding
   * `sipral_stack_config_t::codecs` for it: codec names separated by
   * commas, as `sipral_codec_info_t::name` spells them, UTF-8 and not
   * NUL-terminated. Null for the stack's own order.
   *
   * Everything else the stack's catalogue carries — frame length,
   * named events, multiplexing, and SRTP where `srtp` here does not
   * override it — is kept, because a call that names its codecs has
   * said nothing about any of those. A name this build has no encoder
   * for, a name given twice, and a stray comma are each
   * `SIPRAL_STATUS_INVALID_ARGUMENT` naming what was wrong, and no
   * call.
   *
   * Read only for a call this stack describes the media of —
   * `media_address` set — for the reason `srtp` gives: a call placed
   * with `sdp` is a session the application wrote, and the order in it
   * is already the application's own. The names are still checked, so
   * that a caller who has one wrong learns it here either way.
   */
  codecs: Pointer;
  /**
   * How many bytes of it.
   */
  codecs_len: number;
  /**
   * What this call does about ICE, overriding
   * `sipral_stack_config_t::ice` for it: a `sipral_ice_t`, or zero to
   * take the stack's own setting. Any other value is
   * `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
   *
   * Read only for a call this stack describes the media of —
   * `media_address` set — for the reason `srtp` gives: a call placed
   * with `sdp` is a session the application wrote, and the candidates
   * in it are already the application's own to write or not.
   */
  ice: number;
  /**
   * Where this call's real-time text arrives (RFC 4103): a second
   * socket the application bound, as an address and a port. Set, the
   * offer or answer carries an `m=text` stream for T.140 with its
   * redundancy, and once both ends agree it `sipral_media_send_text`,
   * `sipral_media_poll_text` and `sipral_media_receive_text` carry
   * it. Null for a call with no text. Not NUL-terminated.
   *
   * Read only with `media_address`, and not offered on a call keyed
   * by SRTP or DTLS-SRTP or gathering ICE: the text stream has no key
   * and no candidates of its own, and typed text sent in the clear
   * beside encrypted audio is worse than none.
   */
  text_address: Pointer;
  /**
   * How many bytes of it.
   */
  text_address_len: number;
  /**
   * Whether this call asks for RTCP feedback: a `sipral_toggle_t`. On
   * offers RTP/AVPF (RFC 4585) with Generic NACKs and reduced-size
   * RTCP (RFC 5506), and runs RFC 4585's timing when the answer takes
   * it; zero leaves it off, as it is by default, because a far end
   * that knows only RTP/AVP refuses a profile it does not know. Read
   * only with `media_address`. An offer on a feedback profile is
   * answered on that profile whatever this says, since RFC 4585 §4.1
   * leaves an answerer no other way to take the stream; the Generic
   * NACKs and reduced-size RTCP it asks for are agreed only when this
   * is on, on the answer too.
   */
  feedback: number;
  /**
   * Nonzero to say this end is the focus of a conference (RFC 4579
   * §3.3): `isfocus` goes on the Contact of every message this call
   * sends from here on.
   */
  focus: number;
}
koffi.struct('sipral_call_config_t', {
  size: 'size_t',
  target: 'void *',
  target_len: 'size_t',
  sdp: 'void *',
  sdp_len: 'size_t',
  destination: 'void *',
  destination_len: 'size_t',
  keep_all_forks: 'uint32_t',
  media_address: 'void *',
  media_address_len: 'size_t',
  headers: 'void *',
  headers_len: 'size_t',
  srtp: 'sipral_srtp_t',
  transport: 'uint32_t',
  codecs: 'void *',
  codecs_len: 'size_t',
  ice: 'sipral_ice_t',
  text_address: 'void *',
  text_address_len: 'size_t',
  feedback: 'sipral_toggle_t',
  focus: 'uint32_t',
});

/**
 * One codec this build contains.
 *
 * Set `size` to `sizeof(sipral_codec_info_t)` before the call.
 */
export interface SipralCodecInfo {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * A sipral_codec_t.
   */
  codec: number;
  /**
   * The RTP timestamp clock, in hertz, which is what goes on the
   * `a=rtpmap` line.
   */
  clock_rate: number;
  /**
   * The rate the codec actually hears at, which is what the samples crossing
   * this ABI are in. G.722's two differ, and RFC 3551 §4.5.2 says so.
   */
  sample_rate: number;
  /**
   * The payload type RFC 3551 table 4 assigns it, when it has one.
   */
  static_payload_type: number;
  /**
   * Whether it has one. Opus does not: it is newer than the table and
   * always travels as a dynamic type.
   */
  has_static_payload_type: number;
  /**
   * Zero. Rounds the struct up to a whole multiple of its alignment on
   * every target, so that a member a later version appends starts at or
   * past the length a caller built against this header declares, never
   * in padding inside it. The library writes zero here and reads nothing
   * from it.
   */
  reserved: number;
}
koffi.struct('sipral_codec_info_t', {
  size: 'size_t',
  codec: 'sipral_codec_t',
  clock_rate: 'uint32_t',
  sample_rate: 'uint32_t',
  static_payload_type: 'uint32_t',
  has_static_payload_type: 'uint32_t',
  reserved: 'uint32_t',
});

/**
 * One codec this call could have used, and what became of it.
 *
 * Set `size` to `sizeof(sipral_codec_candidate_t)` before the call.
 *
 * The list is what the negotiation itself decided, kept from the moment
 * it decided it. It is not worked out again when it is asked for, because
 * a second run against a description that has since been renegotiated
 * would disagree with the first in exactly the case somebody is
 * debugging.
 */
export interface SipralCodecCandidate {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * A sipral_codec_t: the candidate itself.
   */
  codec: number;
  /**
   * A sipral_codec_outcome_t: what became of it.
   */
  outcome: number;
  /**
   * A sipral_codec_t: what beat it, when `outcome` is
   * `SIPRAL_CODEC_OUTCOME_OUTRANKED`. `SIPRAL_CODEC_UNKNOWN`
   * otherwise, because nothing beat a codec that was never named and
   * nothing beat the one that won.
   */
  outranked_by: number;
  /**
   * Zero. Rounds the struct up to a whole multiple of its alignment on
   * every target, so that a member a later version appends starts at or
   * past the length a caller built against this header declares, never
   * in padding inside it. The library writes zero here and reads nothing
   * from it.
   */
  reserved: number;
}
koffi.struct('sipral_codec_candidate_t', {
  size: 'size_t',
  codec: 'sipral_codec_t',
  outcome: 'sipral_codec_outcome_t',
  outranked_by: 'sipral_codec_t',
  reserved: 'uint32_t',
});

/**
 * One path a call's ICE agent tried — a candidate pair it checked, or a
 * relay it held — and what became of it, with its two addresses written
 * into the caller's own buffers.
 *
 * The caller fills in `size`, the two pointers and the two capacities;
 * the library fills in the rest. A pointer left null with a capacity of
 * zero is an address the caller does not want. Written down by the
 * agent as each outcome happened, never worked out again when it is
 * asked for: RFC 8445 §8.1.2 takes the losing pairs off the checklist
 * the moment one is selected.
 */
export interface SipralPathCandidate {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * The pair's priority (RFC 8445 §6.1.2.3), as this end's role
   * computes it; zero for a relay.
   */
  priority: Wide;
  /**
   * A sipral_path_kind_t.
   */
  kind: number;
  /**
   * A sipral_path_outcome_t.
   */
  outcome: number;
  /**
   * For `SIPRAL_PATH_OUTCOME_REFUSED`, the STUN error code the far end
   * answered with; for `SIPRAL_PATH_OUTCOME_RELAY_REFUSED` and
   * `SIPRAL_PATH_OUTCOME_LOST`, the TURN server's, zero when it gave
   * none. Zero otherwise.
   */
  code: number;
  /**
   * A sipral_candidate_kind_t: what `local` is.
   */
  local_kind: number;
  /**
   * A sipral_candidate_kind_t: what `remote` is, when it is a
   * candidate at all.
   */
  remote_kind: number;
  /**
   * Zero. Keeps the members after it where a 32-bit and a 64-bit target
   * both put them without padding at the end of the struct, so that a
   * member a later version appends starts past the length a caller built
   * against this header declares. The library writes zero here and reads
   * nothing from it.
   */
  reserved: number;
  /**
   * Where to write the local address, `host:port` with a trailing
   * NUL: for a pair, the candidate its checks left from — the host
   * candidate, or the relayed one; for a relay, the relayed address.
   */
  local: Pointer;
  /**
   * How much room `local` has. At least SIPRAL_ADDRESS_BYTES when
   * it is not null.
   */
  local_capacity: number;
  /**
   * How many bytes of it were written, the NUL not counted. Zero for
   * a relay that has no relayed address.
   */
  local_len: number;
  /**
   * Where to write the far address, `host:port` with a trailing NUL:
   * for a pair, the far end's candidate; for a relay, the TURN
   * server.
   */
  remote: Pointer;
  /**
   * How much room `remote` has. At least SIPRAL_ADDRESS_BYTES
   * when it is not null.
   */
  remote_capacity: number;
  /**
   * How many bytes of it were written, the NUL not counted.
   */
  remote_len: number;
}
koffi.struct('sipral_path_candidate_t', {
  size: 'size_t',
  priority: 'uint64_t',
  kind: 'sipral_path_kind_t',
  outcome: 'sipral_path_outcome_t',
  code: 'uint32_t',
  local_kind: 'sipral_candidate_kind_t',
  remote_kind: 'sipral_candidate_kind_t',
  reserved: 'uint32_t',
  local: 'void *',
  local_capacity: 'size_t',
  local_len: 'size_t',
  remote: 'void *',
  remote_capacity: 'size_t',
  remote_len: 'size_t',
});

/**
 * What one call's media settled on, and what it is doing now.
 *
 * A4's reporting half and as much of D5 as this stack knows: the codec that
 * was agreed, the number it travels under, and the shape of the stream around
 * it. What is deliberately not here is why each other candidate lost —
 * RFC 3264 §6.1 leaves that decision with the peer, and a reason invented on
 * this side would be a reason nobody can act on.
 *
 * Set `size` to `sizeof(sipral_media_info_t)` before the call.
 */
export interface SipralMediaInfo {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * A sipral_codec_t: what the two ends agreed on.
   */
  codec: number;
  /**
   * The payload type on the wire. It is the offer's own number and not
   * necessarily ours: the two ends pick their own numbers for a format
   * with no static one, so a peer that numbers it 111 has said what we
   * say with 96.
   */
  payload_type: number;
  /**
   * The RTP timestamp clock, in hertz.
   */
  clock_rate: number;
  /**
   * The rate the samples crossing this ABI are at: the codec's, or the
   * one sipral_media_set_app_rate chose.
   */
  sample_rate: number;
  /**
   * How long a frame is, in milliseconds.
   */
  frame_ms: number;
  /**
   * Samples in one frame: exactly what sipral_media_playback fills and
   * what sipral_media_capture wants, at `sample_rate`.
   */
  frame_samples: number;
  /**
   * A sipral_direction_t.
   */
  direction: number;
  /**
   * Whether this end is meant to be sending. Zero while it holds the far
   * end, or while the far end has refused to receive.
   */
  sending: number;
  /**
   * Whether this end is meant to be receiving.
   */
  receiving: number;
  /**
   * Whether RFC 4733 named events were agreed.
   */
  has_dtmf: number;
  /**
   * The payload type they travel under, when they were.
   */
  dtmf_payload_type: number;
  /**
   * A sipral_rtcp_t.
   */
  rtcp: number;
  /**
   * Whether the stream is keyed.
   */
  secured: number;
  /**
   * Whether a recording is running on this call.
   */
  recording: number;
  /**
   * How much audio it has taken.
   */
  recorded_ms: Wide;
  /**
   * Whether the watchdog currently considers inbound audio stopped.
   */
  stalled: number;
  /**
   * Whether the call agreed a real-time text stream (RFC 4103), which
   * `sipral_media_send_text` writes to.
   */
  has_text: number;
  /**
   * Whether the audio stream runs RTP/AVPF (RFC 4585): both ends named
   * a feedback profile.
   */
  feedback: number;
  /**
   * Whether both ends agreed Generic NACKs (`a=rtcp-fb:* nack`), so
   * that a gap in what arrives is asked for again.
   */
  generic_nack: number;
  /**
   * Whether both ends agreed reduced-size RTCP (RFC 5506,
   * `a=rtcp-rsize`).
   */
  reduced_size: number;
  /**
   * Zero. Rounds the struct up to a whole multiple of its alignment on
   * every target, so that a member a later version appends starts at or
   * past the length a caller built against this header declares, never
   * in padding inside it. The library writes zero here and reads nothing
   * from it.
   */
  reserved: number;
}
koffi.struct('sipral_media_info_t', {
  size: 'size_t',
  codec: 'sipral_codec_t',
  payload_type: 'uint32_t',
  clock_rate: 'uint32_t',
  sample_rate: 'uint32_t',
  frame_ms: 'uint32_t',
  frame_samples: 'size_t',
  direction: 'sipral_direction_t',
  sending: 'uint32_t',
  receiving: 'uint32_t',
  has_dtmf: 'uint32_t',
  dtmf_payload_type: 'uint32_t',
  rtcp: 'sipral_rtcp_t',
  secured: 'uint32_t',
  recording: 'uint32_t',
  recorded_ms: 'uint64_t',
  stalled: 'uint32_t',
  has_text: 'uint32_t',
  feedback: 'uint32_t',
  generic_nack: 'uint32_t',
  reduced_size: 'uint32_t',
  reserved: 'uint32_t',
});

/**
 * What one call's media has cost, and what it is costing now.
 *
 * A6. Cheap enough to read at the frame rate of a user interface — everything
 * in it is already counted and nothing walks a history — and complete enough
 * to keep as the record of a call, which is the same struct delivered with
 * `SIPRAL_EVENT_KIND_MEDIA_STATISTICS` when the call ends.
 *
 * The three delays are in microseconds and not milliseconds. Jitter on a
 * healthy call is a fraction of a millisecond, and a figure that reads zero
 * whenever things are going well is a figure nobody looks at twice.
 *
 * Set `size` to `sizeof(sipral_stream_stats_t)` before the call.
 */
export interface SipralStreamStats {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * A sipral_codec_t: what the call settled on, which is the first thing
   * anybody looking at a bad call wants to know.
   */
  codec: number;
  /**
   * Whether a round-trip time is known. Zero until a report has come back,
   * which on a short call may be never: the first one is deliberately
   * delayed (RFC 3550 §6.2) and a peer that sends no RTCP never provides
   * one.
   */
  has_round_trip: number;
  /**
   * The round trip, from RTCP.
   */
  round_trip_us: Wide;
  /**
   * Packets this end has put on the wire.
   */
  packets_sent: Wide;
  /**
   * Payload octets in them, not counting headers.
   */
  octets_sent: Wide;
  /**
   * Packets taken in and held for playout.
   */
  packets_received: Wide;
  /**
   * Sequence numbers that came due with nothing in them.
   */
  packets_lost: Wide;
  /**
   * Packets that arrived behind the playout point.
   */
  packets_late: Wide;
  /**
   * Packets thrown out of the window before they could be played.
   */
  packets_overflowed: Wide;
  /**
   * Packets whose sequence number was already held.
   */
  packets_duplicated: Wide;
  /**
   * Packets accepted after a higher sequence number had already arrived.
   */
  packets_reordered: Wide;
  /**
   * Frames dropped in a pause to bring the delay down. Deliberate, and
   * inaudible when the pause is real.
   */
  frames_shrunk: Wide;
  /**
   * Frames the concealment was asked to invent in a pause to push the delay
   * up.
   */
  frames_stretched: Wide;
  /**
   * How far behind the newest packet the playout point is: the delay the
   * far end's voice is actually suffering.
   */
  delay_us: Wide;
  /**
   * What the buffer is aiming at, from the arrival times it has seen.
   */
  target_delay_us: Wide;
  /**
   * Interarrival jitter, the smoothed mean deviation of transit time
   * (RFC 3550 §6.4.1).
   */
  jitter_us: Wide;
  /**
   * Frames concealed as a fraction of frames played, over the last ten
   * seconds or so. The counters above say what the call has cost; this says
   * whether it is bad right now.
   */
  loss_rate: number;
  /**
   * One number for a bar on a screen: a hundred for a call with nothing
   * wrong with it, zero for one nobody can hold. Not a mean opinion score,
   * and deliberately not shaped like one.
   */
  score: number;
  /**
   * Whether the numbers say this call is in trouble now.
   */
  suffering: number;
  /**
   * How long since a packet last arrived. A live call sits at one frame.
   */
  silent_for_ms: Wide;
  /**
   * Whether an RFC 3611 VoIP Metrics report is available at all —
   * zero until this stream has identified a source to report on.
   * Every `voip_*` member below is meaningless while this is zero.
   */
  has_voip_metrics: number;
  /**
   * RFC 3611 SS4.7.1's loss rate, as its own 256ths (multiply by
   * 100 and divide by 256 for a percentage).
   */
  voip_loss_rate_256: number;
  /**
   * RFC 3611 SS4.7.1's discard rate, as its own 256ths.
   */
  voip_discard_rate_256: number;
  /**
   * RFC 3611 SS4.7.2's burst density, as its own 256ths.
   */
  voip_burst_density_256: number;
  /**
   * RFC 3611 SS4.7.2's mean burst duration.
   */
  voip_burst_duration_us: Wide;
  /**
   * RFC 3611 SS4.7.2's gap density, as its own 256ths.
   */
  voip_gap_density_256: number;
  /**
   * RFC 3611 SS4.7.2's mean gap duration.
   */
  voip_gap_duration_us: Wide;
  /**
   * RFC 3611 SS4.7.2's `Gmin`: the burst/gap classification
   * threshold this stream's jitter buffer used, fixed for the
   * stream's whole life.
   */
  voip_gmin: number;
  /**
   * RFC 3611 SS4.7.3's end-system delay. Zero for every build of
   * this stack today: SS4.7.3 defines it as the sending side's own
   * accumulation and encoding delay added to the receiving side's,
   * and nothing here has visibility into the sending side's half.
   */
  voip_end_system_delay_us: Wide;
  /**
   * RFC 3611 SS4.7.7's nominal jitter buffer delay.
   */
  voip_jitter_buffer_nominal_us: Wide;
  /**
   * RFC 3611 SS4.7.7's current maximum jitter buffer delay.
   */
  voip_jitter_buffer_maximum_us: Wide;
  /**
   * RFC 3611 SS4.7.7's absolute maximum jitter buffer delay.
   */
  voip_jitter_buffer_abs_max_us: Wide;
  /**
   * Whether `voip_r_factor` is available: zero when the active
   * codec is one ITU-T G.113 tabulates no `Ie`/`Bpl` for (RFC 3611
   * SS4.7.5's own `127` "unavailable" sentinel).
   */
  has_voip_r_factor: number;
  /**
   * RFC 3611 SS4.7.5's R factor, `0..=100`.
   */
  voip_r_factor: number;
  /**
   * Whether `voip_mos_lq_x10` is available, for the same reason as
   * `has_voip_r_factor`.
   */
  has_voip_mos_lq: number;
  /**
   * RFC 3611 SS4.7.5's estimated listening-quality MOS, in tenths
   * (`14..=50`).
   */
  voip_mos_lq_x10: number;
  /**
   * Whether `voip_mos_cq_x10` is available, for the same reason.
   */
  has_voip_mos_cq: number;
  /**
   * RFC 3611 SS4.7.5's estimated conversational-quality MOS, in
   * tenths.
   */
  voip_mos_cq_x10: number;
  /**
   * Frames played as nothing because the jitter buffer had run dry
   * while the far end was still sending: the earpiece asked for audio
   * before it had arrived, and heard silence or comfort noise in its
   * place, wherever that fell. A frame the far end never sent, in its
   * own pause, is not one, and nor is a packet lost on the way, which
   * is `packets_lost`. No packet is lost or discarded by it, so none of
   * the `voip_*` rates above sees it (RFC 3611 SS4.7.1 counts packets);
   * `loss_rate`, `score` and `suffering` do.
   */
  frames_underrun: Wide;
  /**
   * Whether the stream runs RTP/AVPF (RFC 4585). Every count below is
   * zero while it does not.
   */
  feedback: number;
  /**
   * The `trr-int` both ends agreed: the least time between two
   * regular reports, in milliseconds. Zero for none.
   */
  trr_interval_ms: number;
  /**
   * Generic NACKs this end sent, each asking for one or more packets.
   */
  nacks_sent: Wide;
  /**
   * The packets those NACKs asked for.
   */
  packets_nacked: Wide;
  /**
   * Generic NACKs the far end sent.
   */
  nacks_received: Wide;
  /**
   * The packets those asked this end for.
   */
  packets_asked_for: Wide;
  /**
   * Early RTCP packets this end sent: feedback that could not wait for
   * the next regular report.
   */
  early_packets: Wide;
  /**
   * Reduced-size RTCP packets this end sent (RFC 5506).
   */
  reduced_size_packets: Wide;
  /**
   * Feedback this end had to hold back, because the stream's RTCP
   * bandwidth had none to spare.
   */
  feedback_suppressed: Wide;
}
koffi.struct('sipral_stream_stats_t', {
  size: 'size_t',
  codec: 'sipral_codec_t',
  has_round_trip: 'uint32_t',
  round_trip_us: 'uint64_t',
  packets_sent: 'uint64_t',
  octets_sent: 'uint64_t',
  packets_received: 'uint64_t',
  packets_lost: 'uint64_t',
  packets_late: 'uint64_t',
  packets_overflowed: 'uint64_t',
  packets_duplicated: 'uint64_t',
  packets_reordered: 'uint64_t',
  frames_shrunk: 'uint64_t',
  frames_stretched: 'uint64_t',
  delay_us: 'uint64_t',
  target_delay_us: 'uint64_t',
  jitter_us: 'uint64_t',
  loss_rate: 'float',
  score: 'float',
  suffering: 'uint32_t',
  silent_for_ms: 'uint64_t',
  has_voip_metrics: 'uint32_t',
  voip_loss_rate_256: 'uint32_t',
  voip_discard_rate_256: 'uint32_t',
  voip_burst_density_256: 'uint32_t',
  voip_burst_duration_us: 'uint64_t',
  voip_gap_density_256: 'uint32_t',
  voip_gap_duration_us: 'uint64_t',
  voip_gmin: 'uint32_t',
  voip_end_system_delay_us: 'uint64_t',
  voip_jitter_buffer_nominal_us: 'uint64_t',
  voip_jitter_buffer_maximum_us: 'uint64_t',
  voip_jitter_buffer_abs_max_us: 'uint64_t',
  has_voip_r_factor: 'uint32_t',
  voip_r_factor: 'uint32_t',
  has_voip_mos_lq: 'uint32_t',
  voip_mos_lq_x10: 'uint32_t',
  has_voip_mos_cq: 'uint32_t',
  voip_mos_cq_x10: 'uint32_t',
  frames_underrun: 'uint64_t',
  feedback: 'uint32_t',
  trr_interval_ms: 'uint32_t',
  nacks_sent: 'uint64_t',
  packets_nacked: 'uint64_t',
  nacks_received: 'uint64_t',
  packets_asked_for: 'uint64_t',
  early_packets: 'uint64_t',
  reduced_size_packets: 'uint64_t',
  feedback_suppressed: 'uint64_t',
});

/**
 * One datagram on its way out, written into the caller's own buffers.
 *
 * The caller fills in `size`, the two pointers and the two capacities; the
 * library fills in the two lengths and the bytes. A `len` of zero means there
 * was nothing to send, which on a capture is an ordinary answer: this end may
 * be held by the far end, or silence suppression may have swallowed the frame.
 *
 * Both buffers are checked before anything is produced. A packet that was
 * built and then had nowhere to go would be a packet missing from a stream
 * whose timestamps had already moved past it.
 */
export interface SipralMediaPacket {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * Where to write the packet. At least SIPRAL_MEDIA_PACKET_BYTES.
   */
  data: Pointer;
  /**
   * How much room `data` has.
   */
  capacity: number;
  /**
   * How much was written. Zero means there was nothing to send.
   */
  len: number;
  /**
   * Where to write the destination, as `host:port` with a trailing NUL. Null
   * with a capacity of zero for a caller that does not want it.
   */
  destination: Pointer;
  /**
   * How much room `destination` has. At least SIPRAL_ADDRESS_BYTES when
   * it is not null.
   */
  destination_capacity: number;
  /**
   * How many bytes of it were written, the NUL not counted.
   */
  destination_len: number;
  /**
   * What to send it over, as a `sipral_transport_t`.
   * `SIPRAL_TRANSPORT_UDP` is a datagram from the call's media socket,
   * which is everything unless the stack reaches its TURN server over
   * TCP or TLS (`turn_transport`); then what goes through the relay
   * says that instead, `destination` is the server, and the bytes are
   * written, as they are and in order, on the media socket's
   * connection to it — never sent as a datagram.
   */
  protocol: number;
  /**
   * Zero. Rounds the struct up to a whole multiple of its alignment on
   * every target, so that a member a later version appends starts at or
   * past the length a caller built against this header declares, never
   * in padding inside it. Set it to zero when the struct is handed in;
   * the library writes zero here and reads nothing from it.
   */
  reserved: number;
}
koffi.struct('sipral_media_packet_t', {
  size: 'size_t',
  data: 'void *',
  capacity: 'size_t',
  len: 'size_t',
  destination: 'void *',
  destination_capacity: 'size_t',
  destination_len: 'size_t',
  protocol: 'sipral_transport_t',
  reserved: 'uint32_t',
});

/**
 * What sipral_processor_callback_t is handed for one call: an ordinary
 * frame to process, or a request to forget what has been learned.
 *
 * Filled by the library and handed to the callback as a `const`
 * pointer, the same shape sipral_screen_request_t is:
 * read `size` before anything past it, and read nothing once the
 * callback has returned — `near_end`, `far_end` and `out` borrow from
 * buffers that belong to this one call and are not this ABI's to keep
 * alive a moment longer.
 */
export interface SipralProcessorFrame {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * 0 for an ordinary frame; 1 for a request to forget whatever state
   * the processor holds — a device change or a codec change mid-call
   * asks for this, and `near_end`, `far_end` and `out`, with the three
   * lengths beside them, are all null and zero when it is set.
   */
  reset: number;
  /**
   * The frame just captured from the microphone. Null when `reset` is
   * set.
   */
  near_end: Pointer;
  /**
   * How many samples `near_end` is. Always the same number as
   * `far_end_len` and `out_len` — carried three times, once beside
   * each buffer, because that is the one buffer each binding marshals
   * on its own. 0 when `reset` is set.
   */
  near_end_len: number;
  /**
   * The far-end audio rendered to the loudspeaker over the same span
   * of time as `near_end`, the same length. Null when `reset` is set.
   */
  far_end: Pointer;
  /**
   * How many samples `far_end` is. See `near_end_len`. 0 when `reset`
   * is set.
   */
  far_end_len: number;
  /**
   * Where the callback writes the frame that replaces `near_end` —
   * every sample of it, since what is not written is read back as
   * whatever was there before. Null when `reset` is set, since there
   * is nothing to write.
   */
  out: Pointer;
  /**
   * How many samples `out` has room for, which is also how many the
   * callback has to write. See `near_end_len`. 0 when `reset` is set.
   */
  out_len: number;
}
koffi.struct('sipral_processor_frame_t', {
  size: 'size_t',
  reset: 'uint32_t',
  near_end: 'void *',
  near_end_len: 'size_t',
  far_end: 'void *',
  far_end_len: 'size_t',
  out: 'void *',
  out_len: 'size_t',
});

/**
 * One message on its way out, written into the caller's own buffers.
 *
 * The caller fills in `size`, the three pointers and the three capacities; the
 * library fills in everything else. A `len` of zero means the stack had nothing
 * to send, which is how the draining loop ends.
 *
 * The two address buffers are checked before a message is taken, so the address
 * side is never the reason one is held. The payload buffer is not: a message
 * too long for it is kept and offered again, because a message the stack has
 * already committed to is not one this ABI may drop.
 */
export interface SipralTransmit {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * Which transport to write to: SIPRAL_TRANSPORT_MAIN for a stack
   * that never bound another, or the number
   * sipral_stack_transport_bind gave whichever account or call
   * this message belongs to.
   */
  transport: number;
  /**
   * What that transport speaks, as a `sipral_transport_t`.
   *
   * Carried because it is the message's and not the socket's: §18.1.1 lets a
   * request that outgrew a datagram go out on a stream instead, and the
   * transport it ends up on is the one this says. Zero for a protocol this
   * ABI has no number for.
   */
  protocol: number;
  /**
   * Where to write the message. Nothing is written unless the whole of it
   * fits.
   */
  data: Pointer;
  /**
   * How much room `data` has.
   */
  capacity: number;
  /**
   * How much was written — or, when the call answered
   * `SIPRAL_STATUS_BUFFER_TOO_SMALL`, how much room the message needs.
   */
  len: number;
  /**
   * Where to write the destination, as `host:port` with a trailing NUL. Null
   * with a capacity of zero for a caller whose socket is connected and
   * already knows.
   */
  destination: Pointer;
  /**
   * How much room `destination` has. At least SIPRAL_ADDRESS_BYTES when
   * it is not null.
   */
  destination_capacity: number;
  /**
   * How many bytes of it were written, the NUL not counted.
   */
  destination_len: number;
  /**
   * Where to write the address to send *from*, in the same shape.
   *
   * RFC 3581 §4: "The response MUST be sent from the same address and port
   * that the corresponding request was received on", which a caller listening
   * on a wildcard address cannot work out for itself. Empty — a `source_len`
   * of zero — means the transport's own address, which is the answer for
   * every request this stack originates.
   */
  source: Pointer;
  /**
   * How much room `source` has. At least SIPRAL_ADDRESS_BYTES when it is
   * not null.
   */
  source_capacity: number;
  /**
   * How many bytes of it were written, the NUL not counted.
   */
  source_len: number;
}
koffi.struct('sipral_transmit_t', {
  size: 'size_t',
  transport: 'uint32_t',
  protocol: 'sipral_transport_t',
  data: 'void *',
  capacity: 'size_t',
  len: 'size_t',
  destination: 'void *',
  destination_capacity: 'size_t',
  destination_len: 'size_t',
  source: 'void *',
  source_capacity: 'size_t',
  source_len: 'size_t',
});

/**
 * A transport that failed, and why, for
 * sipral_stack_transport_failed_with.
 *
 * The caller fills in all of it. `detail` is the platform's own sentence
 * — OpenSSL's, `SslStream`'s, `SSLSocket`'s, Network.framework's — and
 * is optional; it travels to the event unread and unparsed, so a user's
 * report can quote it.
 */
export interface SipralTransportFailure {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * Which transport: SIPRAL_TRANSPORT_MAIN, or a number
   * sipral_stack_transport_bind added.
   */
  transport: number;
  /**
   * A sipral_transport_error_t.
   */
  error: number;
  /**
   * A sipral_tls_failure_t; `SIPRAL_TLS_FAILURE_NONE` for anything
   * that was not TLS refusing, and only that on a transport that does
   * not speak TLS.
   */
  tls: number;
  /**
   * The platform's own words for it, not NUL-terminated. Null with a
   * length of zero for none.
   */
  detail: Pointer;
  /**
   * How many bytes of it; at most SIPRAL_TRANSPORT_DETAIL_BYTES.
   */
  detail_len: number;
}
koffi.struct('sipral_transport_failure_t', {
  size: 'size_t',
  transport: 'uint32_t',
  error: 'sipral_transport_error_t',
  tls: 'sipral_tls_failure_t',
  detail: 'void *',
  detail_len: 'size_t',
});

/**
 * What a SIPRAL_EVENT_KIND_REGISTRATION_CHANGED carries.
 */
export interface SipralRegistrationEvent {
  /**
   * A sipral_registration_state_t.
   */
  state: number;
  /**
   * A sipral_registration_failure_t, zero when nothing failed.
   */
  failure: number;
  /**
   * The status the registrar answered with, or zero when none arrived.
   */
  status_code: number;
  /**
   * The binding's granted lifetime, zero unless it is live.
   */
  expires_ms: Wide;
  /**
   * How long until the refresh, zero unless one is scheduled.
   */
  refresh_in_ms: Wide;
  /**
   * How long until the next attempt. Only meaningful while the state is
   * retrying, which is exactly when the stack is going to try again.
   */
  retry_in_ms: Wide;
}
koffi.struct('sipral_registration_event_t', {
  state: 'sipral_registration_state_t',
  failure: 'sipral_registration_failure_t',
  status_code: 'uint32_t',
  expires_ms: 'uint64_t',
  refresh_in_ms: 'uint64_t',
  retry_in_ms: 'uint64_t',
});

/**
 * What every call event carries.
 *
 * Not every member means something in every kind, and the ones that do not
 * are zero. A zero here always reads as absent rather than as a value.
 */
export interface SipralCallEvent {
  /**
   * A sipral_call_state_t.
   */
  state: number;
  /**
   * A sipral_call_end_reason_t, zero while the call is alive.
   */
  end_reason: number;
  /**
   * The status a response carried, or zero.
   */
  status_code: number;
  /**
   * The other call this event is also about: the sibling of a fork, or the
   * call that was replaced. SIPRAL_HANDLE_NONE otherwise.
   */
  other: Wide;
  /**
   * Whether this end has asked the far end to stop sending.
   */
  held_here: number;
  /**
   * Whether the far end has asked this one to.
   */
  held_there: number;
  /**
   * What this end is describing, and how long it is.
   */
  local_sdp: Pointer;
  /**
   * How many bytes of it.
   */
  local_sdp_len: number;
  /**
   * And what the far end is.
   */
  remote_sdp: Pointer;
  /**
   * How many bytes of it.
   */
  remote_sdp_len: number;
  /**
   * When a refused session change goes out again by itself, zero when it is
   * not going to.
   */
  retry_in_ms: Wide;
  /**
   * The `From` URI of the request that created this call: as written in
   * the header, without the angle brackets and without header
   * parameters such as `tag`. The same on every event of this call.
   * Null and zero when this build has none to report.
   */
  from_uri: Pointer;
  /**
   * How many bytes of it.
   */
  from_uri_len: number;
  /**
   * That `From`'s display name, quotes and backslash escapes resolved
   * (RFC 3261 §25.1). Null and zero when the header named none.
   */
  from_display: Pointer;
  /**
   * How many bytes of it.
   */
  from_display_len: number;
  /**
   * The `To` URI of the request that created this call, as written in
   * the header.
   */
  to_uri: Pointer;
  /**
   * How many bytes of it.
   */
  to_uri_len: number;
  /**
   * The `Call-ID` of the request that created this call.
   */
  call_id: Pointer;
  /**
   * How many bytes of it.
   */
  call_id_len: number;
  /**
   * The digit an INFO this end sent named, for
   * SIPRAL_EVENT_KIND_DTMF_SENT. Zero for every other kind.
   */
  digit: number;
  /**
   * For SIPRAL_EVENT_KIND_CALL_ENDED: the SIP status the far end's
   * `Reason` (RFC 3326) named — on the BYE or the CANCEL that ended
   * the call, or on the refusal. 200 on a CANCEL is a forking proxy
   * saying another phone answered: not a missed call. Zero when no
   * SIP reason was given. ABI 0.29.
   */
  cause_sip: number;
  /**
   * The same for a Q.850 cause, which a gateway to the telephone
   * network writes: 16 a normal clearing, 17 a busy line. Zero when
   * none was given.
   */
  cause_q850: number;
  /**
   * The `text` of the first `Reason` value, unquoted. Null and zero
   * when there was none.
   */
  cause_text: Pointer;
  /**
   * How many bytes of it.
   */
  cause_text_len: number;
  /**
   * Whether the INVITE of a call that came in arrived from a peer its
   * account trusts (`trusted_peers` on `sipral_account_config_t`).
   * When it did not, `asserted_uri`, `asserted_display` and
   * `verstat` say nothing, whatever it carried (RFC 3325 §8). The same
   * on every event of the call; zero for a call this end placed.
   */
  identity_trusted: number;
  /**
   * Who the network says is calling: the first `P-Asserted-Identity`,
   * or a calling `Remote-Party-ID` when there is none, as written.
   * Null and zero when a trusted peer said nothing.
   */
  asserted_uri: Pointer;
  /**
   * How many bytes of it.
   */
  asserted_uri_len: number;
  /**
   * That identity's display name. Null and zero when it named none.
   */
  asserted_display: Pointer;
  /**
   * How many bytes of it.
   */
  asserted_display_len: number;
  /**
   * A sipral_verstat_t: what the
   * network concluded about the caller's number.
   */
  verstat: number;
  /**
   * The `SIPRAL_PRIVACY_*` bits the caller's `Privacy` asked for.
   */
  privacy: number;
  /**
   * Who the call was last diverted from: the top-most `Diversion`
   * (RFC 5806), as written. Null and zero when none.
   * `sipral_call_identity_text` reads the rest.
   */
  diverted_from: Pointer;
  /**
   * How many bytes of it.
   */
  diverted_from_len: number;
  /**
   * Why: its `reason`. Null and zero when none.
   */
  diversion_reason: Pointer;
  /**
   * How many bytes of it.
   */
  diversion_reason_len: number;
  /**
   * How many `Diversion` values the INVITE carried.
   */
  diversion_count: number;
  /**
   * How many `History-Info` entries it carried.
   */
  history_count: number;
  /**
   * A sipral_answer_mode_t: the
   * INVITE's `Answer-Mode` (RFC 5373).
   */
  answer_mode: number;
  /**
   * Whether that field said `;require`: the caller would rather the
   * call be refused, with a 403, than answered any other way.
   */
  answer_mode_required: number;
  /**
   * The same for `Priv-Answer-Mode`, which RFC 5373 §4.2 holds to a
   * stricter policy.
   */
  priv_answer_mode: number;
  /**
   * Whether that field said `;require`.
   */
  priv_answer_mode_required: number;
  /**
   * Whether the call asked to be answered without the user —
   * `Answer-Mode: Auto`, `answer-after` on `Call-Info` or
   * `Alert-Info`, or `info=alert-autoanswer` — after
   * `answer_after_ms`. Whether to is the application's policy.
   */
  has_answer_after: number;
  /**
   * After how long, when `has_answer_after` is set.
   */
  answer_after_ms: Wide;
  /**
   * A sipral_ring_source_t: whether
   * the ring says the caller is internal or external.
   */
  ring_source: number;
  /**
   * The first `Alert-Info` URI, without the angle brackets. Null and
   * zero when none. `sipral_call_identity_text` reads the rest.
   */
  alert_info: Pointer;
  /**
   * How many bytes of it.
   */
  alert_info_len: number;
  /**
   * A sipral_verification_outcome_t:
   * this stack's own verdict on the caller (RFC 8224 §6.2), for an
   * account that verifies; zero when nothing was verified. Unlike
   * `verstat`, which is what a network before this end concluded,
   * this is what this end checked itself. ABI 0.31.
   */
  verification: number;
  /**
   * A sipral_attestation_t: the
   * level a valid SHAKEN PASSporT claimed.
   */
  attestation: number;
  /**
   * A sipral_verification_failure_t:
   * why the verdict did not hold. `sipral_call_identity_text` reads
   * the number it was signed for, its `origid` and its certificate URL.
   */
  verification_failure: number;
}
koffi.struct('sipral_call_event_t', {
  state: 'sipral_call_state_t',
  end_reason: 'sipral_call_end_reason_t',
  status_code: 'uint32_t',
  other: 'sipral_handle_t',
  held_here: 'uint32_t',
  held_there: 'uint32_t',
  local_sdp: 'void *',
  local_sdp_len: 'size_t',
  remote_sdp: 'void *',
  remote_sdp_len: 'size_t',
  retry_in_ms: 'uint64_t',
  from_uri: 'void *',
  from_uri_len: 'size_t',
  from_display: 'void *',
  from_display_len: 'size_t',
  to_uri: 'void *',
  to_uri_len: 'size_t',
  call_id: 'void *',
  call_id_len: 'size_t',
  digit: 'uint32_t',
  cause_sip: 'uint32_t',
  cause_q850: 'uint32_t',
  cause_text: 'void *',
  cause_text_len: 'size_t',
  identity_trusted: 'uint32_t',
  asserted_uri: 'void *',
  asserted_uri_len: 'size_t',
  asserted_display: 'void *',
  asserted_display_len: 'size_t',
  verstat: 'sipral_verstat_t',
  privacy: 'uint32_t',
  diverted_from: 'void *',
  diverted_from_len: 'size_t',
  diversion_reason: 'void *',
  diversion_reason_len: 'size_t',
  diversion_count: 'uint32_t',
  history_count: 'uint32_t',
  answer_mode: 'sipral_answer_mode_t',
  answer_mode_required: 'uint32_t',
  priv_answer_mode: 'uint32_t',
  priv_answer_mode_required: 'uint32_t',
  has_answer_after: 'uint32_t',
  answer_after_ms: 'uint64_t',
  ring_source: 'sipral_ring_source_t',
  alert_info: 'void *',
  alert_info_len: 'size_t',
  verification: 'sipral_verification_outcome_t',
  attestation: 'sipral_attestation_t',
  verification_failure: 'sipral_verification_failure_t',
});

/**
 * What a transfer event carries.
 */
export interface SipralTransferEvent {
  /**
   * What the far end's own call is doing, or zero.
   */
  status_code: number;
  /**
   * Whether the request named a dialog to replace, which is what makes a
   * transfer attended rather than blind.
   */
  attended: number;
  /**
   * Who to call, as UTF-8. Not NUL-terminated.
   */
  target: Pointer;
  /**
   * How many bytes of it.
   */
  target_len: number;
}
koffi.struct('sipral_transfer_event_t', {
  status_code: 'uint32_t',
  attended: 'uint32_t',
  target: 'void *',
  target_len: 'size_t',
});

/**
 * What a media event carries.
 *
 * As with a call event, not every member means something in every kind, and
 * the ones that do not are zero or null.
 */
export interface SipralMediaEvent {
  /**
   * A sipral_codec_t: what the negotiation
   * settled on, zero where the event is not about a codec.
   */
  codec: number;
  /**
   * A sipral_direction_t: which way audio
   * may flow, as seen from here.
   */
  direction: number;
  /**
   * How long the stream has been silent, for a stall and for its recovery.
   */
  silent_for_ms: Wide;
  /**
   * How much audio reached the file, for a recording that stopped by
   * itself.
   */
  recorded_ms: Wide;
  /**
   * A sipral_media_fault_t, zero when
   * nothing failed.
   */
  fault: number;
  /**
   * The sentence behind `fault`, as UTF-8. Not NUL-terminated, and null
   * when nothing failed.
   */
  reason: Pointer;
  /**
   * How many bytes of it.
   */
  reason_len: number;
  /**
   * What the stream cost, for the kind that carries it, and null for every
   * other. It belongs to the library and lives as long as the callback.
   */
  statistics: Pointer;
  /**
   * The key the far end pressed, as its character, and zero for an event
   * no keypad has a key for.
   */
  digit: number;
  /**
   * The RFC 4733 event code behind `digit`. Codes at and above sixteen are
   * real events that are not keys.
   */
  event_code: number;
  /**
   * How long the far end held it. Zero either for an `application/dtmf`
   * INFO, which carries no duration at all, or for the other form's
   * own `Duration=0` — a peer that held the key for no time at all.
   * The Rust facade keeps the two apart; this ABI does not.
   */
  held_ms: Wide;
  /**
   * A sipral_srtp_suite_t: the transform
   * this call's media is protected with, for
   * SIPRAL_EVENT_KIND_MEDIA_SECURED and zero on every other kind.
   */
  suite: number;
  /**
   * A sipral_digit_source_t: which of the two ways this stack accepts a
   * digit reported this one, for SIPRAL_EVENT_KIND_DIGIT_RECEIVED.
   */
  source: number;
  /**
   * Whether the RFC 6035 PUBLISH left this end, for
   * SIPRAL_EVENT_KIND_QUALITY_REPORT_SENT and zero on every other
   * kind. Not whether a collector accepted it.
   */
  quality_report_sent: number;
  /**
   * A sipral_key_exchange_t: how
   * the call's keys were exchanged, for
   * SIPRAL_EVENT_KIND_MEDIA_STARTED, SIPRAL_EVENT_KIND_MEDIA_CHANGED
   * and SIPRAL_EVENT_KIND_MEDIA_SECURED, which carry the encryption
   * report of the call's stream: this, `encrypted`, `authenticated`,
   * and `suite` from then on. ABI 0.31.
   */
  key_exchange: number;
  /**
   * Whether the stream is encrypted, now. Zero at the start of a
   * DTLS-SRTP call, whose keys arrive with
   * SIPRAL_EVENT_KIND_MEDIA_SECURED.
   */
  encrypted: number;
  /**
   * Whether the key exchange authenticated the far end: a DTLS-SRTP
   * handshake that checked its certificate against the signalled
   * fingerprint. Never for SDES.
   */
  authenticated: number;
}
koffi.struct('sipral_media_event_t', {
  codec: 'sipral_codec_t',
  direction: 'sipral_direction_t',
  silent_for_ms: 'uint64_t',
  recorded_ms: 'uint64_t',
  fault: 'sipral_media_fault_t',
  reason: 'void *',
  reason_len: 'size_t',
  statistics: 'void *',
  digit: 'uint32_t',
  event_code: 'uint32_t',
  held_ms: 'uint64_t',
  suite: 'sipral_srtp_suite_t',
  source: 'sipral_digit_source_t',
  quality_report_sent: 'uint32_t',
  key_exchange: 'sipral_key_exchange_t',
  encrypted: 'uint32_t',
  authenticated: 'uint32_t',
});

/**
 * What a SIPRAL_EVENT_KIND_RECOVERY carries: the lifecycle machine
 * settling, either by proving the path again or by giving the ladder up.
 */
export interface SipralRecoveryEvent {
  /**
   * A sipral_recovery_outcome_t.
   */
  state: number;
  /**
   * A sipral_recovery_rung_t: the last rung tried. Zero unless `state`
   * is SIPRAL_RECOVERY_OUTCOME_GAVE_UP.
   */
  rung: number;
  /**
   * A sipral_recovery_failure_t. Zero unless `state` is
   * SIPRAL_RECOVERY_OUTCOME_GAVE_UP.
   */
  reason: number;
  /**
   * Bindings the ladder never proved. Meaningful only when `state` is
   * SIPRAL_RECOVERY_OUTCOME_GAVE_UP.
   */
  unverified: number;
}
koffi.struct('sipral_recovery_event_t', {
  state: 'sipral_recovery_outcome_t',
  rung: 'sipral_recovery_rung_t',
  reason: 'sipral_recovery_failure_t',
  unverified: 'uint32_t',
});

/**
 * What a SIPRAL_EVENT_KIND_TRANSPORT_WANTED carries: a request RFC
 * 3261 §18.1.1 would not let out over a datagram, and nowhere open to
 * send it instead.
 */
export interface SipralTransportWantedEvent {
  /**
   * What to open, as a
   * sipral_transport_t. Zero for a
   * protocol this build has no number for, which
   * `sipral_stack_transport_bind` then cannot be asked to open
   * either — nothing this build originates ever measures against a
   * protocol like that, so this is the layer below having grown one
   * rather than a caller mistake.
   */
  protocol: number;
  /**
   * Where to, as `host:port`. Not NUL-terminated.
   */
  destination: Pointer;
  /**
   * How many bytes of it.
   */
  destination_len: number;
  /**
   * How large the request came out, in bytes as they would have gone
   * on the wire.
   */
  request_bytes: number;
  /**
   * The largest it could have been and still fitted a datagram: the
   * path MTU less the §18.1.1 headroom where the MTU is known, 1300
   * where it is not.
   */
  limit_bytes: number;
}
koffi.struct('sipral_transport_wanted_event_t', {
  protocol: 'sipral_transport_t',
  destination: 'void *',
  destination_len: 'size_t',
  request_bytes: 'size_t',
  limit_bytes: 'uint32_t',
});

/**
 * What a SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED and a
 * SIPRAL_EVENT_KIND_NOTIFIED carry.
 *
 * The subscription names itself here rather than in `sipral_event_t`,
 * which has room for an account and a call and not for every kind of
 * handle this ABI mints. The account is not carried at all: a caller
 * asked for the subscription on one, and a sibling from a fork belongs
 * to the same one as the subscription it forked from.
 */
export interface SipralSubscriptionEvent {
  /**
   * Which subscription. Minted by `sipral_account_subscribe`, or by
   * this ABI when a fork made one nobody asked for.
   */
  subscription: Wide;
  /**
   * A sipral_subscription_state_t.
   */
  state: number;
  /**
   * A sipral_subscription_end_t:
   * why it is not live. Zero while it is.
   */
  reason: number;
  /**
   * The SIP status a response gave for it, when one did. Zero
   * otherwise.
   */
  status_code: number;
  /**
   * Whether the notification carried dialog state this build could
   * read. Zero on every kind but SIPRAL_EVENT_KIND_NOTIFIED, and
   * zero there for a body in any other form or none at all.
   */
  has_dialog_info: number;
  /**
   * What the notifier granted, in milliseconds. Zero until one has.
   */
  expires_ms: Wide;
  /**
   * How long until this stack refreshes it, in milliseconds.
   */
  refresh_in_ms: Wide;
  /**
   * How long until the next attempt, in milliseconds, when the state
   * is `SIPRAL_SUBSCRIPTION_STATE_RETRYING`. Zero otherwise, which
   * includes every subscription that has ended for good.
   */
  retry_in_ms: Wide;
  /**
   * The subscription this one forked from
   * ([RFC 6665 §4.1.4]), or `SIPRAL_HANDLE_NONE`. A sibling is a
   * subscription of its own from here on, with its own dialog, its own
   * refresh and its own state; RFC 4235 §3.9 makes this the normal case
   * for dialog state, one per device the watched address is registered
   * on.
   *
   * [RFC 6665 §4.1.4]: https://www.rfc-editor.org/rfc/rfc6665#section-4.1.4
   */
  forked_from: Wide;
}
koffi.struct('sipral_subscription_event_t', {
  subscription: 'sipral_handle_t',
  state: 'sipral_subscription_state_t',
  reason: 'sipral_subscription_end_t',
  status_code: 'uint32_t',
  has_dialog_info: 'uint32_t',
  expires_ms: 'uint64_t',
  refresh_in_ms: 'uint64_t',
  retry_in_ms: 'uint64_t',
  forked_from: 'sipral_handle_t',
});

/**
 * What a SIPRAL_EVENT_KIND_CALL_ANNOUNCED and a
 * SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING carry.
 */
export interface SipralAnnounceEvent {
  /**
   * Which announcement. Minted by `sipral_account_announce`, and it
   * names nothing once either of these two events has been raised
   * about it.
   */
  announcement: Wide;
  /**
   * How long the call was waited for, in milliseconds. Meaningful only
   * on SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING.
   */
  waited_ms: Wide;
}
koffi.struct('sipral_announce_event_t', {
  announcement: 'sipral_handle_t',
  waited_ms: 'uint64_t',
});

/**
 * What a SIPRAL_EVENT_KIND_RESOLVE_NEEDED carries: the name a dialog's
 * next hop is written as, and the handle an answer takes.
 */
export interface SipralResolveEvent {
  /**
   * The dialog this is about, and what
   * sipral_stack_resolved
   * is answered with. Minted by the library and valid while the dialog
   * is; answering for one that has ended is
   * `SIPRAL_STATUS_STALE_HANDLE` and changes nothing.
   */
  dialog: Wide;
  /**
   * The host to resolve, as the URI spells it — a name, or a literal
   * address, which is still reported because the flow the dialog is on
   * may legitimately differ from it. An IPv6 literal carries its
   * brackets (RFC 3261 §19.1.1). Not NUL-terminated.
   */
  host: Pointer;
  /**
   * How many bytes of it.
   */
  host_len: number;
  /**
   * The port the URI gave, or zero for none. Zero is not 5060: RFC
   * 3263 §4.2 leaves the choice to whoever does the lookup, because
   * an SRV answer carries a port of its own.
   */
  port: number;
  /**
   * The transport the URI or the scheme named, as a
   * sipral_transport_t, or zero for
   * neither — which leaves §4.1's NAPTR step to the caller, and is
   * also what a protocol this build has no number for reads as.
   */
  protocol: number;
}
koffi.struct('sipral_resolve_event_t', {
  dialog: 'sipral_handle_t',
  host: 'void *',
  host_len: 'size_t',
  port: 'uint32_t',
  protocol: 'sipral_transport_t',
});

/**
 * What a SIPRAL_EVENT_KIND_MESSAGE_RECEIVED, a
 * SIPRAL_EVENT_KIND_MESSAGE_SENT and a
 * SIPRAL_EVENT_KIND_MESSAGES_WAITING carry.
 *
 * One struct for all three, the way sipral_subscription_event_t answers
 * for two kinds: a member meaningless on one kind is zero or null there.
 * The whole request or response, when there is one, rides in
 * `sipral_event_t::message` instead — `attach` points it at the same
 * bytes `content_type` and `body` are read out of, so both are valid for
 * exactly as long as the callback is.
 */
export interface SipralMessageEvent {
  /**
   * SIPRAL_EVENT_KIND_MESSAGE_SENT: which send, minted by
   * `sipral_account_message`. SIPRAL_HANDLE_NONE on the other two
   * kinds, and names nothing once this event has been raised about it.
   */
  message: Wide;
  /**
   * SIPRAL_EVENT_KIND_MESSAGES_WAITING: which subscription reported
   * it. SIPRAL_HANDLE_NONE on the other two kinds, which are not
   * subscriptions.
   */
  subscription: Wide;
  /**
   * SIPRAL_EVENT_KIND_MESSAGE_SENT: the final status. Zero on the
   * other two kinds.
   */
  status_code: number;
  /**
   * SIPRAL_EVENT_KIND_MESSAGE_RECEIVED: the `Content-Type` of the
   * body, as written. Null on the other two kinds, and on a MESSAGE
   * with no body at all.
   */
  content_type: Pointer;
  /**
   * How many bytes of it.
   */
  content_type_len: number;
  /**
   * SIPRAL_EVENT_KIND_MESSAGE_RECEIVED: the body. Null the same as
   * `content_type`.
   */
  body: Pointer;
  /**
   * How many bytes of it.
   */
  body_len: number;
  /**
   * SIPRAL_EVENT_KIND_MESSAGES_WAITING: RFC 3842 §3.5's status
   * line, 1 for `yes` and 0 for `no`. Meaningless on the other two
   * kinds.
   */
  waiting: number;
  /**
   * SIPRAL_EVENT_KIND_MESSAGES_WAITING: new messages of the
   * `voice-message` class (RFC 3458 §6.2), the one a phone's
   * message-waiting light is about. Zero when the body named no
   * `voice-message` line, which a boolean-only notification does.
   */
  new_messages: number;
  /**
   * The same, old.
   */
  old_messages: number;
  /**
   * New messages flagged urgent.
   */
  urgent_new_messages: number;
  /**
   * Old messages flagged urgent.
   */
  urgent_old_messages: number;
  /**
   * SIPRAL_EVENT_KIND_MESSAGES_WAITING: `Message-Account`, when the
   * notifier sent one (RFC 3842 §3.5 makes it mandatory only for a
   * subscription to a group or collection of accounts). Null on the
   * other two kinds, and on a body that named none.
   */
  message_account: Pointer;
  /**
   * How many bytes of it.
   */
  message_account_len: number;
}
koffi.struct('sipral_message_event_t', {
  message: 'sipral_handle_t',
  subscription: 'sipral_handle_t',
  status_code: 'uint32_t',
  content_type: 'void *',
  content_type_len: 'size_t',
  body: 'void *',
  body_len: 'size_t',
  waiting: 'uint32_t',
  new_messages: 'uint32_t',
  old_messages: 'uint32_t',
  urgent_new_messages: 'uint32_t',
  urgent_old_messages: 'uint32_t',
  message_account: 'void *',
  message_account_len: 'size_t',
});

/**
 * What a SIPRAL_EVENT_KIND_NAT_MAPPING
 * carries.
 *
 * The three addresses are `host:port`, not NUL-terminated, and the
 * library's: valid for as long as the callback runs.
 */
export interface SipralNatEvent {
  /**
   * A sipral_nat_mapping_t.
   */
  mapping: number;
  /**
   * Nonzero for a signalling socket — a transport of this stack's —
   * and zero for a media socket sipral_stack_nat_map named.
   */
  signalling: number;
  /**
   * The transport, when `signalling` is nonzero: `SIPRAL_TRANSPORT_MAIN`
   * or a number `sipral_stack_transport_bind` bound. Zero otherwise,
   * which is not a transport here.
   */
  transport: number;
  /**
   * How many accounts' `Contact` moved to `public` because of this —
   * each one that holds a binding, or is getting one, has registered it
   * already. Zero for a media socket, and for an answer no account's
   * `Contact` named the socket in.
   */
  accounts: number;
  /**
   * The socket, as the application named it.
   */
  local: Pointer;
  /**
   * How many bytes of it.
   */
  local_len: number;
  /**
   * Where the server saw it: the public address. Empty for
   * `SIPRAL_NAT_MAPPING_UNANSWERED`.
   */
  mapped: Pointer;
  /**
   * How many bytes of it.
   */
  mapped_len: number;
  /**
   * What it was before, for `SIPRAL_NAT_MAPPING_MOVED`. Empty
   * otherwise.
   */
  previous: Pointer;
  /**
   * How many bytes of it.
   */
  previous_len: number;
}
koffi.struct('sipral_nat_event_t', {
  mapping: 'sipral_nat_mapping_t',
  signalling: 'uint32_t',
  transport: 'uint32_t',
  accounts: 'uint32_t',
  local: 'void *',
  local_len: 'size_t',
  mapped: 'void *',
  mapped_len: 'size_t',
  previous: 'void *',
  previous_len: 'size_t',
});

/**
 * What a SIPRAL_EVENT_KIND_NAT_RELAY
 * carries.
 *
 * The addresses and the reason are text, not NUL-terminated, and the
 * library's: valid for as long as the callback runs. Nothing of the
 * credential is in any of them.
 */
export interface SipralNatRelayEvent {
  /**
   * A sipral_nat_relay_t.
   */
  outcome: number;
  /**
   * For `SIPRAL_NAT_RELAY_FAILED`, the STUN error code the server
   * refused with — 401 for a credential it does not accept, 486 for a
   * user at its allocation quota, 508 for a server with nothing left —
   * and zero when there was none: no answer at all, or an answer this
   * end could not accept. Zero for `SIPRAL_NAT_RELAY_ALLOCATED`.
   */
  code: number;
  /**
   * The media socket, as `sipral_stack_nat_map` named it.
   */
  local: Pointer;
  /**
   * How many bytes of it.
   */
  local_len: number;
  /**
   * The relayed address, `host:port`. Empty for
   * `SIPRAL_NAT_RELAY_FAILED`.
   */
  relayed: Pointer;
  /**
   * How many bytes of it.
   */
  relayed_len: number;
  /**
   * Where the server saw the socket from, when it said. Empty
   * otherwise.
   */
  mapped: Pointer;
  /**
   * How many bytes of it.
   */
  mapped_len: number;
  /**
   * Why there is no relay, in English, for a log. Empty for
   * `SIPRAL_NAT_RELAY_ALLOCATED`.
   */
  reason: Pointer;
  /**
   * How many bytes of it.
   */
  reason_len: number;
}
koffi.struct('sipral_nat_relay_event_t', {
  outcome: 'sipral_nat_relay_t',
  code: 'uint32_t',
  local: 'void *',
  local_len: 'size_t',
  relayed: 'void *',
  relayed_len: 'size_t',
  mapped: 'void *',
  mapped_len: 'size_t',
  reason: 'void *',
  reason_len: 'size_t',
});

/**
 * What a SIPRAL_EVENT_KIND_REFERRAL carries: a REFER outside any
 * dialog, or the word that one lapsed.
 */
export interface SipralReferralEvent {
  /**
   * Zero while the referral waits for the application. Set on the
   * event that says it lapsed, to what the stack answered it with —
   * 408, once its transaction ran out unanswered — and then every
   * other member is zero or null.
   */
  status_code: number;
  /**
   * Whether its `Refer-To` named a dialog to replace (RFC 3891), which
   * makes it an attended transfer's second half rather than a plain
   * request to dial.
   */
  attended: number;
  /**
   * Who to call, as UTF-8. Not NUL-terminated.
   */
  target: Pointer;
  /**
   * How many bytes of it.
   */
  target_len: number;
  /**
   * Its `Referred-By` (RFC 3892), as UTF-8 and as the sender wrote it:
   * who it says is asking. Context for the decision, never proof of
   * anything. Null when the REFER carried none, or more than the one
   * §2.1 allows. Not NUL-terminated.
   */
  referred_by: Pointer;
  /**
   * How many bytes of it.
   */
  referred_by_len: number;
}
koffi.struct('sipral_referral_event_t', {
  status_code: 'uint32_t',
  attended: 'uint32_t',
  target: 'void *',
  target_len: 'size_t',
  referred_by: 'void *',
  referred_by_len: 'size_t',
});

/**
 * What a SIPRAL_EVENT_KIND_TURN_STREAM
 * carries.
 *
 * The addresses are text, not NUL-terminated, and the library's: valid
 * for as long as the callback runs.
 */
export interface SipralTurnStreamEvent {
  /**
   * A sipral_turn_stream_t.
   */
  state: number;
  /**
   * What to open, as a `sipral_transport_t`: `SIPRAL_TRANSPORT_TCP` or
   * `SIPRAL_TRANSPORT_TLS`, what `turn_transport` named.
   */
  protocol: number;
  /**
   * The media socket, as `sipral_stack_nat_map` named it: the
   * connection's own name in the three calls that take one.
   */
  local: Pointer;
  /**
   * How many bytes of it.
   */
  local_len: number;
  /**
   * The TURN server, `host:port`, as `turn_server` named it.
   */
  server: Pointer;
  /**
   * How many bytes of it.
   */
  server_len: number;
}
koffi.struct('sipral_turn_stream_event_t', {
  state: 'sipral_turn_stream_t',
  protocol: 'sipral_transport_t',
  local: 'void *',
  local_len: 'size_t',
  server: 'void *',
  server_len: 'size_t',
});

/**
 * What `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED` carries.
 */
export interface SipralAudioEvent {
  /**
   * A `sipral_audio_change_t`.
   */
  change: number;
  /**
   * A `sipral_audio_origin_t`.
   */
  origin: number;
  /**
   * A `sipral_audio_role_t`, for a change about one role; zero otherwise.
   */
  role: number;
  /**
   * A `sipral_audio_direction_t`, for `SIPRAL_AUDIO_CHANGE_DEFAULT_CHANGED`;
   * zero otherwise.
   */
  direction: number;
  /**
   * The device the change is about — the one a role landed on, or
   * the one that went — or zero.
   */
  device: number;
}
koffi.struct('sipral_audio_event_t', {
  change: 'sipral_audio_change_t',
  origin: 'sipral_audio_origin_t',
  role: 'sipral_audio_role_t',
  direction: 'sipral_audio_direction_t',
  device: 'uint32_t',
});

/**
 * What a SIPRAL_EVENT_KIND_STUN_SERVER
 * carries.
 *
 * The addresses are `host:port`, not NUL-terminated, and the library's:
 * valid for as long as the callback runs.
 */
export interface SipralStunServerEvent {
  /**
   * A sipral_stun_server_state_t.
   */
  state: number;
  /**
   * For `SIPRAL_STUN_SERVER_STATE_CHANGED`, the server in use now; for
   * `SIPRAL_STUN_SERVER_STATE_ALL_FAILED`, the last one that failed.
   */
  server: Pointer;
  /**
   * How many bytes of it.
   */
  server_len: number;
  /**
   * For `SIPRAL_STUN_SERVER_STATE_CHANGED`, the server that was in use.
   * Empty otherwise.
   */
  previous: Pointer;
  /**
   * How many bytes of it.
   */
  previous_len: number;
}
koffi.struct('sipral_stun_server_event_t', {
  state: 'sipral_stun_server_state_t',
  server: 'void *',
  server_len: 'size_t',
  previous: 'void *',
  previous_len: 'size_t',
});

/**
 * What a SIPRAL_EVENT_KIND_CALLER_VERIFICATION carries: one half of
 * the verification of who is calling (RFC 8224 §6.2).
 */
export interface SipralVerificationEvent {
  /**
   * A sipral_verification_stage_t:
   * the certificate is wanted, or the verdict is in.
   */
  stage: number;
  /**
   * A sipral_verification_outcome_t,
   * for a verdict.
   */
  outcome: number;
  /**
   * A sipral_verification_failure_t:
   * why it did not hold.
   */
  failure: number;
  /**
   * A sipral_attestation_t: the
   * level a valid SHAKEN PASSporT claimed.
   */
  attestation: number;
  /**
   * A sipral_verstat_t: the `verstat`
   * this verdict comes to (3GPP TS 24.229).
   */
  verstat: number;
  /**
   * The response RFC 8224 §6.2.2 prescribes for the failure, zero for
   * a valid one. Sent only when `refused` is set.
   */
  response_code: number;
  /**
   * Whether the call was refused with it, which only a strict account
   * does.
   */
  refused: number;
  /**
   * The URL of the certificate: the one to fetch, or the one that was
   * verified. UTF-8, not NUL-terminated; null and zero when there is
   * none.
   */
  certificate_url: Pointer;
  /**
   * How many bytes of it.
   */
  certificate_url_len: number;
  /**
   * The calling number a valid PASSporT was signed for, canonical.
   */
  orig: Pointer;
  /**
   * How many bytes of it.
   */
  orig_len: number;
  /**
   * The origination identifier a valid SHAKEN PASSporT claimed (RFC
   * 8588 §5), a UUID.
   */
  origid: Pointer;
  /**
   * How many bytes of it.
   */
  origid_len: number;
  /**
   * Why it did not hold, in more words than `failure`, for a log.
   */
  detail: Pointer;
  /**
   * How many bytes of it.
   */
  detail_len: number;
}
koffi.struct('sipral_verification_event_t', {
  stage: 'sipral_verification_stage_t',
  outcome: 'sipral_verification_outcome_t',
  failure: 'sipral_verification_failure_t',
  attestation: 'sipral_attestation_t',
  verstat: 'sipral_verstat_t',
  response_code: 'uint32_t',
  refused: 'uint32_t',
  certificate_url: 'void *',
  certificate_url_len: 'size_t',
  orig: 'void *',
  orig_len: 'size_t',
  origid: 'void *',
  origid_len: 'size_t',
  detail: 'void *',
  detail_len: 'size_t',
});

/**
 * What a SIPRAL_EVENT_KIND_PROGRESS_DETECTED carries. `what` says
 * which of the other members mean anything; the rest are zero.
 */
export interface SipralProgressEvent {
  /**
   * A sipral_progress_kind_t.
   */
  what: number;
  /**
   * A sipral_progress_tone_t, for a tone.
   */
  tone: number;
  /**
   * A sipral_amd_verdict_t, for who answered.
   */
  verdict: number;
  /**
   * A sipral_amd_reason_t, for who answered.
   */
  reason: number;
  /**
   * When, in milliseconds: a tone's first burst from the first frame
   * listened to; the decision after answer; the beep's end after
   * answer.
   */
  at_ms: Wide;
  /**
   * How long after answer the first word began, or the silence if
   * nobody spoke.
   */
  initial_silence_ms: Wide;
  /**
   * From the first word's start to the last word's end.
   */
  greeting_ms: Wide;
  /**
   * How many words were heard.
   */
  words: number;
  /**
   * The beep's frequency, in hertz, as measured.
   */
  frequency_hz: number;
  /**
   * How long the beep sounded.
   */
  length_ms: Wide;
  /**
   * The special information tone's first frequency, as measured.
   */
  sit_hz_1: number;
  /**
   * Its second.
   */
  sit_hz_2: number;
  /**
   * Its third.
   */
  sit_hz_3: number;
  /**
   * How long the first sounded.
   */
  sit_ms_1: number;
  /**
   * The second.
   */
  sit_ms_2: number;
  /**
   * The third.
   */
  sit_ms_3: number;
}
koffi.struct('sipral_progress_event_t', {
  what: 'sipral_progress_kind_t',
  tone: 'sipral_progress_tone_t',
  verdict: 'sipral_amd_verdict_t',
  reason: 'sipral_amd_reason_t',
  at_ms: 'uint64_t',
  initial_silence_ms: 'uint64_t',
  greeting_ms: 'uint64_t',
  words: 'uint32_t',
  frequency_hz: 'uint32_t',
  length_ms: 'uint64_t',
  sit_hz_1: 'uint32_t',
  sit_hz_2: 'uint32_t',
  sit_hz_3: 'uint32_t',
  sit_ms_1: 'uint32_t',
  sit_ms_2: 'uint32_t',
  sit_ms_3: 'uint32_t',
});

/**
 * What a SIPRAL_EVENT_KIND_CONFERENCE_CHANGED carries.
 */
export interface SipralConferenceEvent {
  /**
   * Which subscription.
   */
  subscription: Wide;
  /**
   * A sipral_conference_update_t.
   */
  update: number;
  /**
   * The version of the document the picture is at now; zero once the
   * conference ended.
   */
  version: number;
  /**
   * How many users the picture holds.
   */
  users: number;
}
koffi.struct('sipral_conference_event_t', {
  subscription: 'sipral_handle_t',
  update: 'sipral_conference_update_t',
  version: 'uint32_t',
  users: 'uint32_t',
});

/**
 * What a SIPRAL_EVENT_KIND_TEXT_RECEIVED carries.
 *
 * The text points into the event and is valid for as long as the
 * callback is.
 */
export interface SipralTextEvent {
  /**
   * What the far end typed, UTF-8, not NUL-terminated.
   */
  text: Pointer;
  /**
   * How many bytes of it.
   */
  text_len: number;
  /**
   * How many blocks of text were lost with no redundant copy to
   * recover them, each marked in `text` by a REPLACEMENT CHARACTER
   * (U+FFFD) where it fell.
   */
  missing: number;
}
koffi.struct('sipral_text_event_t', {
  text: 'void *',
  text_len: 'size_t',
  missing: 'uint32_t',
});

/**
 * What a SIPRAL_EVENT_KIND_PRESENCE_CHANGED carries.
 *
 * The text points into the event and is valid for as long as the
 * callback is.
 */
export interface SipralPresenceEvent {
  /**
   * A sipral_presence_kind_t.
   */
  kind: number;
  /**
   * SIPRAL_PRESENCE_KIND_WATCHED: which subscription.
   * `SIPRAL_HANDLE_NONE` for a publication, whose account is the
   * event's `account`.
   */
  subscription: Wide;
  /**
   * SIPRAL_PRESENCE_KIND_WATCHED: a sipral_basic_t, open when any
   * of the presentity's tuples is open.
   */
  basic: number;
  /**
   * SIPRAL_PRESENCE_KIND_WATCHED: a sipral_activity_t, the first
   * the person listed.
   */
  activity: number;
  /**
   * SIPRAL_PRESENCE_KIND_WATCHED: the presentity, as the document
   * named it. Not NUL-terminated.
   */
  entity: Pointer;
  /**
   * How many bytes of it.
   */
  entity_len: number;
  /**
   * SIPRAL_PRESENCE_KIND_WATCHED: the first note, the document's
   * own or else a tuple's. Null when there is none.
   */
  note: Pointer;
  /**
   * How many bytes of it.
   */
  note_len: number;
  /**
   * SIPRAL_PRESENCE_KIND_PUBLICATION: a sipral_publication_state_t.
   */
  publication_state: number;
  /**
   * SIPRAL_PRESENCE_KIND_PUBLICATION: a sipral_publish_failure_t
   * when the state is SIPRAL_PUBLICATION_STATE_FAILED.
   */
  failure: number;
  /**
   * SIPRAL_PRESENCE_KIND_PUBLICATION: the status the compositor
   * answered with, when one did.
   */
  status_code: number;
  /**
   * SIPRAL_PRESENCE_KIND_PUBLICATION: the lifetime granted, in
   * milliseconds, when it was published.
   */
  expires_ms: Wide;
  /**
   * SIPRAL_PRESENCE_KIND_PUBLICATION: how long until the stack
   * refreshes it, in milliseconds.
   */
  refresh_in_ms: Wide;
}
koffi.struct('sipral_presence_event_t', {
  kind: 'sipral_presence_kind_t',
  subscription: 'sipral_handle_t',
  basic: 'sipral_basic_t',
  activity: 'sipral_activity_t',
  entity: 'void *',
  entity_len: 'size_t',
  note: 'void *',
  note_len: 'size_t',
  publication_state: 'sipral_publication_state_t',
  failure: 'sipral_publish_failure_t',
  status_code: 'uint32_t',
  expires_ms: 'uint64_t',
  refresh_in_ms: 'uint64_t',
});

/**
 * The payload of `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`: a transport this
 * stack signals on stopped carrying traffic.
 *
 * The text is the library's, valid for as long as the callback runs.
 */
export interface SipralTransportFailedEvent {
  /**
   * Which transport: SIPRAL_TRANSPORT_MAIN, or a number
   * sipral_stack_transport_bind added.
   */
  transport: number;
  /**
   * What it spoke, as a `sipral_transport_t`.
   */
  protocol: number;
  /**
   * A sipral_transport_error_t: what the application said went wrong,
   * `SIPRAL_TRANSPORT_ERROR_CLOSED` for a connection that closed.
   */
  error: number;
  /**
   * A sipral_tls_failure_t: why TLS refused, when that is what it was.
   */
  tls: number;
  /**
   * The platform's own sentence, as the application handed it over.
   * Null with a length of zero when it gave none.
   */
  detail: Pointer;
  /**
   * How many bytes of it.
   */
  detail_len: number;
}
koffi.struct('sipral_transport_failed_event_t', {
  transport: 'uint32_t',
  protocol: 'sipral_transport_t',
  error: 'sipral_transport_error_t',
  tls: 'sipral_tls_failure_t',
  detail: 'void *',
  detail_len: 'size_t',
});

/**
 * What a `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` carries.
 */
export interface SipralLocalConferenceEvent {
  /**
   * The conference.
   */
  conference: Wide;
  /**
   * A sipral_local_conference_change_t.
   */
  change: number;
  /**
   * A sipral_departure_t, for `SIPRAL_LOCAL_CONFERENCE_CHANGE_LEFT`.
   */
  departure: number;
  /**
   * Who joined or left: a call, or the conference's own handle for
   * this end. `SIPRAL_HANDLE_NONE` for the other changes.
   */
  member: Wide;
  /**
   * Members now, this end included.
   */
  members: number;
  /**
   * Members talking now.
   */
  talkers: number;
  /**
   * The loudest of them, or `SIPRAL_HANDLE_NONE`.
   */
  loudest: Wide;
}
koffi.struct('sipral_local_conference_event_t', {
  conference: 'sipral_handle_t',
  change: 'sipral_local_conference_change_t',
  departure: 'sipral_departure_t',
  member: 'sipral_handle_t',
  members: 'uint32_t',
  talkers: 'uint32_t',
  loudest: 'sipral_handle_t',
});

/**
 * What a SIPRAL_EVENT_KIND_LOOKUP_WANTED,
 * a SIPRAL_EVENT_KIND_LOCATED
 * and a SIPRAL_EVENT_KIND_LOCATE_FAILED
 * carry, the account being `sipral_event_t::account`.
 *
 * One struct for the three, the way `sipral_subscription_event_t`
 * answers for two kinds: a member meaningless on one kind is zero or
 * null there. Every pointer is the library's, valid for the duration of
 * the callback.
 */
export interface SipralLocateEvent {
  /**
   * A sipral_dns_record_type_t: what to ask `name` for, on a lookup.
   */
  record: number;
  /**
   * A sipral_locate_failure_t: why a lookup named no address.
   */
  failure: number;
  /**
   * The name to ask, on a lookup: `_sip._udp.example.com`, or a
   * host. Handed back to sipral_account_looked_up with the answer.
   * UTF-8, not NUL-terminated.
   */
  name: Pointer;
  /**
   * How many bytes of it.
   */
  name_len: number;
  /**
   * Where the account's server was located: every address the answer
   * named, as `host:port` separated by commas, in RFC 3263 section
   * 4.3's order from the one the account's requests go to now. UTF-8,
   * not NUL-terminated.
   */
  targets: Pointer;
  /**
   * How many bytes of it.
   */
  targets_len: number;
  /**
   * When the name is looked up again after a failure, in
   * milliseconds. An address an earlier answer named stays in use
   * meanwhile.
   */
  retry_in_ms: Wide;
}
koffi.struct('sipral_locate_event_t', {
  record: 'sipral_dns_record_type_t',
  failure: 'sipral_locate_failure_t',
  name: 'void *',
  name_len: 'size_t',
  targets: 'void *',
  targets_len: 'size_t',
  retry_in_ms: 'uint64_t',
});

/**
 * What a SIPRAL_EVENT_KIND_CHALLENGE_DECLINED carries: who asked for
 * the account's password, and why it was not given (ABI 0.36).
 */
export interface SipralChallengeEvent {
  /**
   * A sipral_challenge_refusal_t.
   */
  refusal: number;
  /**
   * Where the challenged request went, and the refusal came from, as
   * `host:port`. Not NUL-terminated.
   */
  server: Pointer;
  /**
   * How many bytes of it.
   */
  server_len: number;
  /**
   * The realms it was challenged for, each on a line of its own,
   * separated by line feeds: a realm may hold a comma, and never a
   * line break. UTF-8, not NUL-terminated.
   */
  realms: Pointer;
  /**
   * How many bytes of it.
   */
  realms_len: number;
}
koffi.struct('sipral_challenge_event_t', {
  refusal: 'sipral_challenge_refusal_t',
  server: 'void *',
  server_len: 'size_t',
  realms: 'void *',
  realms_len: 'size_t',
});

/**
 * What a SIPRAL_EVENT_KIND_TOKEN_REQUIRED carries: the `Bearer`
 * challenge of an account's server (RFC 8898 §4), and where it came
 * from (ABI 1.2). Every text is UTF-8 and not NUL-terminated; one the
 * server left out is empty.
 */
export interface SipralTokenEvent {
  /**
   * A sipral_token_error_t.
   */
  error: number;
  /**
   * A `sipral_toggle_t`: `SIPRAL_TOGGLE_ON` when a proxy asked (407,
   * answered in `Proxy-Authorization`), `SIPRAL_TOGGLE_OFF` when the
   * registrar or the far end did (401).
   */
  proxy: number;
  /**
   * Where the challenged request went, and the challenge came from,
   * as `host:port`.
   */
  server: Pointer;
  /**
   * How many bytes of it.
   */
  server_len: number;
  /**
   * The protection domain, empty when the challenge named none.
   */
  realm: Pointer;
  /**
   * How many bytes of it.
   */
  realm_len: number;
  /**
   * The scope the token has to carry: space-separated strings the
   * authorization server defines (RFC 6749 §3.3).
   */
  scope: Pointer;
  /**
   * How many bytes of it.
   */
  scope_len: number;
  /**
   * The authorization server: an `https` URI. A value that was not
   * one is left out.
   */
  authz_server: Pointer;
  /**
   * How many bytes of it.
   */
  authz_server_len: number;
  /**
   * The `error` code as the server wrote it, for `Other`.
   */
  error_code: Pointer;
  /**
   * How many bytes of it.
   */
  error_code_len: number;
}
koffi.struct('sipral_token_event_t', {
  error: 'sipral_token_error_t',
  proxy: 'sipral_toggle_t',
  server: 'void *',
  server_len: 'size_t',
  realm: 'void *',
  realm_len: 'size_t',
  scope: 'void *',
  scope_len: 'size_t',
  authz_server: 'void *',
  authz_server_len: 'size_t',
  error_code: 'void *',
  error_code_len: 'size_t',
});

/**
 * What a SIPRAL_EVENT_KIND_NETWORK_TEST
 * carries: every part of one test, and the verdict (ABI 1.2). The
 * event's `account` is the account probed and its `call` the echo call,
 * when there were any. The two addresses are `host:port`, not
 * NUL-terminated, and the library's: valid for as long as the callback
 * runs.
 */
export interface SipralNetworkTestEvent {
  /**
   * The number sipral_stack_network_test gave the test.
   */
  test: number;
  /**
   * A sipral_network_verdict_t: the worst of the parts tested.
   */
  verdict: number;
  /**
   * A sipral_network_probe_t: whether a STUN server answered.
   */
  stun: number;
  /**
   * A sipral_nat_kind_t, from that answer.
   */
  nat: number;
  /**
   * A sipral_network_probe_t: whether the TURN server allocated a
   * relay for the probe socket.
   */
  turn: number;
  /**
   * A `sipral_transport_t`: what the TURN server was reached over, or
   * zero when it was not tested.
   */
  turn_protocol: number;
  /**
   * A sipral_server_reach_t.
   */
  server: number;
  /**
   * The status the server answered with, or zero.
   */
  server_status: number;
  /**
   * From sending the `OPTIONS` to its answer, in milliseconds.
   */
  server_round_trip_ms: number;
  /**
   * A sipral_network_probe_t: whether audio came back on the echo call
   * and was measured. Failed for a call whose media never started, or
   * that brought nothing back.
   */
  echo: number;
  /**
   * A sipral_network_verdict_t for the echo alone.
   */
  echo_verdict: number;
  /**
   * Packets lost or too late to play, as a percentage of those due.
   */
  loss_percent: number;
  /**
   * Interarrival jitter (RFC 3550 §6.4.1), in milliseconds.
   */
  jitter_ms: number;
  /**
   * Nonzero when RTCP brought a round trip back in time.
   */
  has_round_trip: number;
  /**
   * That round trip, in milliseconds.
   */
  round_trip_ms: number;
  /**
   * The one-way delay the rating assumed: half the round trip and the
   * jitter buffer's delay, in milliseconds.
   */
  one_way_delay_ms: number;
  /**
   * G.107's transmission rating R, 0 to 100, for concealed G.711.
   */
  r_factor: number;
  /**
   * The conversational mean opinion score estimated from it, 1.0 to
   * 4.5.
   */
  mos: number;
  /**
   * The socket the STUN answer was about: the probe socket, or the
   * signalling socket.
   */
  local: Pointer;
  /**
   * How many bytes of it.
   */
  local_len: number;
  /**
   * Where the STUN server saw it. Empty without an answer.
   */
  mapped: Pointer;
  /**
   * How many bytes of it.
   */
  mapped_len: number;
}
koffi.struct('sipral_network_test_event_t', {
  test: 'uint32_t',
  verdict: 'sipral_network_verdict_t',
  stun: 'sipral_network_probe_t',
  nat: 'sipral_nat_kind_t',
  turn: 'sipral_network_probe_t',
  turn_protocol: 'sipral_transport_t',
  server: 'sipral_server_reach_t',
  server_status: 'uint32_t',
  server_round_trip_ms: 'uint32_t',
  echo: 'sipral_network_probe_t',
  echo_verdict: 'sipral_network_verdict_t',
  loss_percent: 'float',
  jitter_ms: 'float',
  has_round_trip: 'uint32_t',
  round_trip_ms: 'uint32_t',
  one_way_delay_ms: 'uint32_t',
  r_factor: 'uint32_t',
  mos: 'float',
  local: 'void *',
  local_len: 'size_t',
  mapped: 'void *',
  mapped_len: 'size_t',
});

/**
 * The arm of an event that its kind names.
 *
 * The whole union is zeroed before that one arm is written, so every
 * byte past the arm, and every byte of another arm, reads as zero —
 * which is what a member appended to an arm later reads as from a
 * library built before it. Another arm still means nothing for this
 * kind.
 */
export interface SipralEventPayload {
  /**
   * For SIPRAL_EVENT_KIND_REGISTRATION_CHANGED.
   */
  registration: SipralRegistrationEvent;
  /**
   * For every call kind.
   */
  call: SipralCallEvent;
  /**
   * For SIPRAL_EVENT_KIND_TRANSFER_REQUESTED,
   * SIPRAL_EVENT_KIND_TRANSFER_PROGRESS and
   * SIPRAL_EVENT_KIND_TRANSFER_DONE.
   */
  transfer: SipralTransferEvent;
  /**
   * For every media kind: started, changed, stalled, resumed, failed, the
   * end-of-call statistics, and a recording that stopped by itself.
   */
  media: SipralMediaEvent;
  /**
   * For SIPRAL_EVENT_KIND_RECOVERY.
   */
  recovery: SipralRecoveryEvent;
  /**
   * For SIPRAL_EVENT_KIND_TRANSPORT_WANTED.
   */
  transport_wanted: SipralTransportWantedEvent;
  /**
   * For SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED and
   * SIPRAL_EVENT_KIND_NOTIFIED.
   */
  subscription: SipralSubscriptionEvent;
  /**
   * For SIPRAL_EVENT_KIND_CALL_ANNOUNCED and
   * SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING.
   */
  announce: SipralAnnounceEvent;
  /**
   * For SIPRAL_EVENT_KIND_RESOLVE_NEEDED.
   */
  resolve: SipralResolveEvent;
  /**
   * For SIPRAL_EVENT_KIND_MESSAGE_RECEIVED,
   * SIPRAL_EVENT_KIND_MESSAGE_SENT and
   * SIPRAL_EVENT_KIND_MESSAGES_WAITING.
   */
  message: SipralMessageEvent;
  /**
   * For SIPRAL_EVENT_KIND_NAT_MAPPING.
   */
  nat: SipralNatEvent;
  /**
   * For SIPRAL_EVENT_KIND_NAT_RELAY.
   */
  relay: SipralNatRelayEvent;
  /**
   * For SIPRAL_EVENT_KIND_REFERRAL.
   */
  referral: SipralReferralEvent;
  /**
   * For SIPRAL_EVENT_KIND_TURN_STREAM.
   */
  turn_stream: SipralTurnStreamEvent;
  /**
   * For SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED.
   */
  audio: SipralAudioEvent;
  /**
   * For SIPRAL_EVENT_KIND_STUN_SERVER.
   */
  stun_server: SipralStunServerEvent;
  /**
   * For SIPRAL_EVENT_KIND_CALLER_VERIFICATION.
   */
  verification: SipralVerificationEvent;
  /**
   * For SIPRAL_EVENT_KIND_PROGRESS_DETECTED.
   */
  progress: SipralProgressEvent;
  /**
   * For SIPRAL_EVENT_KIND_CONFERENCE_CHANGED.
   */
  conference: SipralConferenceEvent;
  /**
   * For SIPRAL_EVENT_KIND_TEXT_RECEIVED.
   */
  text: SipralTextEvent;
  /**
   * For SIPRAL_EVENT_KIND_PRESENCE_CHANGED.
   */
  presence: SipralPresenceEvent;
  /**
   * For SIPRAL_EVENT_KIND_TRANSPORT_FAILED.
   */
  transport_failed: SipralTransportFailedEvent;
  /**
   * For SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED.
   */
  local_conference: SipralLocalConferenceEvent;
  /**
   * For SIPRAL_EVENT_KIND_LOOKUP_WANTED, SIPRAL_EVENT_KIND_LOCATED
   * and SIPRAL_EVENT_KIND_LOCATE_FAILED.
   */
  locate: SipralLocateEvent;
  /**
   * For SIPRAL_EVENT_KIND_CHALLENGE_DECLINED.
   */
  challenge: SipralChallengeEvent;
  /**
   * For SIPRAL_EVENT_KIND_TOKEN_REQUIRED.
   */
  token: SipralTokenEvent;
  /**
   * For SIPRAL_EVENT_KIND_NETWORK_TEST.
   */
  network_test: SipralNetworkTestEvent;
}
koffi.union('sipral_event_payload_t', {
  registration: 'sipral_registration_event_t',
  call: 'sipral_call_event_t',
  transfer: 'sipral_transfer_event_t',
  media: 'sipral_media_event_t',
  recovery: 'sipral_recovery_event_t',
  transport_wanted: 'sipral_transport_wanted_event_t',
  subscription: 'sipral_subscription_event_t',
  announce: 'sipral_announce_event_t',
  resolve: 'sipral_resolve_event_t',
  message: 'sipral_message_event_t',
  nat: 'sipral_nat_event_t',
  relay: 'sipral_nat_relay_event_t',
  referral: 'sipral_referral_event_t',
  turn_stream: 'sipral_turn_stream_event_t',
  audio: 'sipral_audio_event_t',
  stun_server: 'sipral_stun_server_event_t',
  verification: 'sipral_verification_event_t',
  progress: 'sipral_progress_event_t',
  conference: 'sipral_conference_event_t',
  text: 'sipral_text_event_t',
  presence: 'sipral_presence_event_t',
  transport_failed: 'sipral_transport_failed_event_t',
  local_conference: 'sipral_local_conference_event_t',
  locate: 'sipral_locate_event_t',
  challenge: 'sipral_challenge_event_t',
  token: 'sipral_token_event_t',
  network_test: 'sipral_network_test_event_t',
});

/**
 * Something the library has to tell the application.
 *
 * The pointer handed to the callback is the library's, and it is valid for
 * the duration of that call and no longer. `size` says how much of the
 * struct this build filled in, and a binding reads no further than that. The
 * union stays the last member for the same reason: an arm that grows grows
 * the tail, which is the one place a released struct may change.
 */
export interface SipralEvent {
  /**
   * How many bytes of this struct are meaningful.
   */
  size: number;
  /**
   * The stack it is about.
   */
  stack: Wide;
  /**
   * What it is.
   */
  kind: number;
  /**
   * The account it is about, or SIPRAL_HANDLE_NONE.
   */
  account: Wide;
  /**
   * The call it is about, or SIPRAL_HANDLE_NONE.
   */
  call: Wide;
  /**
   * The SIP message behind it, whole and unparsed, when there is one.
   *
   * A reason phrase, a `Retry-After`, the `Contact` of a redirect and the
   * caller's display name all live here and none of them is worth a member
   * of its own. Null when the event came from no single message.
   */
  message: Pointer;
  /**
   * How many bytes of it.
   */
  message_len: number;
  /**
   * The arm sipral_event_t::kind names.
   */
  payload: SipralEventPayload;
}
koffi.struct('sipral_event_t', {
  size: 'size_t',
  stack: 'sipral_handle_t',
  kind: 'sipral_event_kind_t',
  account: 'sipral_handle_t',
  call: 'sipral_handle_t',
  message: 'void *',
  message_len: 'size_t',
  payload: 'sipral_event_payload_t',
});

/**
 * What was standing when the process was told it is about to stop
 * (sipral_stack_suspending's `out_report`).
 *
 * Set `size` to `sizeof(sipral_suspending_t)` before the call. Counts
 * and nothing else, because the window this is produced in is one where
 * an allocation that grows with the number of accounts is a cost with no
 * upper bound worth paying. Everything in it is already past tense by
 * the time it is read: the bindings have stopped being evidence, the
 * subscriptions have stopped being evidence, and nothing was sent about
 * either.
 */
export interface SipralSuspending {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * Bindings that read as live and do not any more.
   */
  unverified: number;
  /**
   * Subscriptions whose last notification stopped being evidence.
   */
  subscriptions: number;
  /**
   * Calls that were up. Nothing was sent about them and nothing was
   * changed: a lid closing and opening again is seconds, and hanging
   * up a live call because the machine blinked is worse than finding
   * out a few seconds later that it is gone.
   */
  calls: number;
}
koffi.struct('sipral_suspending_t', {
  size: 'size_t',
  unverified: 'size_t',
  subscriptions: 'size_t',
  calls: 'size_t',
});

/**
 * What sipral_screen_callback_t reads about one INVITE, before it has
 * had any effect at all.
 *
 * Filled by the library and handed to the callback as a `const`
 * pointer, the same shape sipral_event_t is: read `size`
 * before anything past it, and read nothing once the callback has
 * returned, since `message` — and `source`, when it is not null —
 * borrow from a request that is still in the middle of being processed
 * and are not this ABI's to keep alive a moment longer. The answer does
 * not travel in here: the callback returns it.
 */
export interface SipralScreenRequest {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * The stack the INVITE arrived on.
   */
  stack: Wide;
  /**
   * The far end of the bytes it arrived in, as `host:port` — the same
   * text form every address in this ABI takes. Null and zero for a
   * byte stream the application bound without naming its far end.
   */
  source: Pointer;
  /**
   * How many bytes of it.
   */
  source_len: number;
  /**
   * The INVITE, whole and unparsed. `sipral_message_header` and its
   * three companions read any header out of these bytes the way they
   * read any other message this ABI hands over.
   */
  message: Pointer;
  /**
   * How many bytes of it.
   */
  message_len: number;
}
koffi.struct('sipral_screen_request_t', {
  size: 'size_t',
  stack: 'sipral_handle_t',
  source: 'void *',
  source_len: 'size_t',
  message: 'void *',
  message_len: 'size_t',
});

/**
 * What to watch, and how. Handed to sipral_account_subscribe.
 *
 * Set `size` to `sizeof(sipral_subscribe_config_t)` before the call.
 * Everything but `target` and `package` may be left zero.
 */
export interface SipralSubscribeConfig {
  /**
   * How long this struct is, as the caller's header declares it.
   */
  size: number;
  /**
   * What to watch, as a SIP URI: `sip:2001@pbx.example.com`.
   */
  target: Pointer;
  /**
   * How many bytes of it.
   */
  target_len: number;
  /**
   * The event package, as the token that names it: `dialog` for a busy
   * lamp field (RFC 4235 §3.1), `message-summary` for message waiting
   * (RFC 3842 §3), `presence` (RFC 3856 §6.1).
   *
   * It goes out exactly as written here, because §8.2.1 compares it
   * byte for byte.
   */
  'package': Pointer;
  /**
   * How many bytes of it.
   */
  package_len: number;
  /**
   * The `Accept` value, when the package's default body type is not
   * the one wanted. Null sends no `Accept` at all, which §3.1.3 makes
   * the package's default — `application/dialog-info+xml` for
   * `dialog`.
   *
   * Sending the wrong one is worse than sending none: §4.1.2.1 has the
   * notifier answer 406 for a type it cannot generate, so nothing is
   * guessed on a caller's behalf.
   */
  accept: Pointer;
  /**
   * How many bytes of it.
   */
  accept_len: number;
  /**
   * How long to ask for, in seconds, or zero for this build's default
   * of one hour.
   *
   * What the notifier grants wins (§3.1.1: "The period of time in the
   * response is the one that defines the duration of the
   * subscription"), and the refresh is scheduled against that rather
   * than against this.
   */
  expires_seconds: number;
  /**
   * Where to send the SUBSCRIBE, as `host:port`, or null to send it
   * where the account registers — which is the outbound proxy for a
   * registered line, and the reason a phone behind a NAT is reachable
   * at all.
   */
  destination: Pointer;
  /**
   * How many bytes of it.
   */
  destination_len: number;
  /**
   * Which transport it goes out on, read only together with
   * `destination`, exactly as `sipral_call_config_t::transport` is.
   * Nonzero with `destination` null is
   * `SIPRAL_STATUS_INVALID_ARGUMENT`.
   */
  transport: number;
  /**
   * Zero. Rounds the struct up to a whole multiple of its alignment on
   * every target, so that a member a later version appends starts at or
   * past the length a caller built against this header declares, never
   * in padding inside it. Set it to zero; the library reads nothing from
   * it.
   */
  reserved: number;
}
koffi.struct('sipral_subscribe_config_t', {
  size: 'size_t',
  target: 'void *',
  target_len: 'size_t',
  'package': 'void *',
  package_len: 'size_t',
  accept: 'void *',
  accept_len: 'size_t',
  expires_seconds: 'uint32_t',
  destination: 'void *',
  destination_len: 'size_t',
  transport: 'uint32_t',
  reserved: 'uint32_t',
});

/**
 * One dialog a `dialog` subscription has been told about, with the text
 * left behind: sipral_subscription_dialog_text reads that, because a
 * pointer into this library's own memory would be a pointer a caller
 * could outlive.
 */
export interface SipralWatchedDialog {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * A sipral_dialog_phase_t.
   */
  phase: number;
  /**
   * A sipral_dialog_direction_t.
   */
  direction: number;
  /**
   * A sipral_dialog_ended_t, and zero while the dialog has not.
   */
  ended: number;
  /**
   * The SIP status behind how it ended, when the notifier sent one.
   * Zero otherwise.
   */
  status_code: number;
  /**
   * How long it has been up, in milliseconds, when the notifier sent a
   * duration. Zero otherwise.
   */
  duration_ms: Wide;
}
koffi.struct('sipral_watched_dialog_t', {
  size: 'size_t',
  phase: 'sipral_dialog_phase_t',
  direction: 'sipral_dialog_direction_t',
  ended: 'sipral_dialog_ended_t',
  status_code: 'uint32_t',
  duration_ms: 'uint64_t',
});

/**
 * What the registrar said about push, in the 2xx to a REGISTER that
 * asked for it (RFC 8599 §8.2).
 */
export interface SipralPushEcho {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * Whether the network said it will ask for notifications of the type
   * this account asked for. Zero means it did not say so, which §4.1.1
   * makes "MUST NOT assume they are coming" rather than "they are not":
   * an application that suspends itself on the strength of a push it
   * was never promised stops ringing.
   */
  accepted: number;
  /**
   * Whether `refresh_lead_ms` was sent at all.
   */
  has_refresh_lead: number;
  /**
   * How long before the binding lapses the network insists on seeing a
   * refresh, from a `sip.pnsreg` indicator (§4.1.4), in milliseconds.
   * Zero when the network sent none, which `has_refresh_lead` is how to
   * tell from a lead of zero.
   */
  refresh_lead_ms: Wide;
}
koffi.struct('sipral_push_echo_t', {
  size: 'size_t',
  accepted: 'uint32_t',
  has_refresh_lead: 'uint32_t',
  refresh_lead_ms: 'uint64_t',
});

/**
 * One device, as `sipral_audio_device_at` fills it in. The name is
 * written beside it, into the caller's buffer.
 *
 * Set `size` to `sizeof(sipral_audio_device_t)` before the call.
 */
export interface SipralAudioDevice {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * The engine's name for the device: stable across refreshes, never
   * reused, never zero. What `sipral_audio_select` takes.
   */
  id: number;
  /**
   * How many channels it captures; zero for a device that is no
   * microphone.
   */
  input_channels: number;
  /**
   * How many channels it plays; zero likewise.
   */
  output_channels: number;
  /**
   * One when the system records from it by default.
   */
  default_input: number;
  /**
   * One when the system plays to it by default.
   */
  default_output: number;
  /**
   * One when the last refresh still found it. A device that went
   * keeps its row and its id, so that a selection saved against it
   * still names something.
   */
  present: number;
}
koffi.struct('sipral_audio_device_t', {
  size: 'size_t',
  id: 'uint32_t',
  input_channels: 'uint32_t',
  output_channels: 'uint32_t',
  default_input: 'uint32_t',
  default_output: 'uint32_t',
  present: 'uint32_t',
});

/**
 * What the engine is doing, as `sipral_audio_info` fills it in.
 *
 * Set `size` to `sizeof(sipral_audio_info_t)` before the call.
 */
export interface SipralAudioInfo {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * One while the devices are open and the pump is running.
   */
  active: number;
  /**
   * One when the platform's own processing sits behind the
   * microphone: the voice-processing unit on macOS and iOS, which
   * cancels the loudspeaker's echo itself; on Windows, a stream
   * accepted as a communications stream, which puts the endpoint's
   * own processing behind it where the endpoint has any — a virtual
   * cable has none, and cancels nothing. An application that wants
   * the echo gone regardless attaches a processor to each call with
   * `sipral_media_attach_processor`; the delay it needs is
   * `render_delay_ms`, and the engine tells each managed call that
   * number itself, again after every device change.
   */
  system_echo_cancellation: number;
  /**
   * The loudspeaker-to-microphone delay the devices report, in
   * milliseconds.
   */
  render_delay_ms: Wide;
  /**
   * The rate the microphone runs at, or zero when it is not open.
   */
  microphone_rate_hz: number;
  /**
   * The rate the loudspeaker runs at, or zero when it is not open.
   */
  speaker_rate_hz: number;
  /**
   * The device the microphone is running on, or zero.
   */
  microphone: number;
  /**
   * The device the loudspeaker is running on, or zero.
   */
  speaker: number;
  /**
   * The device the ringer is running on, or zero when the ring goes
   * through the loudspeaker.
   */
  ringer: number;
  /**
   * Zero. Rounds the struct up to a whole multiple of its alignment on
   * every target, so that a member a later version appends starts at or
   * past the length a caller built against this header declares, never
   * in padding inside it. The library writes zero here and reads nothing
   * from it.
   */
  reserved: number;
}
koffi.struct('sipral_audio_info_t', {
  size: 'size_t',
  active: 'uint32_t',
  system_echo_cancellation: 'uint32_t',
  render_delay_ms: 'uint64_t',
  microphone_rate_hz: 'uint32_t',
  speaker_rate_hz: 'uint32_t',
  microphone: 'uint32_t',
  speaker: 'uint32_t',
  ringer: 'uint32_t',
  reserved: 'uint32_t',
});

/**
 * One packet the engine encoded from the microphone, handed to
 * `sipral_stack_config_t::audio_transmit_callback`: send it from the
 * call's media socket and return.
 *
 * Filled by the library and handed to the callback as a `const`
 * pointer, the shape `sipral_processor_frame_t` is: read `size` before
 * anything past it, and read nothing once the callback has returned.
 * The callback runs on the engine's own thread, once per frame per
 * call; it may call `sipral_media_receive` and the other media entry
 * points, and must not destroy the stack.
 */
export interface SipralAudioTransmit {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * The call whose socket this leaves from.
   */
  call: Wide;
  /**
   * How it leaves, as a `sipral_transport_t`: `SIPRAL_TRANSPORT_UDP` is
   * a datagram from the media socket; `SIPRAL_TRANSPORT_TCP` and
   * `SIPRAL_TRANSPORT_TLS` are bytes to write, in order, on the
   * socket's connection to its TURN server, as `sipral_media_capture`
   * marks them.
   */
  protocol: number;
  /**
   * Zero. Keeps the members after it where a 32-bit and a 64-bit target
   * both put them without padding at the end of the struct, so that a
   * member a later version appends starts past the length a caller built
   * against this header declares. The library writes zero here and reads
   * nothing from it.
   */
  reserved: number;
  /**
   * Where to send it, `host:port`, UTF-8 and not NUL-terminated.
   */
  destination: Pointer;
  /**
   * How many bytes of it.
   */
  destination_len: number;
  /**
   * The octets.
   */
  payload: Pointer;
  /**
   * How many of them.
   */
  payload_len: number;
}
koffi.struct('sipral_audio_transmit_t', {
  size: 'size_t',
  call: 'sipral_handle_t',
  protocol: 'sipral_transport_t',
  reserved: 'uint32_t',
  destination: 'void *',
  destination_len: 'size_t',
  payload: 'void *',
  payload_len: 'size_t',
});

/**
 * One log line, as sipral_log_callback_t reads it.
 *
 * Filled by the library and handed over as a `const` pointer: read
 * `size` before anything past it, and nothing once the callback has
 * returned — the two strings are the library's and live for the call
 * alone.
 */
export interface SipralLogRecord {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * The stack the line is about.
   */
  stack: Wide;
  /**
   * A `sipral_log_level_t`, never `SIPRAL_LOG_LEVEL_OFF`.
   */
  level: number;
  /**
   * Which part of the stack wrote it — `registration`, `call`,
   * `media`, `decision`, `sip`, `api` — as UTF-8, not NUL-terminated.
   */
  target: Pointer;
  /**
   * How many bytes of it.
   */
  target_len: number;
  /**
   * The line, already redacted, as UTF-8, not NUL-terminated. A
   * `SIPRAL_LOG_LEVEL_TRACE` line holding a whole message has line
   * breaks in it.
   */
  message: Pointer;
  /**
   * How many bytes of it.
   */
  message_len: number;
  /**
   * How many lines the rate limit or the queue ceiling turned away
   * since the line before this one. Zero almost always.
   */
  suppressed: Wide;
}
koffi.struct('sipral_log_record_t', {
  size: 'size_t',
  stack: 'sipral_handle_t',
  level: 'sipral_log_level_t',
  target: 'void *',
  target_len: 'size_t',
  message: 'void *',
  message_len: 'size_t',
  suppressed: 'uint64_t',
});

/**
 * How a stack verifies the callers of the calls its accounts receive.
 *
 * Set `size` to `sizeof(sipral_stir_config_t)` and zero the rest before
 * filling anything in.
 */
export interface SipralStirConfig {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * The trust anchors — the STI-PA's approved roots in a SHAKEN
   * deployment — as PEM or DER certificates, one after another. Null
   * and zero for none, which turns verification off for every account
   * that only reports.
   */
  anchors: Pointer;
  /**
   * How many bytes of them.
   */
  anchors_len: number;
  /**
   * How far a PASSporT's `iat` may be from now, either way, in
   * seconds; zero for RFC 8224 §6.2's sixty.
   */
  freshness_seconds: Wide;
  /**
   * How long a call waits for `sipral_call_stir_certificate` before
   * its certificate counts as one that could not be had, in
   * milliseconds; zero for four seconds.
   */
  certificate_wait_ms: Wide;
  /**
   * The wall clock at `now_ms`, in seconds since 1970, or zero to keep
   * the one an earlier call gave. A PASSporT is signed and judged by
   * the time, and only the caller can say which `now_ms` a time goes
   * with, so the first call must give it.
   * (`sipral_stack_config_t::media_clock_unix_seconds` goes with no
   * `now_ms` at all, and is not taken for it.) A stack created with no
   * media clock dates its RTCP sender reports by this one too.
   */
  unix_seconds: Wide;
  /**
   * A `sipral_toggle_t`: whether a certificate whose TNAuthList names a
   * service provider code (RFC 8226 §9) has authority over every
   * calling number. Off by default, when only the numbers and ranges a
   * certificate names are its own: a code names a provider, not
   * numbers, and taking it as covering any number is a decision about
   * the providers the anchors certify — the one a SHAKEN deployment,
   * whose certificates carry codes and no numbers, makes by turning
   * this on. ABI 0.32.
   */
  accept_service_provider_codes: number;
  /**
   * Zero. Rounds the struct up to a whole multiple of its alignment on
   * every target, so that a member a later version appends starts at or
   * past the length a caller built against this header declares, never
   * in padding inside it. Set it to zero; the library reads nothing from
   * it.
   */
  reserved: number;
}
koffi.struct('sipral_stir_config_t', {
  size: 'size_t',
  anchors: 'void *',
  anchors_len: 'size_t',
  freshness_seconds: 'uint64_t',
  certificate_wait_ms: 'uint64_t',
  unix_seconds: 'uint64_t',
  accept_service_provider_codes: 'sipral_toggle_t',
  reserved: 'uint32_t',
});

/**
 * How one stream of a call is protected: one entry of the encryption
 * report.
 *
 * Set `size` to `sizeof(sipral_stream_encryption_t)` before the call.
 */
export interface SipralStreamEncryption {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * A sipral_media_kind_t: what the stream carries.
   */
  media: number;
  /**
   * Whether what it sends is encrypted and what it takes
   * authenticated, now. Zero while it waits for the handshake that
   * keys it.
   */
  encrypted: number;
  /**
   * A sipral_key_exchange_t: how its keys were exchanged.
   */
  key_exchange: number;
  /**
   * A sipral_srtp_suite_t: the transform it runs, once it runs one.
   */
  suite: number;
  /**
   * Whether the key exchange authenticated the far end: set for a
   * DTLS-SRTP stream once its handshake finished, the far end's
   * certificate having matched its signalled fingerprint; never for
   * SDES, whose key is exactly as authentic as the signalling
   * transport, which this library cannot see.
   */
  authenticated: number;
  /**
   * Whether it agreed to be encrypted and is still waiting for its
   * keys.
   */
  awaiting_keys: number;
}
koffi.struct('sipral_stream_encryption_t', {
  size: 'size_t',
  media: 'sipral_media_kind_t',
  encrypted: 'uint32_t',
  key_exchange: 'sipral_key_exchange_t',
  suite: 'sipral_srtp_suite_t',
  authenticated: 'uint32_t',
  awaiting_keys: 'uint32_t',
});

/**
 * How sipral_call_detect_progress listens. Zero in any member but
 * `size` is that member's default.
 *
 * Set `size` to `sizeof(sipral_progress_config_t)` before the call.
 */
export interface SipralProgressConfig {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * A `sipral_toggle_t`: on (the default) listens with what follows,
   * off stops listening and reads nothing else.
   */
  listen: number;
  /**
   * A sipral_tone_region_t. Europe by default.
   */
  region: number;
  /**
   * A `sipral_toggle_t`: whether to decide who answered. On by default.
   */
  answering_machine: number;
  /**
   * A `sipral_toggle_t`: whether to listen for the beep after a verdict
   * of a machine. On by default.
   */
  beep: number;
  /**
   * How long after the verdict to listen for the beep. Thirty
   * seconds by default.
   */
  beep_window_ms: number;
  /**
   * The longest silence after answer before the verdict is not sure.
   * 3000 by default.
   */
  max_initial_silence_ms: number;
  /**
   * The longest greeting a person gives. 1600 by default.
   */
  max_greeting_ms: number;
  /**
   * The silence after a greeting that says a person is waiting. 700
   * by default.
   */
  silence_after_greeting_ms: number;
  /**
   * The most words a person's greeting has. 4 by default.
   */
  max_words: number;
  /**
   * The shortest run of speech that is a word. 120 by default.
   */
  min_word_ms: number;
  /**
   * The shortest silence that separates two words. 60 by default.
   */
  min_word_gap_ms: number;
  /**
   * The longest the decision may take, from answer. 6000 by default.
   */
  max_decision_ms: number;
  /**
   * How far above the noise floor a frame must be to be speech, in
   * dB. 6 by default.
   */
  min_speech_above_floor_db: number;
  /**
   * The shortest beep. 120 by default.
   */
  beep_min_ms: number;
  /**
   * The longest beep: anything held longer is a tone, not a beep.
   * This build's own default unless set.
   */
  beep_max_ms: number;
  /**
   * How many whole cycles of a repeating cadence are heard before the
   * tone is reported, from one to four. One by default.
   */
  tone_cycles: number;
}
koffi.struct('sipral_progress_config_t', {
  size: 'size_t',
  listen: 'sipral_toggle_t',
  region: 'sipral_tone_region_t',
  answering_machine: 'sipral_toggle_t',
  beep: 'sipral_toggle_t',
  beep_window_ms: 'uint32_t',
  max_initial_silence_ms: 'uint32_t',
  max_greeting_ms: 'uint32_t',
  silence_after_greeting_ms: 'uint32_t',
  max_words: 'uint32_t',
  min_word_ms: 'uint32_t',
  min_word_gap_ms: 'uint32_t',
  max_decision_ms: 'uint32_t',
  min_speech_above_floor_db: 'uint32_t',
  beep_min_ms: 'uint32_t',
  beep_max_ms: 'uint32_t',
  tone_cycles: 'uint32_t',
});

/**
 * The beep sipral_call_consent_tone plays while a call is recorded.
 * Zero in any member but `size` is that member's default.
 *
 * Set `size` to `sizeof(sipral_consent_tone_t)` before the call.
 */
export interface SipralConsentTone {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * A `sipral_toggle_t`: on (the default) beeps as what follows says,
   * off plays no tone and reads nothing else.
   */
  enabled: number;
  /**
   * Its frequency, from 300 to 3400 Hz. 1400 by default.
   */
  frequency_hz: number;
  /**
   * How far below 0 dBm0 it sounds, from 3 to 40 dB: 18 is a beep at
   * −18 dBm0, the default.
   */
  attenuation_db: number;
  /**
   * How long each beep lasts, from 50 to 2000 ms. 200 by default.
   */
  length_ms: number;
  /**
   * How often it repeats, start to start: longer than a beep and at
   * most ten minutes. Fifteen seconds by default.
   */
  interval_ms: number;
  /**
   * A `sipral_toggle_t`: whether this end hears it too. On by default.
   */
  local: number;
}
koffi.struct('sipral_consent_tone_t', {
  size: 'size_t',
  enabled: 'sipral_toggle_t',
  frequency_hz: 'uint32_t',
  attenuation_db: 'uint32_t',
  length_ms: 'uint32_t',
  interval_ms: 'uint32_t',
  local: 'sipral_toggle_t',
});

/**
 * How sipral_media_record_start_with writes a recording. Zero in
 * every member but `size` is sipral_media_record_start's file.
 *
 * Set `size` to `sizeof(sipral_recording_options_t)` before the call.
 */
export interface SipralRecordingOptions {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * A sipral_recording_format_t.
   */
  format: number;
  /**
   * A sipral_recording_layout_t.
   */
  layout: number;
  /**
   * The rate the file is written at, in hertz, or zero for the rate the
   * call's codec hears at when the recording starts (48 kHz for Ogg
   * Opus on a call at a rate Opus does not take). WAV takes 8000 to
   * 48000; Ogg Opus takes 8000, 12000, 16000, 24000 and 48000.
   */
  sample_rate: number;
  /**
   * An Ogg Opus recording's bitrate in bits a second, all channels
   * together, or zero for libopus's own choice. Not read for WAV.
   */
  bitrate: number;
  /**
   * How often, in milliseconds, what has been written is made to
   * survive a crash, or zero for every five seconds.
   */
  checkpoint_ms: number;
  /**
   * Zero. Rounds the struct up to a whole multiple of its alignment on
   * every target, so that a member a later version appends starts at or
   * past the length a caller built against this header declares, never
   * in padding inside it. Set it to zero; the library reads nothing from
   * it.
   */
  reserved: number;
}
koffi.struct('sipral_recording_options_t', {
  size: 'size_t',
  format: 'sipral_recording_format_t',
  layout: 'sipral_recording_layout_t',
  sample_rate: 'uint32_t',
  bitrate: 'uint32_t',
  checkpoint_ms: 'uint32_t',
  reserved: 'uint32_t',
});

/**
 * A conference as a `conference` subscription holds it, read with
 * sipral_subscription_conference.
 */
export interface SipralConference {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * The version of the last document merged.
   */
  version: number;
  /**
   * How many users the picture holds, which is what
   * sipral_subscription_conference_user_at reads by index.
   */
  users: number;
  /**
   * Whether the focus said how many users it counts
   * (`conference-state`'s `user-count`), which may differ from
   * `users`: a focus need not list every one.
   */
  has_user_count: number;
  /**
   * That count, when it said.
   */
  user_count: number;
  /**
   * `conference-state`'s `active`: one when the focus said it is, two
   * when it said it is not, zero when it said nothing.
   */
  active: number;
  /**
   * Its `locked`, the same way.
   */
  locked: number;
}
koffi.struct('sipral_conference_t', {
  size: 'size_t',
  version: 'uint32_t',
  users: 'uint32_t',
  has_user_count: 'uint32_t',
  user_count: 'uint32_t',
  active: 'uint32_t',
  locked: 'uint32_t',
});

/**
 * One user of a conference, read with
 * sipral_subscription_conference_user_at; its text is read with
 * sipral_subscription_conference_text.
 */
export interface SipralConferenceUser {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * How many endpoints — devices — the user is in the conference
   * from.
   */
  endpoints: number;
  /**
   * A sipral_endpoint_status_t: where the first of them is.
   */
  status: number;
  /**
   * How many media streams the first of them has.
   */
  media: number;
  /**
   * Zero. Rounds the struct up to a whole multiple of its alignment on
   * every target, so that a member a later version appends starts at or
   * past the length a caller built against this header declares, never
   * in padding inside it. The library writes zero here and reads nothing
   * from it.
   */
  reserved: number;
}
koffi.struct('sipral_conference_user_t', {
  size: 'size_t',
  endpoints: 'uint32_t',
  status: 'sipral_endpoint_status_t',
  media: 'uint32_t',
  reserved: 'uint32_t',
});

/**
 * This account's presence, as sipral_account_publish_presence takes
 * it.
 *
 * Set `size` to `sizeof(sipral_presence_t)` and zero the rest before
 * filling anything in.
 */
export interface SipralPresence {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * A sipral_basic_t, open or closed. Required.
   */
  basic: number;
  /**
   * A sipral_activity_t; SIPRAL_ACTIVITY_NONE publishes no
   * person at all. SIPRAL_ACTIVITY_OTHER is refused: there is no
   * name to publish it under.
   */
  activity: number;
  /**
   * A note a buddy list shows beside the name, UTF-8 and not
   * NUL-terminated, or null for none.
   */
  note: Pointer;
  /**
   * How many bytes of it.
   */
  note_len: number;
}
koffi.struct('sipral_presence_t', {
  size: 'size_t',
  basic: 'sipral_basic_t',
  activity: 'sipral_activity_t',
  note: 'void *',
  note_len: 'size_t',
});

/**
 * Where a call is recorded, as sipral_call_record_to takes it.
 *
 * Set `size` to `sizeof(sipral_record_config_t)` and zero the rest
 * before filling anything in.
 */
export interface SipralRecordConfig {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * The recording server's URI, the INVITE's target. Required. Not
   * NUL-terminated.
   */
  server: Pointer;
  /**
   * How many bytes of it.
   */
  server_len: number;
  /**
   * Where to send the INVITE, as an address and a port, when not
   * where the recorded call's account sends. Null for there.
   */
  destination: Pointer;
  /**
   * How many bytes of it.
   */
  destination_len: number;
  /**
   * The transport `destination` is reached over, as
   * `sipral_call_config_t::transport` names one. Read only with
   * `destination`.
   */
  transport: number;
  /**
   * The socket the copy of this end's audio goes from, as an address
   * and a port, and what the offer names for the stream labelled `1`.
   * Required: a socket the application bound.
   */
  this_end: Pointer;
  /**
   * How many bytes of it.
   */
  this_end_len: number;
  /**
   * The same for the far end's audio, labelled `2`. Required, and a
   * socket of its own.
   */
  far_end: Pointer;
  /**
   * How many bytes of it.
   */
  far_end_len: number;
}
koffi.struct('sipral_record_config_t', {
  size: 'size_t',
  server: 'void *',
  server_len: 'size_t',
  destination: 'void *',
  destination_len: 'size_t',
  transport: 'uint32_t',
  this_end: 'void *',
  this_end_len: 'size_t',
  far_end: 'void *',
  far_end_len: 'size_t',
});

/**
 * How `sipral_local_conference_create` makes a conference. Zero in
 * every member but `size` is a conference of sixteen with this end in
 * it at 16 kHz.
 *
 * Set `size` to `sizeof(sipral_local_conference_config_t)` before the
 * call.
 */
export interface SipralLocalConferenceConfig {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * The most members it holds at once, this end included, or zero
   * for sixteen. At most 1024.
   */
  max_members: number;
  /**
   * A `sipral_toggle_t`: whether this end takes part. On unless it is
   * `SIPRAL_TOGGLE_OFF`; a conference without this end only bridges
   * its calls.
   */
  local: number;
  /**
   * The rate of this end's frames in application mode, in hertz —
   * 8000, 16000, 32000 or 48000 — or zero for 16000. A tick's frame is
   * twenty milliseconds of it. In device mode the audio engine
   * converts the devices to it.
   */
  sample_rate: number;
  /**
   * Zero. Rounds the struct up to a whole multiple of its alignment on
   * every target, so that a member a later version appends starts at or
   * past the length a caller built against this header declares, never
   * in padding inside it. Set it to zero; the library reads nothing from
   * it.
   */
  reserved: number;
}
koffi.struct('sipral_local_conference_config_t', {
  size: 'size_t',
  max_members: 'uint32_t',
  local: 'sipral_toggle_t',
  sample_rate: 'uint32_t',
  reserved: 'uint32_t',
});

/**
 * A conference as it stands: `sipral_local_conference_info`.
 *
 * Set `size` to `sizeof(sipral_local_conference_info_t)` before the
 * call.
 */
export interface SipralLocalConferenceInfo {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * Members, this end included.
   */
  members: number;
  /**
   * The most it holds.
   */
  capacity: number;
  /**
   * Members talking in the last tick.
   */
  talkers: number;
  /**
   * 1 when this end takes part.
   */
  local: number;
  /**
   * The rate of this end's frames, in hertz.
   */
  sample_rate: number;
  /**
   * Samples in one of this end's frames: twenty milliseconds.
   */
  frame_samples: number;
  /**
   * 1 while the conference is being recorded.
   */
  recording: number;
  /**
   * How much has been recorded, while it is.
   */
  recorded_ms: Wide;
  /**
   * Packets dropped because nobody polled for them in time.
   */
  packets_dropped: Wide;
}
koffi.struct('sipral_local_conference_info_t', {
  size: 'size_t',
  members: 'uint32_t',
  capacity: 'uint32_t',
  talkers: 'uint32_t',
  local: 'uint32_t',
  sample_rate: 'uint32_t',
  frame_samples: 'uint32_t',
  recording: 'uint32_t',
  recorded_ms: 'uint64_t',
  packets_dropped: 'uint64_t',
});

/**
 * One member of a conference: `sipral_local_conference_member_at`.
 *
 * Set `size` to `sizeof(sipral_local_conference_member_t)` before the
 * call.
 */
export interface SipralLocalConferenceMember {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * The call, or the conference's own handle for this end.
   */
  member: Wide;
  /**
   * 1 when it was talking in the last tick, muted or not.
   */
  talking: number;
  /**
   * 1 when nobody hears it.
   */
  muted_input: number;
  /**
   * 1 when it hears nothing.
   */
  muted_output: number;
  /**
   * The level of what it says, in the steps `sipral_audio_set_gain`
   * takes: 256 is unity.
   */
  gain_input: number;
  /**
   * The level of what it hears, in the same steps.
   */
  gain_output: number;
  /**
   * Zero. Rounds the struct up to a whole multiple of its alignment on
   * every target, so that a member a later version appends starts at or
   * past the length a caller built against this header declares, never
   * in padding inside it. The library writes zero here and reads nothing
   * from it.
   */
  reserved: number;
}
koffi.struct('sipral_local_conference_member_t', {
  size: 'size_t',
  member: 'sipral_handle_t',
  talking: 'uint32_t',
  muted_input: 'uint32_t',
  muted_output: 'uint32_t',
  gain_input: 'uint32_t',
  gain_output: 'uint32_t',
  reserved: 'uint32_t',
});

/**
 * What sipral_account_check_certificate found: whether the account's
 * pin decided, and what the certificate's dates say.
 *
 * Set `size` to `sizeof(sipral_pinned_certificate_t)` before the call.
 */
export interface SipralPinnedCertificate {
  /**
   * How many bytes of this struct the library filled in.
   */
  size: number;
  /**
   * The certificate's `notBefore`, in seconds since 1 January 1970,
   * or zero when its DER could not be read that far.
   */
  not_before: Wide;
  /**
   * Its `notAfter`, the same way.
   */
  not_after: Wide;
  /**
   * One when the account pins a certificate and this is it: accept
   * the handshake, whoever signed it. Zero when the account pins
   * none: the platform's own checks apply, as they would without
   * this call.
   */
  pinned: number;
  /**
   * One when `unix_seconds` is past `not_after`. Accepted all the
   * same: its dates were written by the holder of the pinned key, and
   * a PBX whose self-signed certificate lapsed would otherwise go
   * silent. Worth a warning.
   */
  expired: number;
  /**
   * One when `unix_seconds` is before `not_before`: a clock set wrong,
   * or a certificate minted with a future date. Accepted too.
   */
  not_yet_valid: number;
  /**
   * Zero.
   */
  reserved: number;
}
koffi.struct('sipral_pinned_certificate_t', {
  size: 'size_t',
  not_before: 'uint64_t',
  not_after: 'uint64_t',
  pinned: 'uint32_t',
  expired: 'uint32_t',
  not_yet_valid: 'uint32_t',
  reserved: 'uint32_t',
});

/**
 * What sipral_stack_network_test tests. Zero in any member but
 * `size` leaves that part out or takes its default.
 *
 * Set `size` to `sizeof(sipral_network_test_config_t)` before the call.
 */
export interface SipralNetworkTestConfig {
  /**
   * `sizeof` this struct, as the caller's header declares it.
   */
  size: number;
  /**
   * The account whose server to probe, on the account's own
   * transport, or `SIPRAL_HANDLE_NONE` to leave it out.
   */
  account: Wide;
  /**
   * A UDP socket the application bound for the test, `host:port`,
   * asked about as `sipral_stack_nat_map` asks about a media socket;
   * null to ask about the signalling socket only, and to test no
   * relay. Not NUL-terminated.
   */
  probe_socket: Pointer;
  /**
   * How many bytes of it.
   */
  probe_socket_len: number;
  /**
   * A call the application placed to an echo service, measured once
   * its media starts and hung up by the test, or `SIPRAL_HANDLE_NONE`.
   */
  echo_call: Wide;
  /**
   * How long the echo is measured. 8000 by default.
   */
  echo_ms: number;
  /**
   * How long the whole test may take. 30000 by default; a part that
   * has not answered by then counts as failed.
   */
  timeout_ms: number;
}
koffi.struct('sipral_network_test_config_t', {
  size: 'size_t',
  account: 'sipral_handle_t',
  probe_socket: 'void *',
  probe_socket_len: 'size_t',
  echo_call: 'sipral_handle_t',
  echo_ms: 'uint32_t',
  timeout_ms: 'uint32_t',
});

/**
 * The one callback a stack has.
 *
 * It is called from inside `sipral_stack_poll`, on the thread that called
 * it, with the `user_data` the stack was created with, and never on two
 * threads at once for one stack. It must not unwind. Nothing is held
 * while it runs, so it may call back into the library, the stack it was
 * given included (`docs/08-ffi.md`, "The shape").
 */
export const sipral_event_callback_t = koffi.proto('void sipral_event_callback_t(const sipral_event_t *event, void *user_data)');

/**
 * The screening policy: consulted once for every INVITE, before it has
 * any effect. Installed with sipral_stack_screen.
 *
 * **It runs with the stack's own lock held**, which is the opposite of
 * sipral_event_callback_t and is the
 * whole reason this type's module documentation exists — read it there.
 * In consequence: **this callback must not call back into the stack it
 * was given**, on this thread or on any other. Doing so does not
 * deadlock — every entry point that takes a stack takes its lock
 * without waiting and answers `SIPRAL_STATUS_BUSY` rather than block —
 * but it is refused outright rather than relied on, and a policy that
 * tries it gets an error code back instead of the call it wanted made.
 * A *different* stack is unaffected. It must not unwind, for the same
 * reason nothing in this ABI may: a panic that reached C across this
 * boundary would take the host process with it.
 *
 * `request` and everything it points at belong to the library and are
 * valid for the duration of this one call and no longer.
 *
 * **The answer is a SIP status code, and the numbers are chosen so that
 * no answer at all is a refusal.** `SIPRAL_SCREEN_ACCEPT` — 200 — lets
 * the INVITE through, exactly as it would arrive with no policy
 * installed. Anything else is a refusal, answered with that status when
 * that status refuses — 400 to 699 — and with 500 when it does not.
 *
 * Three ranges do not refuse, and each fails the same way. Zero is what
 * a binding hands back when the application's own listener threw and
 * the exception was caught at the boundary, and it is no status at all.
 * A 1xx is a provisional answer: it would leave the caller ringing at a
 * call this end has already forgotten, holding a server transaction
 * nothing here will ever answer. A 2xx that is not the one acceptance
 * is spelled with accepts nothing, and a 3xx redirects nowhere without
 * a `Contact` this ABI has no way to give it. So a policy whose answer
 * went missing does not let a stranger in on the strength of it, and a
 * policy that meant to refuse and named a number that cannot refuse is
 * a bug to fix rather than a reason to wave one through.
 */
export const sipral_screen_callback_t = koffi.proto('uint32_t sipral_screen_callback_t(const sipral_screen_request_t *request, void *user_data)');

/**
 * Echo cancellation, gain control or noise suppression, run over one
 * frame, or told to forget what it has learned — sipral_processor_frame_t
 * says which. Installed with sipral_media_attach_processor.
 *
 * **It runs with this call's media locked**, which is the opposite of
 * sipral_event_callback_t and the reason
 * sipral_media_attach_processor's own doc comment says so before it
 * says anything else — read it there. In consequence: **this callback
 * must not call back into the media handle it was attached through**,
 * on this thread or on any other. It must not unwind, for the same
 * reason nothing in this ABI may.
 *
 * `frame` and everything it points at belong to the library and are
 * valid for the duration of this one call and no longer.
 */
export const sipral_processor_callback_t = koffi.proto('void sipral_processor_callback_t(const sipral_processor_frame_t *frame, void *user_data)');

/**
 * Where the packets the engine encodes go: the application's, called
 * on the engine's thread with one `sipral_audio_transmit_t` per packet.
 */
export const sipral_audio_transmit_callback_t = koffi.proto('void sipral_audio_transmit_callback_t(const sipral_audio_transmit_t *transmit, void *user_data)');

/**
 * Where a stack's log lines go. Installed with
 * sipral_stack_log.
 *
 * Called on whichever thread has just finished a call into this stack,
 * after the stack has been let go and with nothing of the library held,
 * so it may call back into the library — this stack included — as an
 * ordinary call. One line at a time, and never on two threads at once.
 * It must not unwind, for the reason nothing in this ABI may.
 *
 * `record` and everything it points at belong to the library and are
 * valid for the duration of this one call and no longer.
 */
export const sipral_log_callback_t = koffi.proto('void sipral_log_callback_t(const sipral_log_record_t *record, void *user_data)');

/** Why the library could not be opened, or cannot serve this binding. */
export class SipralLoadError extends Error {
  constructor(message: string) {
    super(`sipral: ${message}`);
    this.name = 'SipralLoadError';
  }
}

/** What the library is called on this platform. */
export function libraryName(): string {
  if (process.platform === 'darwin') return 'libsipral_ffi.dylib';
  if (process.platform === 'win32') return 'sipral_ffi.dll';
  return 'libsipral_ffi.so';
}

/**
 * Where the library might be, in the order it is looked for:
 * `path` or `SIPRAL_LIBRARY`, whether either names the file or the
 * directory holding it; then beside this package, for one that
 * bundled the library; then the repository's own `target/release` and
 * `target/debug`, for working against a checkout.
 */
export function libraryCandidates(path?: string): string[] {
  const name = libraryName();
  const found: string[] = [];
  const named = path ?? process.env.SIPRAL_LIBRARY;
  if (named) {
    found.push(existsSync(named) && statSync(named).isDirectory() ? join(named, name) : named);
  }
  const here = dirname(fileURLToPath(import.meta.url));
  found.push(join(here, '..', name));
  const repository = join(here, '..', '..', '..');
  found.push(join(repository, 'target', 'release', name));
  found.push(join(repository, 'target', 'debug', name));
  return found;
}

/**
 * The library, opened and checked, with every entry point it has.
 *
 * {@link Sipral.open} is the only way to get one: it opens the
 * library and asks `sipral_abi_check` whether it can serve the ABI this
 * file was printed from, and throws {@link SipralLoadError} naming both
 * versions when it cannot, rather than letting whichever call first
 * reads a member that is not there fail instead.
 */
export class Sipral {
  /** Open the library and check it. */
  static open(path?: string): Sipral {
    const tried = libraryCandidates(path);
    const file = tried.find((candidate) => existsSync(candidate));
    if (file === undefined) {
      throw new SipralLoadError(
        `could not find ${libraryName()}. Tried:\n${tried.map((one) => `  ${one}`).join('\n')}\n\n` +
          'Build it with `cargo build --release -p sipral-ffi`, or set SIPRAL_LIBRARY to its path or its directory.',
      );
    }
    const sipral = new Sipral(koffi.load(file), file);
    const status = sipral.sipral_abi_check(SIPRAL_ABI_VERSION_MAJOR, SIPRAL_ABI_VERSION_MINOR);
    if (status !== SipralStatus.Ok) {
      throw new SipralLoadError(
        `this build of the library does not implement ABI ${SIPRAL_ABI_VERSION_MAJOR}.${SIPRAL_ABI_VERSION_MINOR}, ` +
          'which this binding was generated against; regenerate the binding or rebuild the library',
      );
    }
    return sipral;
  }

  /** The file the library was loaded from. */
  readonly path: string;


  /**
   * Copy the calling thread's last error message into `buffer`.
   *
   * The message is UTF-8 and is written with a trailing NUL, which is not
   * counted in the length. `out_needed`, when it is not null, always receives
   * the number of bytes the message needs including that NUL, so a caller
   * that passes a capacity of zero and a null buffer gets the length back
   * and `SIPRAL_STATUS_BUFFER_TOO_SMALL`. Nothing is written to a buffer
   * too small to hold the whole message: a truncated one would cut a
   * multi-byte character in half.
   *
   * The message describes the last call this thread made and nothing else.
   * The next call on this thread replaces it, a call that succeeds empties
   * it — including one that succeeded around a nested call that did not —
   * and this call leaves it alone, so it can be read twice. It is never
   * shared with another thread.
   *
   * Safety
   *
   * `buffer` must be writable for `capacity` bytes or null with a capacity
   * of zero, and `out_needed` must point to one `size_t` or be null.
   */
  readonly sipral_last_error_message: (buffer: Pointer, capacity: number, out_needed: Pointer) => number;

  /**
   * The short name of a status code, as a static NUL-terminated string, or
   * null for a number that is not a status code.
   *
   * The string belongs to the library and lives as long as it is loaded.
   * It is meant for a log line; the last error is the sentence for a human.
   *
   * Safety
   *
   * Reads no memory the caller owns, and is safe to call from any thread.
   */
  readonly sipral_status_name: (status: number) => string;

  /**
   * Report the ABI version this library provides.
   *
   * Safety
   *
   * `out_version` must point at a `sipral_abi_version_t` whose `size`
   * member says how long it is.
   */
  readonly sipral_abi_version: (out_version: Pointer) => number;

  /**
   * Whether this library can serve a binding generated against
   * `major`.`minor`. Called once, at load, before anything else: by the
   * binding itself where its language gives it somewhere to call from, and
   * by the application where it does not. The Versioning section of
   * `docs/08-ffi.md` says which binding is which.
   *
   * It can when `major` is this library's major and `minor` is no later
   * than this library's minor: a later minor only appends to an earlier
   * one, so a binding built against 1.0 loads against a library at 1.4,
   * and one built against 1.4 is turned away by a library at 1.0, which
   * lacks what 1.4 added.
   *
   * `SIPRAL_STATUS_UNSUPPORTED_VERSION` when it cannot, with a last error
   * naming both versions, which is what the binding should put in the
   * exception it throws. The patch number is not asked for: it never
   * changes a declaration, so it cannot make two builds disagree.
   *
   * Safety
   *
   * Reads no memory the caller owns, and is safe to call from any thread.
   */
  readonly sipral_abi_check: (major: number, minor: number) => number;

  /**
   * How many bytes this build compiled one of the ABI's structs to.
   *
   * `name` is what the header calls the type — `sipral_stack_config_t` —
   * as bytes and a length, the way every string crosses here. A name this
   * build has no struct for is `SIPRAL_STATUS_INVALID_ARGUMENT`, which is
   * the answer a caller holding somebody else's header gets.
   *
   * Nothing in the library needs asking: the `size` member a struct
   * carries settles a disagreement in the ordinary course of a call. This
   * is for finding out there is one before making it. A package built
   * against one header and loaded over a native library from another
   * shows up here as a `sizeof` that differs, in one call at load, rather
   * than in whichever member happened to move.
   *
   * Safety
   *
   * `name` must be readable for `name_len` bytes, and `out_size` must
   * point at one `size_t`.
   */
  readonly sipral_abi_struct_size: (name: Pointer, name_len: number, out_size: Pointer) => number;

  /**
   * How many of the ABI's structs carry a `size` member.
   *
   * The companion to `sipral_abi_struct_size`, and the part of the check a
   * caller cannot write for itself. A caller that compares lengths holds
   * a list of the structs it knows about, and the list is what goes
   * stale: a struct this ABI gained is one nobody thought to ask about,
   * and a length check that covers all but the newest still passes. Ask
   * for this number, compare it with the length of that list, and the day
   * the ABI grows another the caller is told.
   *
   * Safety
   *
   * `out_count` must point at one `size_t`.
   */
  readonly sipral_abi_versioned_count: (out_count: Pointer) => number;

  /**
   * What this build of the library can do, in one call.
   *
   * Names no stack, and answers the same way before any stack is created
   * as after: a build's capabilities do not change while it runs. Safe to
   * call from any thread, at any time, including from inside the event
   * callback.
   *
   * Safety
   *
   * `out_capabilities` must point at a `sipral_capabilities_t` whose
   * `size` member says how long it is.
   */
  readonly sipral_capabilities: (out_capabilities: Pointer) => number;

  /**
   * Create a stack, and write its handle to `out_stack`.
   *
   * The handle is written only if this returns `SIPRAL_STATUS_OK`. A stack
   * that is created must be destroyed with sipral_stack_destroy.
   *
   * A process holds 256 stacks at once. The next is
   * `SIPRAL_STATUS_EXHAUSTED` until one of them is destroyed and no poll is
   * still running on it.
   *
   * Safety
   *
   * `config` must point at a `sipral_stack_config_t` whose `size` member
   * says how long it is, with every pointer in it readable for the length
   * beside it, and `out_stack` at one `sipral_handle_t`.
   */
  readonly sipral_stack_create: (config: Pointer, out_stack: Pointer) => number;

  /**
   * Read back what a stack is running with.
   *
   * Every value here was either given at creation or defaulted there, and
   * none of it changes afterwards but the two a running stack switches,
   * `diagnostic_trace` and `system_echo_cancellation`. It is the other
   * half of a configuration call that answered `SIPRAL_STATUS_OK`: the
   * call says the value was taken, this says what it came to.
   *
   * Safety
   *
   * `out_settings` must point at a `sipral_stack_settings_t` whose `size`
   * member says how long it is.
   */
  readonly sipral_stack_settings: (stack: Wide, out_settings: Pointer) => number;

  /**
   * Destroy a stack.
   *
   * The handle is dead the moment this returns, and a second destroy is
   * `SIPRAL_STATUS_STALE_HANDLE` rather than a corrupted heap. Called from
   * inside the callback it is still safe: what the poll is holding stays
   * alive until that poll returns. Called from inside a frame of one of its
   * calls — a processor — it is `SIPRAL_STATUS_BUSY` and nothing is freed,
   * because freeing the stack ends that call's media and the frame is
   * holding it. No account is de-registered and no call is hung up; a stack
   * that has to leave politely does that first.
   *
   * Nothing is sent, either: the stack owns no socket. A relay on a TURN
   * server is given back only by a Refresh this end sends, so one still
   * held at this point stays allocated on the server until its lifetime
   * runs out, up to ten minutes later. To leave none behind, hang up every
   * call, poll until each has ended and send what
   * `sipral_stack_poll_farewell` hands out, call
   * `sipral_stack_nat_unmap` for every media socket still named and send
   * what `sipral_stack_poll_stun` hands out, and destroy after that.
   *
   * Safety
   *
   * Safe to call with any handle value. Reads no memory the caller owns.
   */
  readonly sipral_stack_destroy: (stack: Wide) => number;

  /**
   * Let the stack do its work, and deliver what it has to say.
   *
   * `now_ms` is the caller's monotonic clock in milliseconds. It must not
   * fall more than fifty milliseconds behind the last one this stack saw —
   * signalling may be called from any thread, and two of them reading the
   * same clock a moment apart is not a caller mistake — and a jump further
   * back than that is `SIPRAL_STATUS_CLOCK_BEHIND` with nothing delivered.
   *
   * The event callback is called from inside this function, on this
   * thread, and with nothing held: the stack's work is done and its lock
   * let go before the first event is handed over, so the callback may call
   * back into the library, this stack included. A poll that finds another
   * poll of the same stack already delivering — which is what a poll from
   * inside the callback always finds — does the stack's work and leaves its
   * events to that one, so they arrive in the order they were raised and
   * never on two threads at once.
   *
   * `result` may be null for a caller that does not want the counts.
   *
   * A poll is also where the stack writes: a retransmission falls due, a
   * registration is refreshed, a transaction gives up and says so. What it
   * wrote is taken with `sipral_stack_poll_transmit`, which is drained after
   * every poll and left alone by the next one — see `docs/08-ffi.md`,
   * "Signalling across the boundary", for the loop in full.
   *
   * Safety
   *
   * `result` must be null or point at a `sipral_poll_result_t` whose `size`
   * member says how long it is.
   */
  readonly sipral_stack_poll: (stack: Wide, now_ms: Wide, result: Pointer) => number;

  /**
   * D3's health counters for one stack, since it was created.
   *
   * Cheap enough to sample on a timer and ship as telemetry: reading this
   * is one struct copy on top of the call itself, the same as
   * `sipral_media_statistics` and for the same reason — nothing here walks
   * the call table or a session to answer.
   *
   * Safety
   *
   * `out_counters` must point at a `sipral_counters_t` whose `size` member
   * says how long it is.
   */
  readonly sipral_stack_counters: (stack: Wide, out_counters: Pointer) => number;

  /**
   * Install, replace, or remove the screening policy for one stack.
   *
   * Every INVITE that survives sipral_stack_invite_limit reaches this
   * callback before anything else does: before ringing, before
   * `SIPRAL_EVENT_KIND_INCOMING_CALL`, before a call handle exists for
   * anybody to answer or reject. What the callback refuses is answered
   * with the SIP status it named — when that status refuses, and with 500
   * when it does not — and forgotten — no event, no handle,
   * nothing for the application to clean up — and what it takes, by
   * answering `SIPRAL_SCREEN_ACCEPT`, arrives exactly as it would with no
   * policy installed at all.
   *
   * `callback` given as `NULL` removes the policy: every INVITE reaches
   * the application again, the way it did before this was ever called.
   * Calling this a second time with a callback replaces the first outright,
   * on this stack alone — a different stack's policy, if it has one, is
   * untouched.
   *
   * The rule that the callback must not call back into this stack, and
   * must not unwind, is on sipral_screen_callback_t and is the reason
   * this module's own documentation exists; read it there before wiring
   * one up.
   *
   * Safety
   *
   * `callback`, when not null, is called on whichever thread is inside an
   * entry point that is feeding this stack bytes, for as long as the
   * policy stays installed. `user_data` is handed back to it untouched on
   * every call and read by nothing here.
   *
   * **Whatever `user_data` points at has to outlive the last call, and the
   * last call is not `sipral_stack_destroy` returning.** A destroy takes
   * this thread's share of the stack away; a receive already running on
   * another thread holds one of its own until it is done, and the policy
   * it is in the middle of asking is still asked. So the moment to free
   * what the pointer names is once no thread is inside this stack any
   * more, which is the application's own knowledge and not something this
   * ABI can answer. Replacing the policy, or removing it with `NULL`, has
   * the same shape: it takes the stack's lock, so it cannot run while a
   * policy is being asked, and once it returns the callback that was
   * there is not asked again.
   */
  readonly sipral_stack_screen: (stack: Wide, callback: Pointer, user_data: Pointer) => number;

  /**
   * How fast one source address may offer this stack an INVITE (A8).
   *
   * `burst` calls from one address are let through at once; one more is
   * earned every `every_ms` after that. What either number means is
   * exactly what Rate already means by it — `sipral_stack_create`'s
   * default is ten at once and one every two thousand milliseconds,
   * loose on purpose, because in most deployments every legitimate call
   * arrives from the one address a phone registered with.
   *
   * A `burst` of zero, or an `every_ms` of zero, is
   * `SIPRAL_STATUS_INVALID_ARGUMENT` and changes nothing: the first admits
   * no call ever, the first or the one after a week of quiet, and the
   * second earns a token in no time, which is a limit that never limits.
   * There is deliberately no way to ask for that from C, since a
   * deployment that wants no floor at all can simply never call this.
   *
   * The floor is asked before sipral_stack_screen's own policy is: a
   * source that has exhausted it never reaches the callback at all, and is
   * counted in `sipral_counters_t::screened_refused_by_rate` or
   * `screened_refused_by_crowding`, never in `screened_refused_by_policy`.
   *
   * **It counts by source address, so it counts nothing it cannot name.**
   * An INVITE that arrived on a byte stream the application bound without
   * saying where the far end is has no address on it, and this floor lets
   * every one of those through to the policy — which is where a caller who
   * cannot identify a stream's far end has to decide, the same way
   * sipral_screen_request_t::source being null is what it has to decide
   * on. Naming the far end in `sipral_stack_transport_bind`'s `remote` is
   * what puts a stream under this floor at all.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_stack_invite_limit: (stack: Wide, every_ms: Wide, burst: number) => number;

  /**
   * Watch something at the far end (A1).
   *
   * One SUBSCRIBE goes out on `account`'s transport, to `account`'s
   * address, and the handle written back names the subscription from now
   * until it ends. Nothing has happened yet when this returns: the request
   * is in the transmit queue, and
   * `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` reports each step of what
   * becomes of it.
   *
   * A subscription refreshes itself for as long as it is live, at a
   * fraction of what the notifier granted, and starts a fresh one by itself
   * after something recoverable — both under this same handle. What ends
   * it for good is sipral_subscription_end, or an event saying it
   * ended with no retry, and the handle names nothing after that.
   *
   * Safety
   *
   * `config` must point at a `sipral_subscribe_config_t` whose `size`
   * member says how long it is, with every pointer in it readable for the
   * length beside it. `out_subscription` must point at one
   * `sipral_handle_t`.
   */
  readonly sipral_account_subscribe: (stack: Wide, account: Wide, config: Pointer, out_subscription: Pointer, now_ms: Wide) => number;

  /**
   * Give a subscription up.
   *
   * A SUBSCRIBE with `Expires: 0` (§4.1.2.3), and the subscription is not
   * over when this returns: §4.4.1 makes it live "until the NOTIFY
   * transaction with a `Subscription-State` of `terminated` completes", so
   * the closing notification is still answered and
   * `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` with
   * `SIPRAL_SUBSCRIPTION_END_UNSUBSCRIBED` says when it has. One that has
   * no dialog yet has nothing to send this in and ends at once.
   *
   * The handle stays usable until that event arrives, and names nothing
   * after it.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_subscription_end: (stack: Wide, subscription: Wide, now_ms: Wide) => number;

  /**
   * Where a subscription is, without waiting for its next event.
   *
   * SIPRAL_SUBSCRIPTION_STATE_UNKNOWN for a handle that names nothing,
   * which is what a subscription that has ended leaves behind — and a
   * status of `SIPRAL_STATUS_OK` all the same, because "it is over" is an
   * answer to this question rather than a failure of it.
   *
   * Safety
   *
   * `out_state` must point at one `uint32_t`.
   */
  readonly sipral_subscription_state: (stack: Wide, subscription: Wide, out_state: Pointer) => number;

  /**
   * What a lamp for this subscription should show (A1).
   *
   * RFC 4235 §3.7.2's virtual state machine over every dialog the notifier
   * has told this subscription about: anything ringing beats anything
   * settled, and SIPRAL_DIALOG_PHASE_IDLE is what is left once they
   * have all ended. One call and one number, which is what a busy lamp
   * field is; sipral_subscription_dialog_count and the two after it
   * are for an application that wants to show who is on the call as well.
   *
   * `SIPRAL_STATUS_NOT_SUPPORTED` for a subscription that has no dialog
   * state at all — one to another package, or one that is not live, whose
   * last notification stopped being evidence the moment it stopped being
   * refreshed.
   *
   * Safety
   *
   * `out_phase` must point at one `uint32_t`.
   */
  readonly sipral_subscription_lamp: (stack: Wide, subscription: Wide, out_phase: Pointer) => number;

  /**
   * How many dialogs this subscription has been told about.
   *
   * They are in the order they were first heard of, and the index one has
   * here is stable only until the next notification arrives: a dialog that
   * ended is dropped from the table, and the numbering closes up behind
   * it. Read a dialog out in the same breath as the count, and read them
   * both again on the next
   * SIPRAL_EVENT_KIND_NOTIFIED.
   *
   * Safety
   *
   * `out_count` must point at one `size_t`.
   */
  readonly sipral_subscription_dialog_count: (stack: Wide, subscription: Wide, out_count: Pointer) => number;

  /**
   * One of them, by index.
   *
   * Safety
   *
   * `out_dialog` must point at a `sipral_watched_dialog_t` whose `size`
   * member says how long it is.
   */
  readonly sipral_subscription_dialog_at: (stack: Wide, subscription: Wide, index: number, out_dialog: Pointer) => number;

  /**
   * A piece of text about one of them, copied into the caller's buffer.
   *
   * The same shape `sipral_last_error_message` has, and for the same
   * reason: the text belongs to the library and a pointer to it would be
   * one a caller could outlive. `out_needed` always receives the number of
   * bytes the text needs including the trailing NUL, so a caller that
   * brought nothing can ask with `capacity` zero and then ask again with
   * room. A buffer too small for the whole of it is
   * `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written to it.
   *
   * A piece the notifier did not send is one byte: the NUL.
   *
   * Safety
   *
   * `buffer` must be writable for `capacity` bytes or be null with a
   * capacity of zero, and `out_needed` must point at one `size_t` or be
   * null.
   */
  readonly sipral_subscription_dialog_text: (stack: Wide, subscription: Wide, index: number, which: number, buffer: Pointer, capacity: number, out_needed: Pointer) => number;

  /**
   * Send an instant message outside any dialog (RFC 3428 §3).
   *
   * One MESSAGE goes out on `account`'s transport, to `target`. The
   * handle written back names the send until its outcome arrives as
   * `SIPRAL_EVENT_KIND_MESSAGE_SENT`, whether or not the request reached a
   * transport at all.
   *
   * `body` is taken whole, including any byte a header field would
   * refuse — it is a body, not a header — and `content_type` is checked
   * the way any text argument at this boundary is.
   *
   * Safety
   *
   * `target` and `content_type` must be readable for their lengths, and
   * UTF-8. `body` must be readable for `body_len` bytes, or null with a
   * length of zero. `out_message` must point at one `sipral_handle_t`.
   */
  readonly sipral_account_message: (stack: Wide, account: Wide, target: Pointer, target_len: number, content_type: Pointer, content_type_len: number, body: Pointer, body_len: number, out_message: Pointer, now_ms: Wide) => number;

  /**
   * A call is expected on this account, announced by a push (C2).
   *
   * `caller` is whoever the notification said is calling, as a SIP URI.
   * The binding is refreshed at once on whatever path exists — §4.1.3
   * makes that a MUST for a woken agent, and a transport the application
   * has not opened yet is the ordinary shape of a wake-up, so the REGISTER
   * is owed and goes the moment one is bound.
   *
   * Exactly one of the two values written back names something, and which
   * one is a race the caller cannot control:
   *
   * - `out_announcement` when nothing has arrived yet. The INVITE that
   *   matches will be reported as `SIPRAL_EVENT_KIND_CALL_ANNOUNCED`
   *   naming this announcement, immediately before the
   *   `SIPRAL_EVENT_KIND_INCOMING_CALL` for the same call; and
   *   `SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING` when none does.
   * - `out_call` when the INVITE beat the push. The screen just raised
   *   belongs to that call handle, and no announcement was recorded for it
   *   to answer. A `SIPRAL_EVENT_KIND_CALL_ANNOUNCED` still arrives for it
   *   when the incoming-call event has not been delivered yet, because the
   *   two are queued together and in that order; once it has, this return
   *   value is the only word about the match there will be.
   *
   * An account with no registrar has no binding to refresh, and for one of
   * those only the matching happens.
   *
   * Safety
   *
   * `caller` must be readable for `caller_len` bytes, and each of
   * `out_announcement` and `out_call` must point at one `sipral_handle_t`.
   */
  readonly sipral_account_announce: (stack: Wide, account: Wide, caller: Pointer, caller_len: number, out_announcement: Pointer, out_call: Pointer, now_ms: Wide) => number;

  /**
   * Refresh the binding now, without announcing anything (C3).
   *
   * For the periodic wake-up a proxy sends to keep a suspended device's
   * binding alive (RFC 8599 §5.5). A push is evidence that the path to the
   * proxy is working, so a back-off earned by an earlier outage is not
   * what to wait for now and is dropped.
   *
   * Nothing is sent when a REGISTER is already in flight, which is already
   * the fastest path, or when the registration has failed in a way trying
   * again cannot fix — repeating a password that was refused is how an
   * account gets locked out, and a push does not change that. Both of those
   * are `SIPRAL_STATUS_OK`: the refresh was asked for and the answer is
   * that nothing needed sending.
   *
   * `SIPRAL_STATUS_INVALID_ARGUMENT` for an account that never registers,
   * which has no binding to refresh: it is the account that is wrong for
   * this call, not the build that is missing the feature. A send that could
   * not happen because no transport is bound yet is reported too, and is
   * not fatal: the refresh is remembered and goes out the moment one is.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_account_refresh_binding: (stack: Wide, account: Wide, now_ms: Wide) => number;

  /**
   * Stop expecting an announced call.
   *
   * The user dismissed the screen, or the application decided the wake-up
   * was stale. `SIPRAL_STATUS_WRONG_STATE` when it had already been
   * fulfilled or had already expired, which is not a mistake: the event
   * that said so and this call can cross.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_announcement_forget: (stack: Wide, announcement: Wide) => number;

  /**
   * What the registrar said about push, in the 2xx to the REGISTER that
   * asked for it.
   *
   * `SIPRAL_STATUS_NOT_SUPPORTED` when this account did not ask for push,
   * or when no binding it could have been said about is standing — none
   * granted yet, one given up, or one that has lapsed.
   *
   * Safety
   *
   * `out_echo` must point at a `sipral_push_echo_t` whose `size` member
   * says how long it is.
   */
  readonly sipral_account_push_echo: (stack: Wide, account: Wide, out_echo: Pointer) => number;

  /**
   * Configure an account, and write its handle to `out_account`.
   *
   * Nothing is sent. The account exists until sipral_account_remove or
   * until the stack is destroyed.
   *
   * Safety
   *
   * `config` must point at a `sipral_account_config_t` whose `size` member
   * says how long it is, with every pointer in it readable for the length
   * beside it, and `out_account` at one `sipral_handle_t`.
   */
  readonly sipral_account_add: (stack: Wide, config: Pointer, out_account: Pointer) => number;

  /**
   * Forget an account, and everything scheduled for it.
   *
   * Nothing is sent: an account being removed may be one whose registrar is
   * unreachable, and waiting on that is not this call's job. Give the
   * binding up politely with sipral_account_unregister first when it
   * matters.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_account_remove: (stack: Wide, account: Wide) => number;

  /**
   * Register, and keep the binding alive until told otherwise.
   *
   * Refreshes, credential retries and the back-off after an outage all
   * happen without another call. What stops them is
   * sipral_account_unregister, or a refusal that trying again cannot
   * fix. Every step of it arrives as a `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED`.
   *
   * An account configured with no registrar never registers, and this
   * answers `SIPRAL_STATUS_INVALID_ARGUMENT` for it with nothing sent.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_account_register: (stack: Wide, account: Wide, now_ms: Wide) => number;

  /**
   * Give the binding up: a REGISTER with `Expires: 0` (§10.2.2).
   *
   * Only this device's binding. A `Contact: *` would remove every binding
   * the address of record has, including the one belonging to the desk
   * phone somebody else is holding.
   *
   * An account configured with no registrar has no binding to give up, and
   * is refused the way `sipral_account_register` refuses it.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_account_unregister: (stack: Wide, account: Wide, now_ms: Wide) => number;

  /**
   * Where an account's registration is, as a `sipral_registration_state_t`.
   *
   * An account configured with no registrar answers
   * `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING`, always.
   *
   * Safety
   *
   * `out_state` must point at one `uint32_t`.
   */
  readonly sipral_account_registration_state: (stack: Wide, account: Wide, out_state: Pointer) => number;

  /**
   * Give an account the OAuth 2.0 access token its server asked for
   * (RFC 8898), in place of any it had (ABI 1.2). A `token_len` of zero
   * takes the token away. The password, if the account has one, stays.
   *
   * The answer to `SIPRAL_EVENT_KIND_TOKEN_REQUIRED`, and the way a token
   * renewed ahead of its expiry goes in: from the next request on, a
   * `Bearer` challenge from the account's own server is answered with
   * `Authorization: Bearer <token>` (RFC 6750 §2.1), and so is every
   * request its cached challenge covers. Offered a `Digest` and a
   * `Bearer` challenge for one realm, the token answers. A token the
   * server refused is never sent to it again. The token answers the
   * account's own server and nobody else, the rule the password is held
   * to. Nothing is sent by this call; a registration that failed for
   * want of a token starts again with `sipral_account_register`.
   *
   * The library does not fetch tokens: `SIPRAL_EVENT_KIND_TOKEN_REQUIRED`
   * names the authorization server and the scope, and the exchange with
   * it is the application's. The token is copied, kept out of every log
   * and diagnostic, and wiped when replaced.
   *
   * `SIPRAL_STATUS_INVALID_ARGUMENT` for a token that is not RFC 6750
   * §2.1's `b64token` — letters, digits, `-._~+/`, then any `=` — with
   * nothing changed and the error not describing it.
   *
   * Safety
   *
   * `token` must be readable for `token_len` bytes, or be null with a
   * length of zero.
   */
  readonly sipral_account_set_access_token: (stack: Wide, account: Wide, token: Pointer, token_len: number) => number;

  /**
   * Test the network before a call: STUN, TURN, the account's server and,
   * with an echo call, the audio path, as `config` says (ABI 1.2). The
   * answer arrives from a later `sipral_stack_poll` as one
   * `SIPRAL_EVENT_KIND_NETWORK_TEST` carrying `*out_test`, once every part
   * has answered or `timeout_ms` has passed. Tests may run side by side.
   *
   * `SIPRAL_STATUS_WRONG_STATE` for a `probe_socket` on a stack that asks
   * no STUN server, and for an account whose server has not been located
   * yet; `SIPRAL_STATUS_INVALID_ARGUMENT` for a `probe_socket` that is not
   * an address or is a signalling socket of the stack's own; a handle
   * that names no account or call of this stack is refused as handles are.
   * Nothing is started when anything is refused.
   *
   * Safety
   *
   * `config` must point at a `sipral_network_test_config_t` whose `size`
   * member says how long it is, with `probe_socket` readable for
   * `probe_socket_len` bytes; `out_test` must point at one `uint32_t`.
   */
  readonly sipral_stack_network_test: (stack: Wide, config: Pointer, now_ms: Wide, out_test: Pointer) => number;

  /**
   * Place a call, and write its handle to `out_call`.
   *
   * The handle exists from here on, before any dialog does, because there
   * has to be something to hang up with while the INVITE is still in
   * flight. A proxy that forks the INVITE gives the branches handles of
   * their own, reported as `SIPRAL_EVENT_KIND_CALL_FORKED`.
   *
   * With `media_address` set, the offer is this stack's to write and the
   * call gets audio of its own: `SIPRAL_EVENT_KIND_MEDIA_STARTED` says when,
   * and the `sipral_media_*` entry points carry the packets from then on.
   * `config.srtp`
   * overrides `sipral_stack_config_t::srtp` for such a call; it is read for
   * no other kind.
   *
   * Safety
   *
   * `config` must point at a `sipral_call_config_t` whose `size` member
   * says how long it is, with every pointer in it readable for the length
   * beside it, and `out_call` at one `sipral_handle_t`.
   */
  readonly sipral_call_place: (stack: Wide, account: Wide, config: Pointer, out_call: Pointer, now_ms: Wide) => number;

  /**
   * Say a call that came in is ringing.
   *
   * A description makes it a 183 Session Progress rather than a 180
   * Ringing, because 180 with a body is a contradiction the far end has to
   * guess at. Pass none for the ordinary case.
   *
   * Safety
   *
   * `sdp` must be null or readable for `sdp_len` bytes.
   */
  readonly sipral_call_ring: (stack: Wide, call: Wide, sdp: Pointer, sdp_len: number, now_ms: Wide) => number;

  /**
   * Say a call that came in is ringing, with this stack running the audio
   * before anybody answers.
   *
   * The answer to the offer the INVITE carried is written from this
   * stack's codec order, against `config.media_address` — where this end
   * will receive media, which only the application can say because it owns
   * the socket — and the session opens on it there and then: the far end
   * hears whatever the application plays before anybody picks up.
   * `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows.
   *
   * `config.srtp` overrides the stack's own SRTP policy for this call, the
   * same way it does on `sipral_call_place`; it is the one way an incoming
   * call can choose its own SRTP policy at all, since
   * `sipral_call_answer_media` reads no configuration of its own. Once
   * this has set it, `sipral_call_answer_media` keeps it: it is answering
   * a call that already has a catalogue, not choosing one.
   *
   * `config.codecs` overrides the stack's codec order for this call in the
   * same way and for the same window: the answer written here is written
   * from it, and `sipral_call_answer_media` keeps what it settled.
   *
   * `sipral_call_answer_media` after this reuses the session and the
   * description written here rather than negotiating a second one. What
   * the 200 OK it sends carries then follows RFC 3262 §5 and RFC 6337
   * §3.1.1 exactly, from whether this call's 183 went out reliably — see
   * `docs/05-media.md`, "Ringing with media".
   *
   * Every other member of `config` — `target`, `sdp`, `destination`,
   * `transport`, `keep_all_forks`, `headers` — names something a call to
   * place would need, and this call already exists; setting one of them
   * is `SIPRAL_STATUS_INVALID_ARGUMENT` naming it.
   *
   * An INVITE that carried no offer is `SIPRAL_STATUS_WRONG_STATE`, with
   * nothing sent: the offer this end would make instead belongs in no
   * provisional response this stack can follow up (RFC 3261 §13.2.1,
   * RFC 6337 §3.1.2).
   *
   * Calling this twice on one call is `SIPRAL_STATUS_WRONG_STATE`, and so is
   * calling it after a `sipral_call_ring` that sent a description of the
   * application's own: every description in the responses to one INVITE
   * has to be that same one (RFC 3261 §13.2.1, RFC 6337 §3.1.1). After a
   * `sipral_call_ring` that sent none, it is not.
   *
   * Safety
   *
   * `config` must point at a `sipral_call_config_t` whose `size` member
   * says how long it is, with `media_address` readable for
   * `media_address_len` bytes.
   */
  readonly sipral_call_ring_media: (stack: Wide, call: Wide, config: Pointer, now_ms: Wide) => number;

  /**
   * Answer a call that came in.
   *
   * `sdp` is the answer to the offer the INVITE carried, and is required:
   * answering with nothing puts the offer on this end and the answer in the
   * far end's ACK, which this ABI has no way to hand back.
   *
   * Safety
   *
   * `sdp` must be readable for `sdp_len` bytes.
   */
  readonly sipral_call_answer: (stack: Wide, call: Wide, sdp: Pointer, sdp_len: number, now_ms: Wide) => number;

  /**
   * Answer a call that came in, and let this stack run its audio.
   *
   * The answer to the offer the INVITE carried is written from this stack's
   * codec order, against `media_address` — where this end will receive
   * media, which only the application can say because it owns the socket.
   * `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows once the stream is open.
   *
   * The other half of `sipral_call_place` with `media_address` set, and the
   * alternative to `sipral_call_answer`, which answers with a description
   * the application wrote and leaves the audio to it.
   *
   * On a call `sipral_call_ring_media` already rang, nothing is written and
   * no second session opens: the 183's description and session stand,
   * `SIPRAL_EVENT_KIND_MEDIA_STARTED` has already been reported, and
   * `media_address` must still be an address and a port but is not used.
   * The 200 OK repeats that description when the 183 went out unreliably and
   * carries none when it went out reliably (RFC 6337 §3.1.1).
   *
   * Safety
   *
   * `media_address` must be readable for `media_address_len` bytes.
   */
  readonly sipral_call_answer_media: (stack: Wide, call: Wide, media_address: Pointer, media_address_len: number, now_ms: Wide) => number;

  /**
   * Answer a call that came in with media this stack describes, from
   * `config`: `sipral_call_answer_media` with the choices
   * `sipral_call_ring_media` takes — `media_address`, `srtp`, `codecs`,
   * `ice`, `text_address` for real-time text, `feedback` for RTP/AVPF
   * and `focus` for a conference focus. Every other member names
   * something only a call to place needs, and setting one is
   * `SIPRAL_STATUS_INVALID_ARGUMENT` naming it.
   *
   * On a call `sipral_call_ring_media` already rang, the 183's
   * description and session stand exactly as `sipral_call_answer_media`
   * says, and nothing in `config` but `focus` changes them.
   *
   * Safety
   *
   * `config` must point at a `sipral_call_config_t` whose `size` member
   * says how long it is, with every pointer in it readable for the length
   * beside it.
   */
  readonly sipral_call_answer_with: (stack: Wide, call: Wide, config: Pointer, now_ms: Wide) => number;

  /**
   * Refuse a call that came in, with a response code of your choosing.
   *
   * 486 Busy Here for a line that is in use, 603 Decline for a person who
   * does not want to talk. The difference is what a proxy does next.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_call_reject: (stack: Wide, call: Wide, code: number, now_ms: Wide) => number;

  /**
   * Hang up, whatever the call is doing.
   *
   * A CANCEL before it is answered, a BYE after, a refusal for one that
   * came in and has not been answered. A call that is already ending is
   * left alone rather than refused.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_call_hangup: (stack: Wide, call: Wide, now_ms: Wide) => number;

  /**
   * Set the header fields that go on what this call sends at the
   * application's request, from now until they are set again.
   *
   * They go on the 180 or 183 from `sipral_call_ring`, the 200 from
   * `sipral_call_answer` and `sipral_call_answer_media`, the refusal from
   * `sipral_call_reject`, the refusal or the BYE that `sipral_call_hangup`
   * turns into, and the re-INVITE or UPDATE that `sipral_call_hold` and
   * `sipral_call_resume` send. Kept rather than spent on the first of those,
   * so that a field set before ringing is on the 200 as well. Never on a
   * CANCEL, which a proxy answers and replaces with its own, and never on
   * what the stack sends by itself: a session refresh, or the BYE for a 2xx
   * that was never acknowledged or for a fork that lost.
   *
   * Replaces what was set before, whole, and a `headers_len` of zero takes
   * every field off. Each field is checked first, as it is on
   * `sipral_call_config_t::headers`, and a refusal names the element, keeps
   * none of the new fields and leaves the old ones in place. Nothing is
   * sent.
   *
   * Safety
   *
   * `headers` must be null with `headers_len` zero, or readable for
   * `headers_len` elements, each with a name and a value readable for the
   * lengths beside them.
   */
  readonly sipral_call_set_headers: (stack: Wide, call: Wide, headers: Pointer, headers_len: number) => number;

  /**
   * Put a call on hold (RFC 3264 §8.4).
   *
   * The description is the stack's to write: the one already negotiated
   * with every stream's direction changed. Asking for a hold that is
   * already in place, or already on its way, sends nothing and succeeds.
   *
   * Asked for while another session change is running in the call, in
   * either direction, it succeeds and waits: its request goes once that
   * change is over (RFC 3261 §14.1), and the outcome arrives as
   * `SIPRAL_EVENT_KIND_SESSION_CHANGED` or
   * `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED` like any other. What waits
   * is the state asked for last, so a resume asked for behind a hold still
   * on its way goes after it. One still waiting when the call ends is
   * never sent, and `SIPRAL_EVENT_KIND_CALL_ENDED` is the last word on it.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_call_hold: (stack: Wide, call: Wide, now_ms: Wide) => number;

  /**
   * Take it off hold again.
   *
   * Every stream goes back to the direction it had before, which is not
   * always both ways: one that was offered receive-only is resumed
   * receive-only. It waits for a change already running exactly as
   * `sipral_call_hold` does.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_call_resume: (stack: Wide, call: Wide, now_ms: Wide) => number;

  /**
   * Offer a call again on another list of codecs (RFC 3264 §8.3.2).
   *
   * `codecs` names them the way `sipral_call_config_t::codecs` does:
   * separated by commas, in the order to offer them. Only the codecs
   * change. Everything else the call has agreed is offered again as it
   * is — its media address, its SRTP key or DTLS fingerprint, its ICE
   * credentials — so nothing is re-keyed and nothing restarts, and a call
   * on hold stays on hold: `sipral_call_resume` takes it off, on the new
   * list. A dynamic payload type keeps the codec it has named on this
   * call, and a codec new to it gets a number nothing has had.
   *
   * The list becomes the call's own once the far end accepts it, and
   * `SIPRAL_EVENT_KIND_MEDIA_CHANGED` names the codec its answer settled
   * on. A refusal arrives as `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED` and
   * leaves the call on the list it had.
   *
   * For a call whose media the stack describes: one placed or answered
   * with `media_address` set. `SIPRAL_STATUS_NOT_SUPPORTED` for a name
   * this build has no codec behind; `SIPRAL_STATUS_INVALID_ARGUMENT` for a
   * list that is empty, names a codec twice or has a stray comma;
   * `SIPRAL_STATUS_WRONG_STATE` for a call the stack writes no description
   * for, one with none agreed yet, one whose stream was refused (a change
   * of codecs does not bring it back), one still early with a far end that
   * never listed UPDATE, or while another change is on its way;
   * `SIPRAL_STATUS_EXHAUSTED` when a codec new to the call finds every
   * dynamic payload type number already taken.
   *
   * Safety
   *
   * `codecs` must be readable for `codecs_len` bytes.
   */
  readonly sipral_call_change_codecs: (stack: Wide, call: Wide, codecs: Pointer, codecs_len: number, now_ms: Wide) => number;

  /**
   * Restart ICE on a call (RFC 8445 §9): offer the call again with new
   * credentials of this end's own, and check every pair again once the
   * far end has answered.
   *
   * The call's last description is offered again with its ICE lines
   * written as for a first offer — both `ice-ufrag` and `ice-pwd` changed,
   * which is how RFC 8839 §4.4.1.1.1 signals a restart — the candidates
   * its agent still holds, and the role it had. Nothing else moves, and
   * nothing reaches the running agent until the far end accepts: "Should
   * a subsequent offer fail, ICE processing continues as if the
   * subsequent offer had never been made" (§4.4). Then the agent checks
   * again under both ends' new credentials while the pair it had goes on
   * carrying the audio, and the new selection arrives as another
   * `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN`; the far end's checks that
   * arrive before its answer are kept and answered then. A refusal
   * arrives as `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED` and leaves ICE as
   * it was.
   *
   * The remedy for a path whose consent was lost
   * (`SIPRAL_MEDIA_FAULT_ICE`), and for a network change this end sees
   * first. For a call whose media the stack describes: one placed or
   * answered with `media_address` set. `SIPRAL_STATUS_WRONG_STATE` for a
   * call the stack writes no description for, one running no ICE agent,
   * one with no description yet, or while another change is on its way;
   * `SIPRAL_STATUS_NOT_SUPPORTED` from a build without ICE.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_call_restart_ice: (stack: Wide, call: Wide, now_ms: Wide) => number;

  /**
   * Describe a call's media at the socket the application bound for it on
   * a new network, and offer that to the far end (RFC 3264 §8.3.1): what
   * `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` asks for.
   *
   * `media_address` is where the new socket is bound, as `host:port`;
   * `public_address` is where it appears from outside when the
   * application has learned that for it, or null with a length of zero
   * to describe the call by `media_address` itself. The re-INVITE carries
   * the call's last description with only `c=` and the port on `m=`
   * moved — codecs, direction, keys and fingerprint stay as they were —
   * and the account's `Contact` as it is when this is called, so
   * `sipral_account_rebind` goes first. The new socket is the call's from
   * here on whatever the far end answers; the answer arrives as
   * `SIPRAL_EVENT_KIND_SESSION_CHANGED` and `SIPRAL_EVENT_KIND_MEDIA_CHANGED`,
   * a refusal as `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`.
   *
   * For a call whose media the stack describes: one placed or answered
   * with `media_address` set. `SIPRAL_STATUS_WRONG_STATE` for a call the
   * stack writes no description for, one whose session runs ICE (which
   * moves by a restart gathered on the new socket, not by this), one with
   * no description yet, or while another change is on its way — asking
   * again once that change is answered moves it then.
   *
   * Safety
   *
   * `media_address` must be readable for `media_address_len` bytes, and
   * `public_address` for `public_address_len` bytes or null with a length
   * of zero.
   */
  readonly sipral_call_media_readdress: (stack: Wide, call: Wide, media_address: Pointer, media_address_len: number, public_address: Pointer, public_address_len: number, now_ms: Wide) => number;

  /**
   * End a call and say why (RFC 3326): what `sipral_call_hangup` does, with
   * a `Reason` on the BYE or the CANCEL it turns into.
   *
   * `sip_cause` is a SIP status and `q850_cause` a Q.850 cause, each zero
   * for none; both may be given, and neither is a plain hangup. `text`, when
   * given, goes on the first value written: the SIP one, or the Q.850 one
   * when there is no SIP one. On the refusal of a call that came in and was
   * never answered only the Q.850 value goes (RFC 6432): a SIP one would
   * repeat the status the refusal carries.
   *
   * Safety
   *
   * `text` must be readable for `text_len` bytes or null with a length of
   * zero.
   */
  readonly sipral_call_hangup_for: (stack: Wide, call: Wide, sip_cause: number, q850_cause: number, text: Pointer, text_len: number, now_ms: Wide) => number;

  /**
   * Answer a call that came in with a 3xx: somewhere else to try
   * (RFC 3261 §21.3), and why (RFC 5806).
   *
   * `status_code` is 300 to 399, 302 for call forwarding. `targets` is where to
   * try, as URIs separated by commas, in the order of preference; one is
   * required for every status but 380. `reason`, when given, is the
   * `Diversion` reason — `no-answer`, `user-busy`, `unconditional`,
   * `deflection`, `do-not-disturb` or any other token — and puts a
   * `Diversion` naming the address that was called on the answer, above
   * the ones the INVITE already carried.
   * `SIPRAL_STATUS_INVALID_ARGUMENT` for another status, a target that is
   * not a URI, or none where one is needed; `SIPRAL_STATUS_WRONG_STATE` for
   * a call that is not waiting to be answered.
   *
   * Safety
   *
   * `targets` must be readable for `targets_len` bytes and `reason` for
   * `reason_len` bytes, each or null with a length of zero.
   */
  readonly sipral_call_redirect: (stack: Wide, call: Wide, status_code: number, targets: Pointer, targets_len: number, reason: Pointer, reason_len: number, now_ms: Wide) => number;

  /**
   * How many entries one of a call's identity lists has:
   * `SIPRAL_IDENTITY_TEXT_DIVERSION` for the `Diversion` values,
   * `SIPRAL_IDENTITY_TEXT_HISTORY` for the `History-Info` entries, and so
   * on — each piece of an entry answers the same count as the entry.
   *
   * Read once, as the INVITE arrived, and the same for the rest of the
   * call. A call this end placed has none of them: zero.
   *
   * Safety
   *
   * `out_count` must point at one `size_t`.
   */
  readonly sipral_call_identity_count: (stack: Wide, call: Wide, which: number, out_count: Pointer) => number;

  /**
   * One piece of one entry of a call's identity lists, copied into the
   * caller's buffer with a trailing NUL: the shape
   * `sipral_subscription_dialog_text` has, for the same reason — the text
   * is the library's, and a pointer to it is one a caller could outlive.
   *
   * `out_needed` always receives the bytes needed including the NUL, so a
   * caller that brought nothing can ask with `capacity` zero and ask again
   * with room; a buffer too small is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with
   * nothing written. A piece the entry does not have — a display name
   * the field did not write — is one byte, the NUL. An index past the
   * end is `SIPRAL_STATUS_INVALID_ARGUMENT`.
   *
   * `index` comes before `which`, as it does in every other entry point
   * that reads a piece of text about one of several things: the entry
   * first, then the piece of it.
   *
   * Safety
   *
   * `buffer` must be writable for `capacity` bytes or null with a capacity
   * of zero, and `out_needed` must point at one `size_t` or be null.
   */
  readonly sipral_call_identity_text: (stack: Wide, call: Wide, index: number, which: number, buffer: Pointer, capacity: number, out_needed: Pointer) => number;

  /**
   * Join two active calls into a local conference of three: from here on,
   * each call's far end hears the other's far end and this end's own
   * microphone, mixed. sipral_media_mix
   * drives one frame of it at a time, on the two calls' own media
   * handles; this only records the pairing.
   *
   * Nothing like a SIP conference server: neither far end's own signalling
   * ever names the other, and this stack sends no `Refer-To`. Both calls
   * must already have media running — placed or answered with
   * `media_address` set, and negotiated — and must agree on a sample rate
   * and a frame length, since nothing here resamples.
   *
   * `SIPRAL_STATUS_INVALID_ARGUMENT` for `call_a == call_b`;
   * `SIPRAL_STATUS_WRONG_STATE` for a call with no running session, a call
   * already joined to another, or two calls whose sessions would decode
   * at different rates or cut audio into frames of different lengths.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_call_join: (stack: Wide, call_a: Wide, call_b: Wide) => number;

  /**
   * Take `call` back out of the pair it is in.
   *
   * Neither call's session is touched: each one goes back to carrying its
   * own audio directly, through `sipral_media_playback` and
   * `sipral_media_capture`, exactly as an unjoined call always has.
   *
   * `SIPRAL_STATUS_WRONG_STATE` for a call that is not currently joined to
   * another.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_call_leave: (stack: Wide, call: Wide) => number;

  /**
   * Accept a change the far end offered, reported as
   * `SIPRAL_EVENT_KIND_SESSION_OFFERED`.
   *
   * `sdp` is the answer to the offer it carried, and is required: every
   * such event carries an offer, and RFC 3264 §5 has an offer answered,
   * so a null or empty `sdp` is `SIPRAL_STATUS_INVALID_ARGUMENT` and the
   * request is still waiting for this or its refusal. A re-INVITE nobody
   * answers is retransmitted and then ends the call, so this or
   * sipral_call_reject_session has to follow that event. An offer that
   * arrived in a PRACK (RFC 3262 §5) is answered the same way, in the
   * PRACK's 2xx.
   *
   * Only for a call the application describes. One this stack describes
   * answers its own re-offers, from the same codec order, before the poll
   * that saw the request returns — so the event never arrives and this is
   * `SIPRAL_STATUS_WRONG_STATE`.
   *
   * Safety
   *
   * `sdp` must be null or readable for `sdp_len` bytes.
   */
  readonly sipral_call_accept_session: (stack: Wide, call: Wide, sdp: Pointer, sdp_len: number, now_ms: Wide) => number;

  /**
   * Refuse one instead. The session stands exactly as it was (§14.1).
   *
   * 488 Not Acceptable Here is the code that says the description was the
   * problem rather than the request.
   *
   * As with sipral_call_accept_session, only for a call the application
   * describes.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_call_reject_session: (stack: Wide, call: Wide, code: number, now_ms: Wide) => number;

  /**
   * Send DTMF on a call that is up, in whichever of the three forms the far
   * end takes.
   *
   * `digits` are `0` to `9`, `*`, `#` and `A` to `D`, the sixteen events of
   * RFC 4733 §3.2, in the order they were pressed, checked as a whole
   * before anything goes out: one character no keypad has, anywhere in the
   * string, sends nothing, not even the keys ahead of it. `duration_ms` is
   * how long each one lasts, or zero for the hundred milliseconds every
   * one of the three forms defaults to.
   *
   * `via` is a sipral_dtmf_t, and it is chosen per send rather than per
   * call: which form a peer accepts is a fact about the peer, and an
   * application that has just learned the answer for this one must not have
   * to tear the call down to act on it. `SIPRAL_DTMF_RTP` puts the digits in
   * the media, where they replace the audio for as long as they last and
   * queue behind each other. The two INFO forms put one request per digit
   * in the dialog, but not all at once: over UDP, overlapping non-INVITE
   * transactions can arrive in any order, so the next digit's INFO waits
   * for the one before it to reach a final answer. A 2xx sends it; a
   * refusal, a timeout or a transport failure ends the sequence there
   * instead, and the digits still waiting are discarded rather than sent
   * out of order — the digit that ended it is what
   * `SIPRAL_EVENT_KIND_DTMF_SENT` names, and nothing is reported for the
   * ones it took down with it. Digits handed over while an INFO of this
   * call is still unanswered queue behind the ones already waiting, as the
   * media's do, rather than go out at once. A call holds at most sixty-four
   * INFO digits at once, the one in flight included; a string that would
   * take it past that is refused whole with `SIPRAL_STATUS_INVALID_ARGUMENT`,
   * the same as one with a character no keypad has, and nothing of it is
   * sent.
   *
   * `SIPRAL_DTMF_RTP` on a call whose negotiation settled on no telephone
   * event payload type writes the digits into the audio instead, as
   * `SIPRAL_DTMF_IN_BAND` does on any call: the one way such a far end can
   * hear a key. Both need the call's media, and answer
   * `SIPRAL_STATUS_WRONG_STATE` before there is any. The INFO forms need a
   * dialog rather than a negotiation, and answer
   * `SIPRAL_STATUS_WRONG_STATE` before there is one.
   *
   * Safety
   *
   * `digits` must be readable for `digits_len` bytes.
   */
  readonly sipral_call_send_dtmf: (stack: Wide, call: Wide, digits: Pointer, digits_len: number, via: number, duration_ms: number, now_ms: Wide) => number;

  /**
   * Ask the far end to call somebody else, and hang up when it has
   * (RFC 3515).
   *
   * A blind transfer: nobody consults the destination first. This end stays
   * in the call until the transfer has succeeded, because hanging up first
   * turns a transfer that failed into a call that vanished. Progress
   * arrives as `SIPRAL_EVENT_KIND_TRANSFER_PROGRESS` and then
   * `SIPRAL_EVENT_KIND_TRANSFER_DONE`.
   *
   * Safety
   *
   * `target` must be readable for `target_len` bytes.
   */
  readonly sipral_call_transfer: (stack: Wide, call: Wide, target: Pointer, target_len: number, now_ms: Wide) => number;

  /**
   * Call the transfer target, so that there is somebody to hand the call
   * to, and write the new call's handle to `out_consultation`.
   *
   * The consultation leg of an attended transfer. It is answered like any
   * other call, and sipral_call_transfer_to is what follows. Putting
   * `call` on hold first is the application's: it is a session change, and
   * this stack does not make those uninvited.
   *
   * `media_address` is `SIPRAL_STATUS_NOT_SUPPORTED` here. The media engine
   * places and answers calls; it does not consult, and a consultation leg
   * registered with it by hand would be one it has described nothing for.
   * A consultation with audio is placed with `sdp` and run by the
   * application, as every call was before this stack carried media.
   *
   * Safety
   *
   * As sipral_call_place.
   */
  readonly sipral_call_consult: (stack: Wide, call: Wide, config: Pointer, out_consultation: Pointer, now_ms: Wide) => number;

  /**
   * Hand `call` to the far end of `other` (RFC 3891).
   *
   * The attended half of a transfer: `other` is normally the consultation
   * call, and the party at its far end replaces the call it already has
   * rather than answering a second one. Any call that is up may be named.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_call_transfer_to: (stack: Wide, call: Wide, other: Wide, now_ms: Wide) => number;

  /**
   * Take a transfer that was asked for, place the call it names the way
   * sipral_call_place places one, and write its handle to
   * `out_placed`.
   *
   * `config.target` is not read: the far end already said where this goes
   * when it asked for the transfer, and a target of the caller's own would
   * be a second one contradicting it — `SIPRAL_STATUS_INVALID_ARGUMENT`
   * naming it. Everything else in `config` means what it means on
   * `sipral_call_place`: `sdp` for a description the application wrote and
   * runs the audio of, `media_address` for one this stack writes and runs
   * (`config.srtp` overriding the stack's own policy for it, the same
   * way), `headers`, `destination`, `transport` and `keep_all_forks` for
   * the INVITE this places. `Replaces` and `Referred-By` among `headers`
   * are `SIPRAL_STATUS_INVALID_ARGUMENT`, nothing sent and the transfer still
   * there to take: that INVITE takes both from the REFER. Giving neither
   * `sdp` nor `media_address` is
   * `SIPRAL_STATUS_INVALID_ARGUMENT`, for the same reason it is on
   * `sipral_call_place`: the answer to an offerless INVITE has nowhere to
   * go but the ACK, and this ABI hands nothing back from there.
   *
   * `call` may be a referral's handle instead — the `call` of a
   * `SIPRAL_EVENT_KIND_REFERRAL`, a REFER outside any dialog — and it is
   * taken exactly the same way, the call placed from the account the
   * event names. The 202 opens the dialog its NOTIFYs travel in, and the
   * handle is spent once this has answered the REFER: it is stale
   * afterwards, whether the call then went or not. One refused before
   * anything was sent — a header, a target — is still there to take.
   *
   * A call that cannot be sent once the 202 has gone ends the REFER's
   * subscription with RFC 3515 §2.4.5's 503, so the far end is told, and
   * this answers `SIPRAL_STATUS_NOT_SENT` as it would for any call.
   *
   * Safety
   *
   * `config` must point at a `sipral_call_config_t` whose `size` member
   * says how long it is, with every pointer in it readable for the length
   * beside it, and `out_placed` at one `sipral_handle_t`.
   */
  readonly sipral_call_accept_transfer: (stack: Wide, call: Wide, config: Pointer, out_placed: Pointer, now_ms: Wide) => number;

  /**
   * Refuse one instead.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_call_reject_transfer: (stack: Wide, call: Wide, code: number, now_ms: Wide) => number;

  /**
   * Take a transfer that was asked for inside `call` with a call the
   * application placed itself, `placed`, and report that call's progress
   * to the far end as though the REFER had placed it (ABI 1.2).
   *
   * For an application that reaches the target its own way — a bridge
   * that calls it on a line of its own and joins the two calls — rather
   * than having `sipral_call_accept_transfer` send an INVITE with the
   * REFER's `Replaces` and `Referred-By`. The REFER is answered 202 (RFC
   * 3515 §2.4.2), and from then on `placed` reports to it as a call the
   * stack placed for it would: a NOTIFY carrying each provisional status
   * (§2.4.5), and its final status ending the subscription (§2.4.7). A
   * `placed` already up is reported with a 200 at once. `call` stays as
   * it is: ending it once the transfer has worked is the application's.
   *
   * `SIPRAL_STATUS_WRONG_STATE` when nothing is waiting to be taken on
   * `call` — a referral's handle (`SIPRAL_EVENT_KIND_REFERRAL`) among
   * them, which `sipral_call_accept_transfer` takes — or when `placed` is
   * `call`, is over, or already reports to another REFER. Everything is
   * checked before the REFER is answered, so a refusal leaves it waiting.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_call_accept_transfer_placed: (stack: Wide, call: Wide, placed: Wide, now_ms: Wide) => number;

  /**
   * Where a call is, as a `sipral_call_state_t`.
   *
   * A call that is over answers `SIPRAL_CALL_STATE_TERMINATED` until the
   * poll that delivers `SIPRAL_EVENT_KIND_CALL_ENDED` retires its handle, and
   * `SIPRAL_STATUS_STALE_HANDLE` after that. A referral's handle
   * (`SIPRAL_EVENT_KIND_REFERRAL`) is `SIPRAL_STATUS_WRONG_STATE`: it
   * names a request, and there is no call yet to be anywhere.
   *
   * Safety
   *
   * `out_state` must point at one `uint32_t`.
   */
  readonly sipral_call_state: (stack: Wide, call: Wide, out_state: Pointer) => number;

  /**
   * Which way a call is held: `out_here` is set when this end asked the far
   * end to stop sending, `out_there` when the far end asked this one.
   * Either may be null.
   *
   * Safety
   *
   * `out_here` and `out_there` must each be null or point at one
   * `uint32_t`.
   */
  readonly sipral_call_hold_state: (stack: Wide, call: Wide, out_here: Pointer, out_there: Pointer) => number;

  /**
   * The name of a codec, as a static NUL-terminated string, or null for a
   * number this build has no codec for.
   *
   * It is spelled as IANA registered it, which is also how it goes on an
   * `a=rtpmap` line — with the rate after it for L16, `L16/8000` and
   * `L16/16000`, which is one encoding name at two rates and is named that
   * way in a codec order. The string belongs to the library and lives as
   * long as it is loaded.
   *
   * Safety
   *
   * Reads no memory the caller owns, and is safe to call from any thread.
   */
  readonly sipral_codec_name: (codec: number) => string;

  /**
   * How many codecs this build contains.
   *
   * A compile-time fact, and the reason A4 starts here rather than at a
   * configuration: no setting can add a codec that was not linked.
   *
   * Safety
   *
   * `out_count` must point at one `size_t`.
   */
  readonly sipral_codec_count: (out_count: Pointer) => number;

  /**
   * One of them, by index, from zero to what `sipral_codec_count` said.
   *
   * The order is this build's own preference, quality first, which is what
   * is offered when nobody has said otherwise — all of it but G.729, which
   * is listed last and offered only where a codec order names it.
   *
   * Safety
   *
   * `out_info` must point at a `sipral_codec_info_t` whose `size` member
   * says how long it is.
   */
  readonly sipral_codec_at: (index: number, out_info: Pointer) => number;

  /**
   * The codecs this stack offers, in the order it offers them.
   *
   * The other half of the configuration: `codecs` in
   * `sipral_stack_config_t` says what to offer, and this says what that came
   * to. `out_count` always receives the number there are, so a caller that
   * passes a capacity of zero and a null buffer learns how much room to
   * bring and gets `SIPRAL_STATUS_BUFFER_TOO_SMALL`.
   *
   * Safety
   *
   * `out_codecs` must be writable for `capacity` `uint32_t` or null with a
   * capacity of zero, and `out_count` must point at one `size_t` or be null.
   */
  readonly sipral_stack_codec_order: (stack: Wide, out_codecs: Pointer, capacity: number, out_count: Pointer) => number;

  /**
   * A handle on one call's media, written to `out_media`.
   *
   * Mint it once the call's negotiation has settled —
   * `SIPRAL_EVENT_KIND_MEDIA_STARTED` is the moment, and minting from inside
   * that event's callback is allowed — and hand it to every `sipral_media_`
   * entry point in place of the stack and the call. None of those takes the
   * stack's lock, which is the point: the thread that carries a call's audio
   * is never refused a frame because signalling, the event callback or
   * another call is busy.
   *
   * `SIPRAL_STATUS_WRONG_STATE` for a call with no media: one placed with a
   * description of the caller's own, or one whose negotiation has not
   * settled. The handle is written only if this returns `SIPRAL_STATUS_OK`.
   *
   * The handle outlives the call. Once the call ends, or its stack is
   * destroyed, every media entry point answers `SIPRAL_STATUS_WRONG_STATE`
   * on it; a hold, a resume or a change of codec keeps it working. Each
   * handle minted is released once with `sipral_media_release`, and asking
   * twice for the same call gives two.
   *
   * Safety
   *
   * `out_media` must point at one `sipral_handle_t`.
   */
  readonly sipral_call_media: (stack: Wide, call: Wide, out_media: Pointer) => number;

  /**
   * Let a media handle go.
   *
   * Its one matching free, whether or not its call is still up and whether
   * or not its stack still exists. The session is not touched: it belongs to
   * the call and ends when the call does, so releasing a handle mid-call
   * stops nothing but the handle. A handle released twice is
   * `SIPRAL_STATUS_STALE_HANDLE` the second time.
   *
   * Safety
   *
   * Safe to call with any handle value. Reads no memory the caller owns.
   */
  readonly sipral_media_release: (media: Wide) => number;

  /**
   * What one call's media settled on.
   *
   * Safety
   *
   * `out_info` must point at a `sipral_media_info_t` whose `size` member
   * says how long it is.
   */
  readonly sipral_media_info: (media: Wide, out_info: Pointer) => number;

  /**
   * How many codecs were in the running on this call.
   *
   * This call's own catalogue, which is the stack's order unless
   * `sipral_call_config_t::codecs` named another. Zero is an answer, not a
   * failure: a call negotiated from a description with no media line in it
   * had nothing in the running at all.
   *
   * Safety
   *
   * `out_count` must point at one `size_t`.
   */
  readonly sipral_media_codec_candidate_count: (media: Wide, out_count: Pointer) => number;

  /**
   * One of them, by index, from zero to what
   * `sipral_media_codec_candidate_count` said, in this call's own order.
   *
   * D5 in one place: what this end offered, what the far end named, and
   * which of the two ran out first. An index past the end is
   * `SIPRAL_STATUS_INVALID_ARGUMENT` naming how many there are.
   *
   * Safety
   *
   * `out_candidate` must point at a `sipral_codec_candidate_t` whose `size`
   * member says how long it is.
   */
  readonly sipral_media_codec_candidate_at: (media: Wide, index: number, out_candidate: Pointer) => number;

  /**
   * How many paths this call's ICE agent tried: every candidate pair its
   * checklist held, then every relay it held.
   *
   * Zero is an answer, not a failure: a call not using ICE has one path,
   * the address its description named, and nothing here to explain. A
   * restart (RFC 8445 §9) starts the list again with the new session.
   *
   * Safety
   *
   * `out_count` must point at one `size_t`.
   */
  readonly sipral_media_path_candidate_count: (media: Wide, out_count: Pointer) => number;

  /**
   * One of them, by index, from zero to what
   * `sipral_media_path_candidate_count` said: the pairs in the order the
   * checklist took them in, then the relays.
   *
   * D5's transport and NAT half, beside `sipral_media_codec_candidate_at`:
   * which path the media took, and for every other one whether its check
   * went unanswered, the far end refused it, the answer came back from
   * elsewhere, the relay would not let the far end through, or it worked
   * and lost to a better one. An index past the end is
   * `SIPRAL_STATUS_INVALID_ARGUMENT` naming how many there are; an address
   * buffer smaller than `SIPRAL_ADDRESS_BYTES` is
   * `SIPRAL_STATUS_BUFFER_TOO_SMALL`, before anything is written.
   *
   * Safety
   *
   * `out_candidate` must point at a `sipral_path_candidate_t` whose `size`
   * member says how long it is, and its two address buffers, when not
   * null, must be writable for the capacities beside them.
   */
  readonly sipral_media_path_candidate_at: (media: Wide, index: number, out_candidate: Pointer) => number;

  /**
   * What one call's media has cost, and what it is costing now.
   *
   * A6's live half. `now_ms` is the caller's monotonic clock, as everywhere
   * else, because "how long since a packet arrived" is a question about the
   * present and nothing here reads a clock to answer it. Like every media
   * entry point, this does not move the stack's own clock: it is read at the
   * frame rate of a user interface, often from the thread that draws one,
   * and a reading a millisecond behind the last poll is not a caller bug.
   *
   * The end-of-call record arrives instead as
   * `SIPRAL_EVENT_KIND_MEDIA_STATISTICS`, because by then the stream is
   * gone and this answers `SIPRAL_STATUS_WRONG_STATE`.
   *
   * Safety
   *
   * `out_stats` must point at a `sipral_stream_stats_t` whose `size` member
   * says how long it is.
   */
  readonly sipral_media_statistics: (media: Wide, now_ms: Wide, out_stats: Pointer) => number;

  /**
   * Take a datagram off the media socket.
   *
   * One entry point for both sockets: RTP and RTCP are told apart by
   * RFC 5761 §4's rule on the payload type field, so a caller that put both
   * on one socket does not have to sort them, and one that did not can hand
   * over whichever arrived.
   *
   * `data` is written through. A secured stream is opened in place, and a
   * caller that needs the ciphertext afterwards keeps its own copy.
   *
   * `out_arrival` may be null for a caller that does not want to know what
   * the datagram turned out to be.
   *
   * `now_ms` is when it arrived, on the stack's clock. Reading it here moves
   * nothing: the network thread and the poll thread read that clock apart,
   * and a datagram a millisecond behind the last poll is not refused.
   *
   * Safety
   *
   * `data` must be readable and writable for `len` bytes, `from` readable
   * for `from_len`, and `out_arrival` must point at one `uint32_t` or be
   * null.
   */
  readonly sipral_media_receive: (media: Wide, data: Pointer, len: number, from: Pointer, from_len: number, now_ms: Wide, out_arrival: Pointer) => number;

  /**
   * Take the frame that is due for the earpiece, and say where it came from.
   *
   * Exactly `sipral_media_info_t::frame_samples` samples are written, and a
   * smaller buffer is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with the number
   * needed in `out_written`. Every source fills the frame, concealment and
   * silence included: a device handed nothing for one frame plays whatever
   * was in its buffer last, and that is a far worse sound than the one being
   * concealed.
   *
   * Safety
   *
   * `samples` must be writable for `capacity` `int16_t`, `out_written` must
   * point at one `size_t` or be null, and `out_source` at one `uint32_t` or
   * be null.
   */
  readonly sipral_media_playback: (media: Wide, samples: Pointer, capacity: number, out_written: Pointer, out_source: Pointer) => number;

  /**
   * Put one frame from the microphone on the wire.
   *
   * `sample_count` is `sipral_media_info_t::frame_samples` and nothing else:
   * a codec cuts one frame at one length, and half a frame encoded as a
   * whole one is what a peer hears as a stutter.
   *
   * A `len` of zero in the packet means the frame was deliberately not sent:
   * the far end is holding this end, silence suppression swallowed it, or
   * ICE has not chosen a path for this call yet. The RTP timestamp moves by
   * a frame in the first two cases, because RFC 3550 §5.1 makes it a
   * measure of time rather than of packets; in the third nothing is
   * encoded at all, since there is no packet for the timestamp to belong
   * to and a codec that carries state would have moved it for nothing.
   * While this end holds the far end the frame goes out as silence, never
   * as the microphone.
   *
   * `now_ms` is read as the stack reads it and moves nothing, as with every
   * media entry point. It is what tells ICE that traffic went out on the
   * pair it chose, which is what RFC 8445 §11 lets it stop sending
   * keepalives for.
   *
   * Safety
   *
   * `samples` must be readable for `sample_count` `int16_t`, and `packet`
   * must point at a `sipral_media_packet_t` whose `size` member says how
   * long it is and whose buffers are writable for the capacities beside
   * them.
   */
  readonly sipral_media_capture: (media: Wide, now_ms: Wide, samples: Pointer, sample_count: number, packet: Pointer) => number;

  /**
   * Choose the rate this call's frames cross the boundary at in
   * application mode: what `sipral_media_playback` fills and what
   * `sipral_media_capture` takes, whatever rate the codec runs at.
   *
   * `hz` is 8000, 16000, 24000 or 48000, and 0 is the codec's own rate,
   * which is where every call starts. The frame keeps the call's
   * duration, so 20 ms of G.711 at 24 kHz is 480 samples, and
   * `sipral_media_info_t::sample_rate` and `frame_samples` report the
   * rate chosen as soon as it is set. The conversion is the library's
   * own resampler, both ways, and follows a re-negotiation onto another
   * codec by itself; the codec, an attached processor, a recording and the
   * in-band detectors keep working at the codec's rate. Asking again for
   * the rate already set changes nothing.
   *
   * Any other rate is `SIPRAL_STATUS_INVALID_ARGUMENT`, with the setting
   * left as it was. `SIPRAL_STATUS_WRONG_STATE` on a stack in device mode,
   * where the audio engine pumps the frames at the devices' rate, and
   * `sipral_media_mix` refuses a pair while either call has a rate of its
   * own: a local conference takes calls at any rate.
   *
   * Safety
   *
   * Reads no memory the caller owns.
   */
  readonly sipral_media_set_app_rate: (media: Wide, hz: number) => number;

  /**
   * Run `callback` over every frame captured on this call, against the
   * far-end audio this call played a render delay earlier — echo
   * cancellation, gain control and noise suppression are all this one
   * seam, and `docs/05-media.md` says why.
   *
   * What was attached before is dropped, along with the echo path it had
   * learned. Attaching mid-call is allowed and costs the first few hundred
   * milliseconds of a fresh adaptation, the same price a call pays at its
   * start.
   *
   * **`callback` runs with this call's media locked**, the same as the
   * screening callback and unlike the event callback: it is called from
   * inside sipral_media_playback (to learn what the loudspeaker was
   * just given) and inside sipral_media_capture (to run the frame just
   * captured), and — with sipral_processor_frame_t's `reset` set — whenever
   * this call's media forgets what it has learned, a device change or a
   * codec change mid-call. All three run on whichever thread called the
   * entry point that triggered them. **From inside `callback`, call
   * nothing on any media handle and nothing on this call's stack**: every
   * such call answers `SIPRAL_STATUS_BUSY` and does nothing. Another
   * thread that calls into this call's media meanwhile waits for the
   * frame to finish, so a processor that reached into a second call's
   * media while that call's processor reached into this one would wait on
   * the other for ever; refusing every media handle from inside a frame
   * is what rules that out. It must not unwind: a panic that reached C
   * across this boundary would take the host process with it, the same
   * rule every callback in this ABI is held to.
   *
   * `user_data` is handed back to `callback` untouched on every call, read
   * by nothing here, and has to outlive the last one — which the caller
   * who installed it is the one to know is over:
   * `sipral_media_detach_processor` returning, or `sipral_media_release`
   * of this handle, are the two ways.
   *
   * Safety
   *
   * `callback` is called on whichever thread calls
   * sipral_media_playback or sipral_media_capture on this call,
   * for as long as the processor stays attached, and `user_data` has to
   * outlive the last such call.
   */
  readonly sipral_media_attach_processor: (media: Wide, callback: Pointer, user_data: Pointer) => number;

  /**
   * Stop running the processor sipral_media_attach_processor attached,
   * if there was one.
   *
   * `out_was_attached`, when not null, says whether there was one to stop:
   * 1 if a processor was attached and is now detached, 0 if there was
   * none. The frames the application hands over reach the encoder
   * untouched again from the next one, and the loudspeaker history kept
   * for it is released. Once this returns, `callback` is not called again
   * for this attachment — the moment `user_data` may be freed.
   *
   * Safety
   *
   * `out_was_attached` must point at one `uint32_t` or be null.
   */
  readonly sipral_media_detach_processor: (media: Wide, out_was_attached: Pointer) => number;

  /**
   * Forget the echo path, the noise floor and the gain the attached
   * processor has learned, keeping the processor itself attached.
   *
   * What a device change asks for: the estimate was built for a different
   * loudspeaker and a different microphone, and carrying it forward makes
   * the processor fight it for a while instead of adapting cleanly. Calls
   * the `callback` given to sipral_media_attach_processor with
   * sipral_processor_frame_t's `reset` set.
   *
   * `out_was_attached`, when not null, says whether there was a processor
   * to reset: 1 if there was, 0 if there was none.
   *
   * Safety
   *
   * `out_was_attached` must point at one `uint32_t` or be null.
   */
  readonly sipral_media_reset_processor: (media: Wide, out_was_attached: Pointer) => number;

  /**
   * One frame of a local conference of two calls: decode what `media_a`'s
   * and `media_b`'s far ends each sent, mix what each of the three
   * parties — the two far ends and this end — is owed, and send the two
   * frames the far ends are owed.
   *
   * `sipral_call_join` must already have paired the two calls these two
   * handles belong to. Nothing here checks that itself: checking it would
   * mean taking the stack's lock on every frame, which is exactly what a
   * media handle exists to avoid, so this mixes whatever two handles it is
   * given — the same trust every other `sipral_media_` entry point places
   * in the caller having minted the handle from a call worth acting on.
   *
   * `mic` is this end's own frame, `mic_count` long; `local` is filled
   * with what this end's own loudspeaker is owed, `local_count` long. Both
   * are `sipral_media_info_t::frame_samples` on a call this pair actually
   * agreed on — `sipral_call_join` already made that the same on both.
   * `packet_a` and `packet_b` are filled the way `sipral_media_capture`
   * fills one, each with what its own call's far end is now owed: `mic`
   * mixed with the *other* far end's frame rather than `mic` alone, which
   * is also what each call's own recording keeps if one is running.
   *
   * Drive a joined pair from one thread, one frame at a time. The two
   * sessions are locked together for the length of the call, in a fixed
   * order that does not depend on which handle is named first, so a
   * second `sipral_media_mix` on the same pair waits for this one rather
   * than deadlocking against it — but a thread still calling
   * `sipral_media_playback`/`sipral_media_capture` on either call alone at
   * the same time is a second driver this mix does not know about.
   *
   * Safety
   *
   * `mic` must be readable for `mic_count` `int16_t` and `local` writable
   * for `local_count` `int16_t`, the two must not overlap, and
   * `packet_a` and `packet_b` must each point at a
   * `sipral_media_packet_t` as `sipral_media_capture` describes.
   */
  readonly sipral_media_mix: (media_a: Wide, media_b: Wide, now_ms: Wide, mic: Pointer, mic_count: number, local: Pointer, local_count: number, packet_a: Pointer, packet_b: Pointer) => number;

  /**
   * The control traffic this call has due.
   *
   * A `len` of zero in the packet means nothing is due yet. RFC 3550 §6.3
   * decides when, and at most one report is due at a time, so one call per
   * frame is enough.
   *
   * It asks one call rather than the whole stack, so the thread that sends
   * a call's audio sends its reports too, on the same socket and without
   * reaching the stack: call it after every frame that goes out, and
   * whenever `sipral_stack_poll` reports a deadline while a call is not
   * capturing. On a call that negotiated no RTCP it answers zero for ever.
   *
   * `now_ms` is read as the stack reads it and moves nothing, as with every
   * media entry point.
   *
   * Safety
   *
   * `packet` must point at a `sipral_media_packet_t` as
   * sipral_media_capture describes.
   */
  readonly sipral_media_poll_rtcp: (media: Wide, now_ms: Wide, packet: Pointer) => number;

  /**
   * A datagram this call owes the far end that is neither audio nor a
   * report: today, a record of the DTLS-SRTP handshake that keys it.
   *
   * A `len` of zero means nothing is due. On a call that is not keyed by a
   * handshake — every call in a build without `SIPRAL_FEATURE_DTLS_SRTP`,
   * and every SDES or plain call in a build with it — that is the answer
   * for ever, and calling this costs one comparison.
   *
   * **Drain it to empty**, in a loop, after every `sipral_media_receive`
   * that answered `SIPRAL_ARRIVAL_HANDSHAKE` and at every deadline
   * `sipral_stack_poll` names. A handshake whose records never leave is a
   * ClientHello that never goes out: the call rings, answers, carries no
   * audio in either direction, and reports nothing wrong for the two
   * minutes it takes to give up. That is the one failure this entry point
   * exists to prevent, and there is no way to notice it from the outside.
   *
   * `now_ms` is read as the stack reads it and moves nothing, as with every
   * media entry point.
   *
   * Safety
   *
   * `packet` must point at a `sipral_media_packet_t` as
   * sipral_media_capture describes.
   */
  readonly sipral_media_poll_transmit: (media: Wide, now_ms: Wide, packet: Pointer) => number;

  /**
   * The RTCP goodbye of a call whose media has ended (task 8.4.21).
   *
   * The library builds the BYE RFC 3550 §6.3.7 owes the far end
   * the moment a call's session stops, but by then the call's media
   * handle is already gone — every `sipral_media_` entry point on it
   * answers `SIPRAL_STATUS_WRONG_STATE` — so this is a stack-level call
   * instead, the one place left that still knows the goodbye belonged to
   * that call.
   *
   * `out_call` is written with the handle of the call the goodbye
   * belonged to — `SIPRAL_HANDLE_NONE` when nothing was waiting. The
   * call itself is already over; the handle is there only so the
   * application knows which media socket to send the datagram from, since
   * it owns that socket and this ABI never did. Passing it to any other
   * entry point answers whatever a stale handle of its kind already
   * answers.
   *
   * One at a time, like every other poll in this crate: call it after
   * every `sipral_stack_poll` that delivered `SIPRAL_EVENT_KIND_CALL_ENDED`
   * for a call this stack was running media on, and keep calling until
   * `packet` comes back with a `len` of zero. A call whose media never
   * ran leaves nothing here, but for one thing.
   *
   * A call given a relay on a TURN server (`turn_server` on the stack's
   * configuration) gives it back through here too: the Refresh with a
   * lifetime of zero that RFC 8656 §8 deletes an allocation with,
   * addressed to the TURN server, from the same socket. It is queued when
   * the call ends, whether or not its media ever ran, and earlier when the
   * call turns out not to use the relay at all — its ICE policy is off, or
   * the far end answered without ICE — so polling here after every
   * `sipral_stack_poll`, not only the ones that ended a call, gives the
   * relay back sooner.
   *
   * Safety
   *
   * `out_call` must point at one `sipral_handle_t`, and `packet` at a
   * `sipral_media_packet_t` as sipral_media_capture describes.
   */
  readonly sipral_stack_poll_farewell: (stack: Wide, out_call: Pointer, packet: Pointer) => number;

  /**
   * Whether a digit is going out or waiting to, and how many have not
   * started yet.
   *
   * Either out parameter may be null. A user interface that greys out the
   * keypad while a number is being sent wants the first; one that shows how
   * much of a pasted number is left wants the second.
   *
   * Safety
   *
   * `out_dialling` must point at one `uint32_t` or be null, and
   * `out_waiting` at one `size_t` or be null.
   */
  readonly sipral_media_dialling: (media: Wide, out_dialling: Pointer, out_waiting: Pointer) => number;

  /**
   * Drop everything queued and stop the digit going out.
   *
   * The digit in flight gets no closing packet, which is right for a call
   * whose media is being taken away: there is nowhere left to send one.
   *
   * Safety
   *
   * Reads no memory the caller owns.
   */
  readonly sipral_media_stop_dialling: (media: Wide) => number;

  /**
   * Start recording this call to `path`.
   *
   * Both directions, mixed, as WAVE. It can be started and stopped as often
   * as the person on the phone presses the button, and each recording is a
   * file of its own: a path written to twice would have two headers in it.
   *
   * `SIPRAL_STATUS_WRONG_STATE` for a call whose media has ended and for one
   * already being recorded — two writers on one stream would interleave
   * frames into both files. `SIPRAL_STATUS_INVALID_ARGUMENT` when the file
   * system refuses the path, with what it said in the last error.
   *
   * The file is made with this call's media held, so this call's audio
   * waits for the file system to answer and no other call's does.
   *
   * Safety
   *
   * `path` must be readable for `path_len` bytes.
   */
  readonly sipral_media_record_start: (media: Wide, path: Pointer, path_len: number) => number;

  /**
   * Stop it, and close the file.
   *
   * `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded. A failure
   * here leaves a file with all of the audio in it and zeroes in the two
   * header fields, which is recoverable and is said rather than hidden.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_media_record_stop: (media: Wide) => number;

  /**
   * Whether a recording is running on this call, and how much audio it has
   * taken. Either out parameter may be null.
   *
   * The length is of the audio written, not of the file: the header in front
   * of it is not a recording of anything.
   *
   * Safety
   *
   * `out_recording` must point at one `uint32_t` or be null, and
   * `out_recorded_ms` at one `uint64_t` or be null.
   */
  readonly sipral_media_record_state: (media: Wide, out_recording: Pointer, out_recorded_ms: Pointer) => number;

  /**
   * Take the next message the stack wants written.
   *
   * One at a time, like every other poll here: a caller loops until the
   * message comes back with a `len` of zero. Call it after every
   * `sipral_stack_poll` and after every call that hands bytes in, since both
   * are moments the stack writes at.
   *
   * A message longer than `capacity` is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with
   * the length it needs in `len`, and it is *kept*: the next call with room
   * for it hands over that same message, before anything queued behind it. So
   * a caller that brought no buffer at all — a null `data` with a capacity of
   * zero — learns what to bring without losing the message it asked about.
   *
   * Safety
   *
   * `transmit` must point at a `sipral_transmit_t` whose `size` member says
   * how long it is and whose buffers are writable for the capacities beside
   * them.
   */
  readonly sipral_stack_poll_transmit: (stack: Wide, transmit: Pointer) => number;

  /**
   * Hand over one datagram, whole, and say where it came from.
   *
   * `from` is the far end, as `host:port`. `to` is the address the datagram
   * arrived on, which RFC 3581 §4 makes the address the response has to go
   * out from; a length of zero, whatever the pointer, means the address
   * this stack was created with, which is the answer for a socket bound to
   * one address.
   *
   * A WebSocket frame comes in here too, on one the application runs
   * itself (bound without `remote`): RFC 7118 §4.2 puts one SIP message in
   * each, so it arrives whole the way a datagram does. A WebSocket the
   * stack runs takes its reads through sipral_stack_receive_stream.
   *
   * Bytes that are not a message are `SIPRAL_STATUS_INVALID_ARGUMENT` with
   * the parse error in the last error. That is an ordinary morning on a
   * public SIP port and costs exactly this one packet: log it and carry on.
   *
   * Safety
   *
   * `data` must be readable for `len` bytes, `from` for `from_len`, and `to`
   * for `to_len`.
   */
  readonly sipral_stack_receive_datagram: (stack: Wide, transport: number, data: Pointer, len: number, from: Pointer, from_len: number, to: Pointer, to_len: number, now_ms: Wide) => number;

  /**
   * Hand over bytes off a connection, in whatever sizes the reads came in.
   *
   * On a WebSocket the stack runs (bound with `remote`), the bytes are the
   * server's handshake answer and frames, read the same way; what is
   * inside them reaches the parser one message at a time.
   *
   * Not a message: a fragment of a framing the layer below reassembles on
   * `Content-Length` (§18.3), and one call may hold several messages, half of
   * one, or none at all. No addresses travel with it, because a connection
   * has one far end and it was named when the transport was bound.
   *
   * Framing that cannot be read is fatal to the connection, and unlike a
   * datagram it cannot be resynchronised: the transport is already retired by
   * the time this answers `SIPRAL_STATUS_INVALID_ARGUMENT`, and the socket
   * should be closed. A read of zero bytes is the far end closing, which is
   * sipral_stack_stream_closed and not this.
   *
   * Safety
   *
   * `data` must be readable for `len` bytes.
   */
  readonly sipral_stack_receive_stream: (stack: Wide, transport: number, data: Pointer, len: number, now_ms: Wide) => number;

  /**
   * Say that a transport is open and may be written to — the main one
   * again, or a further one this stack has not had before.
   *
   * The one way back from sipral_stack_transport_failed, the way a
   * stream stack names its far end, and the way a further transport enters
   * the table at all. `transport` is SIPRAL_TRANSPORT_MAIN to (re)bind
   * the main one, or any other number: one this stack already has rebinds
   * it, and one it does not opens it — the number is the caller's own
   * choice, the same as `sipral_account_config_t::transport` and
   * `sipral_call_config_t::transport` read it. `out_transport_id` may be
   * null; when it is not, it receives that same number, which is where a
   * caller answering
   * SIPRAL_EVENT_KIND_TRANSPORT_WANTED
   * reads back the id it just gave one of those two configs.
   *
   * `protocol` is a sipral_transport_t.
   * Rebinding an existing transport takes zero to mean "whatever it
   * already speaks" and anything else has to agree with that or this is
   * `SIPRAL_STATUS_INVALID_ARGUMENT` — a stack retransmits or does not
   * according to what a transport was opened speaking, and changing that
   * underneath the timers would be a transport configured out of RFC 3261
   * §17 halfway through a call. Opening a new one needs a protocol to
   * speak, so zero there is the same refusal for the opposite reason:
   * nothing to fall back on.
   *
   * `local` is the address the far end reaches this one at, as `host:port`.
   * `remote` is the far end of a connection, and is refused on a datagram
   * transport, which has many; a length of zero, whatever the pointer,
   * leaves it out. On `SIPRAL_TRANSPORT_WS` or `SIPRAL_TRANSPORT_WSS` it
   * says the stack is to make the connection a WebSocket itself: the
   * handshake is the next thing sipral_stack_poll_transmit hands over,
   * and the reads go to sipral_stack_receive_stream.
   *
   * This is also how a request
   * SIPRAL_EVENT_KIND_TRANSPORT_WANTED
   * named gets to leave: the call that asked for it was refused with
   * `SIPRAL_STATUS_NOT_SENT` and nothing went on the wire, and once this
   * returns `SIPRAL_STATUS_OK` for the protocol and destination the event
   * gave, asking again — placing the call, registering — sends it on the
   * stream just bound. There is no further event about that one request.
   *
   * Safety
   *
   * `local` must be readable for `local_len` bytes, `remote` for
   * `remote_len`, and `out_transport_id`, when it is not null, must point
   * at one `uint32_t`.
   */
  readonly sipral_stack_transport_bind: (stack: Wide, transport: number, protocol: number, local: Pointer, local_len: number, remote: Pointer, remote_len: number, now_ms: Wide, out_transport_id: Pointer) => number;

  /**
   * Say that a transport failed, and that whatever was written to it did not
   * arrive.
   *
   * The transport is retired: every transaction waiting on it fails now, and
   * the calls and registrations behind them are reported on the next
   * `sipral_stack_poll` — nothing is delivered from inside this call, here as
   * everywhere else. Nothing can be sent until
   * sipral_stack_transport_bind brings one back.
   *
   * So this is not the call for one `sendto` that was refused. An ICMP
   * unreachable is one destination saying no, and a stack that retired its
   * socket over it would drop the calls that were fine. This is for the
   * socket that is over.
   *
   * It is also the answer to a `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` the
   * application could not honour: a failure told of a transport that is
   * not up — the number it would have bound the stream at, never bound or
   * retired — while the stack waits for that stream is a connection that
   * could not be opened, and every request waiting for it stops waiting
   * now (RFC 3261 §18.1.1: trimmed into a datagram when it then fits,
   * ended with a 513 naming the limit otherwise). A number never bound is
   * `SIPRAL_STATUS_INVALID_ARGUMENT` while nothing is waiting.
   *
   * The next poll raises `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` for it, ahead
   * of what the failure did to the registrations and calls on it.
   * sipral_stack_transport_failed_with is the same call with the TLS
   * library's reason carried along.
   *
   * Safety
   *
   * Safe to call with any handle value. Reads no memory the caller owns.
   */
  readonly sipral_stack_transport_failed: (stack: Wide, transport: number, error: number, now_ms: Wide) => number;

  /**
   * Say that a transport failed, and why, in the words of the TLS library
   * that refused it.
   *
   * Everything sipral_stack_transport_failed does — the transport is
   * retired, the transactions on it fail, nothing is sent on it until
   * sipral_stack_transport_bind brings it back — and the reason is
   * carried to `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`: `failure->tls` for a
   * machine to switch on, `failure->detail` for a person to read. A
   * connection that never got as far as a handshake is told here too, so
   * that the application hears about it in the one place it hears about
   * every other loss; retiring a transport that carried nothing yet costs
   * nothing, and the bind that follows the reconnect undoes it. A
   * transport already down is not retired twice, and the failure is still
   * raised: that is how each attempt to connect again that fails is told.
   * A stream a `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` asked for and that
   * could not be opened is told here as well, as
   * sipral_stack_transport_failed says.
   *
   * A TLS reason on a transport that does not speak TLS or WSS is
   * `SIPRAL_STATUS_INVALID_ARGUMENT`, and so is a detail longer than
   * SIPRAL_TRANSPORT_DETAIL_BYTES or not UTF-8; nothing is retired.
   *
   * Safety
   *
   * `failure` must point at a `sipral_transport_failure_t` whose `size`
   * member says how long it is, and its `detail` must be readable for
   * `detail_len` bytes.
   */
  readonly sipral_stack_transport_failed_with: (stack: Wide, failure: Pointer, now_ms: Wide) => number;

  /**
   * Say that a connection closed: the far end went away, or a read returned
   * zero.
   *
   * The same retirement as sipral_stack_transport_failed, and a separate
   * call because it is a separate thing to have happened. An orderly close is
   * not an error the caller has to invent a kind for, and a stack that made it
   * one would have the two indistinguishable in a log for ever after. The
   * event the next poll raises says `SIPRAL_TRANSPORT_ERROR_CLOSED`.
   *
   * Safety
   *
   * Safe to call with any handle value. Reads no memory the caller owns.
   */
  readonly sipral_stack_stream_closed: (stack: Wide, transport: number, now_ms: Wide) => number;

  /**
   * Ask these STUN servers from now on, without creating the stack again.
   *
   * `servers` is `host:port` addresses separated by commas, in order of
   * preference: the first is what `stun_server` would have named, the
   * rest what `stun_fallbacks` would. On a stack that asks already, every
   * socket it keeps mapped is asked again of the new list at once, and
   * what each one learned stands until the new server answers —
   * `SIPRAL_EVENT_KIND_STUN_SERVER` says the server in use moved, and
   * `SIPRAL_EVENT_KIND_NAT_MAPPING` what the new one answers. A server
   * kept from the old list keeps its back-off. On a stack created with
   * `SIPRAL_NAT_OFF` the main transport starts being kept mapped, as it
   * would have been with `SIPRAL_NAT_STUN`; a further datagram transport
   * joins it the next time it is bound with
   * `sipral_stack_transport_bind`.
   *
   * An empty list — `servers_len` zero — asks nobody any more: every
   * account whose `Contact` a STUN answer moved goes back to the socket's
   * own address and registers it, every media socket named is forgotten,
   * and a call is described by its socket's own address from then on.
   * `SIPRAL_STATUS_INVALID_ARGUMENT` for that on a stack with a TURN
   * server, whose relays ride on the media sockets STUN names, and for an
   * entry that is not an address and a port. `SIPRAL_STATUS_NOT_SUPPORTED`
   * for a list in a build without `SIPRAL_FEATURE_STUN`.
   *
   * Safety
   *
   * `servers` must be readable for `servers_len` bytes.
   */
  readonly sipral_stack_stun_servers: (stack: Wide, servers: Pointer, servers_len: number, now_ms: Wide) => number;

  /**
   * Ask where a media socket appears from, before a call is described
   * on it.
   *
   * `local` is the address the socket is bound to, as `host:port` — the
   * same text the call's `media_address` will be. The request is waiting
   * in sipral_stack_poll_stun when this returns, the answer goes in
   * through sipral_stack_receive_stun, and
   * `SIPRAL_EVENT_KIND_NAT_MAPPING` says what it came to, within five and
   * a half seconds whatever the server does. From then on a call placed,
   * rung or answered with that `media_address` is described by the public
   * address, and asks for `a=rtcp-mux`, since one mapping describes one
   * port. Placing one before the answer is `SIPRAL_STATUS_WRONG_STATE`.
   *
   * Until that call, the socket is asked again every twenty-five seconds,
   * as the signalling socket is: nothing else crosses its NAT binding
   * while it waits, and an answer minutes old names a mapping the NAT may
   * have let go. Keep sending what `sipral_stack_poll_stun` hands out for
   * it and handing in what arrives; an answer that differs is
   * `SIPRAL_NAT_MAPPING_MOVED`, and the call is described by it. At most
   * one request per socket waits in the queue.
   *
   * The mapping is spent by the call it describes. A socket used for a
   * second call is named here again — nothing kept the first answer true
   * in between.
   *
   * `SIPRAL_STATUS_WRONG_STATE` on a stack created without
   * `SIPRAL_NAT_STUN`, and `SIPRAL_STATUS_INVALID_ARGUMENT` for a
   * signalling socket of the stack's own, which is kept mapped already.
   *
   * Safety
   *
   * `local` must be readable for `local_len` bytes.
   */
  readonly sipral_stack_nat_map: (stack: Wide, local: Pointer, local_len: number, now_ms: Wide) => number;

  /**
   * Say that a media socket sipral_stack_nat_map named will carry no
   * call after all, and give back what the stack keeps for it.
   *
   * Its mapping is no longer asked again every twenty-five seconds, and a
   * request for it still waiting in sipral_stack_poll_stun is
   * dropped. With a TURN server configured, its relay goes back to the
   * server: a Refresh with a lifetime of zero (RFC 8656 §8), waiting in
   * sipral_stack_poll_stun when this returns, to be sent from the
   * socket like everything else there. A socket whose Allocate was sent
   * and not answered yet asks nothing more, but the server may have
   * allocated all the same: the answer, handed in through
   * sipral_stack_receive_stun as before, is taken for up to the forty
   * seconds the request would have waited, and an allocation it reports
   * is given back the same way. Without this the stack keeps the
   * allocation refreshed for as long as it lives, and after
   * `sipral_stack_destroy`, which sends nothing, the server holds it — a
   * port and a share of the account's quota — until its lifetime runs
   * out, up to ten minutes later.
   *
   * For a socket the application closes, a call it decides not to place,
   * and every socket still named before the stack is destroyed. A socket
   * a call was placed, rung or answered on has already been spent by that
   * call, whose relay goes back when the call ends; naming it here, or a
   * socket never named, does nothing. To be named again the socket goes
   * through sipral_stack_nat_map from the start.
   *
   * `SIPRAL_STATUS_WRONG_STATE` on a stack created without
   * `SIPRAL_NAT_STUN`, and `SIPRAL_STATUS_INVALID_ARGUMENT` for a
   * signalling socket of the stack's own, which is kept mapped for as long
   * as it is bound.
   *
   * Safety
   *
   * `local` must be readable for `local_len` bytes.
   */
  readonly sipral_stack_nat_unmap: (stack: Wide, local: Pointer, local_len: number, now_ms: Wide) => number;

  /**
   * Take the next STUN request a media socket has to send.
   *
   * The same record and the same rules as `sipral_stack_poll_transmit`,
   * on a queue of its own: loop until `len` comes back zero, after every
   * sipral_stack_nat_map, every sipral_stack_receive_stun and
   * every `sipral_stack_poll`, since the stack retransmits a request
   * nobody answered. `source` is always written, and it is the socket to
   * send from — the whole point is the address the server sees it come
   * from, so sending it from any other socket learns the wrong one.
   * `transport` is zero and names nothing here. `protocol` is UDP for a
   * datagram; on a stack whose `turn_transport` is TCP or TLS, what is for
   * the TURN server says that instead, and is written, as it is, on the
   * connection from `source` that `SIPRAL_EVENT_KIND_TURN_STREAM` asked
   * for — never sent as a datagram.
   *
   * A call placed, rung or answered on a socket with its relay sends
   * through here too, for as long as it has no media handle: the Binding
   * indications that keep the NAT binding towards the TURN server open
   * while the phone rings, and the refresh that keeps the allocation past
   * its lifetime less a minute — nine minutes with coturn's default. From
   * the media handle on they leave through `sipral_media_poll_transmit`
   * with the rest of the call's media path.
   *
   * Safety
   *
   * `transmit` must point at a `sipral_transmit_t` whose `size` member says
   * how long it is and whose buffers are writable for the capacities beside
   * them.
   */
  readonly sipral_stack_poll_stun: (stack: Wide, transmit: Pointer) => number;

  /**
   * Hand over a datagram that arrived on a media socket
   * sipral_stack_nat_map named, before a call has media on it.
   *
   * That includes a call already placed, rung or answered on the socket,
   * until its media handle exists: everything arriving on the socket
   * still comes in here, and the call takes what is its own. The TURN
   * server's answers to what a call with a relay sent through
   * sipral_stack_poll_stun — a refresh left unanswered loses the
   * relay. The far end's first connectivity checks on a call using ICE,
   * which start with its answer and can arrive before the 200 is read:
   * one signed with the password the call's description gave out is kept,
   * the newest sixteen for the socket, and answered by the call's agent
   * when its session opens (RFC 8445 §7.3) — unless it waited longer than
   * 39.5 seconds, the far end's transaction for it, or its call ended
   * first, when it is dropped. And once the session is open, in
   * the poll between `SIPRAL_EVENT_KIND_MEDIA_STARTED` and
   * `sipral_call_media`, anything at all, which goes to the session as
   * through `sipral_media_receive`. From the media handle on, the socket's
   * datagrams go to `sipral_media_receive` instead — except on a socket
   * the branches of a forked call share (`keep_all_forks`), whose
   * datagrams keep coming here for as long as the branches last: one
   * offer described them all on the one socket, and each datagram goes to
   * the branch that claims it, by the ICE fragment a check names, the
   * check an answer answers, or the address its media comes from (RFC
   * 8839 §7.3). That much a stack that asks no server takes too; anything
   * else it refuses with `SIPRAL_STATUS_WRONG_STATE`.
   *
   * `to` is the socket it arrived on, as `local` was given there; `from`
   * is where it came from. `SIPRAL_STATUS_OK` when it was the STUN
   * server's answer, which is then the stack's and nobody else's, or the
   * call's as above; `SIPRAL_STATUS_INVALID_ARGUMENT` for anything else —
   * early media before the session opens, a datagram from a stranger, a
   * check nobody can authenticate, an answer from any address but the
   * server's, a datagram the session dropped — which costs that one
   * datagram and nothing more. Only the server's own address is believed,
   * and only an answer to a request this stack sent: that is the whole
   * defence against a forged answer naming an address of the attacker's
   * choosing as this end's own.
   *
   * Safety
   *
   * `data` must be readable for `len` bytes, `from` for `from_len`, and
   * `to` for `to_len`.
   */
  readonly sipral_stack_receive_stun: (stack: Wide, data: Pointer, len: number, from: Pointer, from_len: number, to: Pointer, to_len: number, now_ms: Wide) => number;

  /**
   * Say that the TCP or TLS connection a
   * `SIPRAL_EVENT_KIND_TURN_STREAM` of state `SIPRAL_TURN_STREAM_OPEN`
   * asked for is open — for TLS, that the handshake has finished and the
   * server's certificate was checked against the name the application
   * configured, by the platform's own TLS stack, as for SIP over TLS.
   *
   * The socket's Allocate is waiting in sipral_stack_poll_stun when
   * this returns, marked with the connection's `protocol`, to be written
   * on it; the answer comes back through sipral_stack_turn_receive,
   * and `SIPRAL_EVENT_KIND_NAT_RELAY` says what the server gave, exactly
   * as over UDP.
   *
   * `SIPRAL_STATUS_INVALID_ARGUMENT` for a socket no connection was asked
   * for, and `SIPRAL_STATUS_WRONG_STATE` on a stack created without
   * `SIPRAL_NAT_STUN`.
   *
   * Safety
   *
   * `local` must be readable for `local_len` bytes.
   */
  readonly sipral_stack_turn_connected: (stack: Wide, local: Pointer, local_len: number, now_ms: Wide) => number;

  /**
   * Hand over bytes read off a media socket's TCP or TLS connection to
   * the TURN server, in whatever pieces the connection delivered them.
   *
   * The messages in them are put back together here (RFC 8656 §12.5)
   * and each goes where a datagram from the server would: to the relay
   * being made or kept for the socket, or, once a call has taken it, to
   * that call — its agent while it waits for its session, and then its
   * media, as through `sipral_media_receive`, audio included. So the
   * connection is read here for as long as it is open, media handle or
   * not, and what the call owes the far end in reply comes out of
   * `sipral_media_poll_transmit` as it always does.
   *
   * `SIPRAL_STATUS_STREAM_BROKEN` when the connection carried something
   * no TURN message starts with, which nothing in a stream can recover
   * from: close it. The socket's relay is lost with it —
   * `SIPRAL_NAT_RELAY_FAILED` for one still waiting for its call — and no
   * `SIPRAL_TURN_STREAM_CLOSE` follows. `SIPRAL_STATUS_INVALID_ARGUMENT`
   * for a socket with no open connection.
   *
   * Safety
   *
   * `local` must be readable for `local_len` bytes, and `data` for `len`.
   */
  readonly sipral_stack_turn_receive: (stack: Wide, local: Pointer, local_len: number, data: Pointer, len: number, now_ms: Wide) => number;

  /**
   * Say that a media socket's connection to the TURN server closed, or
   * could not be opened at all.
   *
   * The server knew the socket's allocation by that connection (RFC 8656
   * §3.2), so the relay went with it: one still being made is
   * `SIPRAL_NAT_RELAY_FAILED` at the next poll, and a call on the socket
   * goes without it; a call that had taken it keeps the paths ICE found
   * that need none, and loses the one through it when its consent runs
   * out (RFC 7675). Naming the socket again with `sipral_stack_nat_map`
   * asks for a new connection. `SIPRAL_STATUS_OK` for a connection the
   * stack had already let go.
   *
   * Safety
   *
   * `local` must be readable for `local_len` bytes.
   */
  readonly sipral_stack_turn_closed: (stack: Wide, local: Pointer, local_len: number, now_ms: Wide) => number;

  /**
   * The short name of an event kind, as a static NUL-terminated
   * string, or null for a number this build has no kind for.
   *
   * The string belongs to the library and lives as long as it is
   * loaded. A number that is reserved for a feature this build does
   * not have answers null, the same as one that was never spent: a
   * name for something that cannot arrive would be a name for
   * nothing.
   *
   * Safety
   *
   * Reads no memory the caller owns, and is safe to call from any
   * thread.
   */
  readonly sipral_event_kind_name: (kind: number) => string;

  /**
   * How many lines a header field is on, in a whole SIP message.
   *
   * The message is any SIP message in bytes: the one an event carries in
   * `sipral_event_t::message`, or one the application came by some other
   * way. The name is matched the way the parser matches it, without regard to
   * case, and a compact form and its long form are one field (RFC 3261
   * §7.3.3): `i` counts the `Call-ID` lines, and `Call-ID` counts a line
   * written `i:`. A field that is not there is a count of zero, not a
   * failure.
   *
   * Safety
   *
   * `message` must be readable for `message_len` bytes and `name` for
   * `name_len`, and `out_count` must point at one `size_t`.
   */
  readonly sipral_message_header_count: (message: Pointer, message_len: number, name: Pointer, name_len: number, out_count: Pointer) => number;

  /**
   * Where one line of a header field is, in a whole SIP message.
   *
   * `index` counts from zero in the order the lines arrived, and has to be
   * below what `sipral_message_header_count` says for the same name: past it
   * is `SIPRAL_STATUS_INVALID_ARGUMENT`. `out_offset` and `out_len` then say
   * where the value sits inside `message`, trimmed at both ends and otherwise
   * as it arrived, a line fold included. An offset rather than a pointer,
   * because the bytes are the caller's, and a binding that copied them across
   * the boundary holds its own copy.
   *
   * One line of a field whose value is a comma-separated list may hold
   * several values; `sipral_message_header_element` reaches those.
   *
   * Safety
   *
   * As `sipral_message_header_count`, with `out_offset` and `out_len` each
   * pointing at one `size_t`.
   */
  readonly sipral_message_header: (message: Pointer, message_len: number, name: Pointer, name_len: number, index: number, out_offset: Pointer, out_len: Pointer) => number;

  /**
   * How many values a field whose value is a comma-separated list holds,
   * across every line it is on.
   *
   * RFC 3261 §7.3.1 makes two values on one line, with a comma between them,
   * and the same two values on two lines one and the same message, and a
   * proxy is free to turn either into the other. So this counts values
   * rather than lines, split at every comma that is not inside quotes or
   * angle brackets. Otherwise as `sipral_message_header_count`.
   *
   * Only for a field defined as a list: `P-Asserted-Identity`, `Diversion`,
   * `Contact`, `Supported`. Any other is split at a comma its value holds as
   * text, like the one in a `Date` or the ones between the parameters of a
   * challenge, and `sipral_message_header_count` is the call for it.
   *
   * Safety
   *
   * As `sipral_message_header_count`.
   */
  readonly sipral_message_header_element_count: (message: Pointer, message_len: number, name: Pointer, name_len: number, out_count: Pointer) => number;

  /**
   * Where one value of a list field is, across every line the field is on.
   *
   * `index` counts values in the order they arrived, and has to be below what
   * `sipral_message_header_element_count` says for the same name. Otherwise
   * as `sipral_message_header`.
   *
   * Safety
   *
   * As `sipral_message_header`.
   */
  readonly sipral_message_header_element: (message: Pointer, message_len: number, name: Pointer, name_len: number, index: number, out_offset: Pointer, out_len: Pointer) => number;

  /**
   * The operating system says this process stops shortly.
   *
   * Everything reached from here is synchronous, bounded by the number of
   * accounts and subscriptions, and cannot fail. Nothing is sent — see
   * `docs/16-lifecycle.md` for why a graceful de-registration is the wrong
   * thing to attempt in this window rather than the obvious one — and
   * nothing stays scheduled: a stack that is suspended and never resumed
   * has no deadline to fire and no work left behind.
   *
   * Calls that are up are left exactly as they are. A lid closing and
   * opening again is seconds, and hanging up a live call because the
   * machine blinked is worse than finding out a few seconds later that it
   * is gone.
   *
   * `out_report` receives what was found: bindings that stopped being
   * evidence, subscriptions whose last notification stopped being
   * evidence, and calls left untouched.
   *
   * Safety
   *
   * `out_report` must point at a `sipral_suspending_t` whose `size` member
   * says how long it is.
   */
  readonly sipral_stack_suspending: (stack: Wide, now_ms: Wide, out_report: Pointer) => number;

  /**
   * The process is awake again.
   *
   * Arbitrary time has passed — arbitrary, not measurable, because the
   * clock this stack is driven by did not run while the machine was
   * suspended — and every transport may be dead. What was believed is
   * dropped and proved again: the transport already there is used first,
   * because most wakes are short and it still works, and
   * sipral_account_rebind is how the application hands over a new one
   * once this stack says it needs one.
   *
   * Safe to call without a matching sipral_stack_suspending. Some
   * platforms only notify on the way back.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_stack_resumed: (stack: Wide, now_ms: Wide) => number;

  /**
   * The network is a different one, described before and after in as much
   * detail as the decision needs.
   *
   * `from_link`/`to_link` is a sipral_link_t. `*_address` is the local
   * address this stack's transports are bound to, as an IPv4 or IPv6
   * literal with no port — a change of it invalidates every transport and
   * every binding at once. `*_interface` is the platform's own identity
   * for the interface, never parsed and only ever compared to another one
   * of itself; two networks can hand out the same address, and a phone
   * that walks from one office to another gets away with it until a call
   * comes in. `*_resolves` is whether a name can become an address there,
   * because that is the one failure that leaves everything else looking
   * healthy. Any of the four address or interface arguments may be null
   * with a length of zero, for a fact the application has none to give.
   *
   * `out_recovery` receives what was decided, as a sipral_recovery_t, so
   * this is safe to call as often as the platform delivers the
   * notification — most of the time nothing this stack uses is different,
   * and `SIPRAL_RECOVERY_NOTHING` is the whole of what happens. It may be
   * null.
   *
   * Safety
   *
   * Every address and interface pointer must be readable for the length
   * beside it or null with a length of zero, and `out_recovery` must point
   * at one `uint32_t` or be null.
   */
  readonly sipral_stack_network_changed: (stack: Wide, from_link: number, from_address: Pointer, from_address_len: number, from_interface: Pointer, from_interface_len: number, from_resolves: number, to_link: number, to_address: Pointer, to_address_len: number, to_interface: Pointer, to_interface_len: number, to_resolves: number, now_ms: Wide, out_recovery: Pointer) => number;

  /**
   * There is no usable interface.
   *
   * Distinct from sipral_stack_name_resolution_lost because the
   * recovery is the opposite one: with nothing that can leave, nothing is
   * tried and nothing is scheduled, which is the cheapest this stack ever
   * is. The way out is sipral_stack_network_changed, the notification
   * every platform delivers when an interface comes back.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_stack_interface_lost: (stack: Wide, now_ms: Wide) => number;

  /**
   * Names no longer become addresses.
   *
   * The dangerous one: the interface is up and packets leave, so
   * everything reads healthy, while every address this stack learned from
   * a name may now stand for somewhere else. A binding whose registrar was
   * written as a name stops being evidence; one pointed at a literal
   * address never needed a resolver and is left running.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_stack_name_resolution_lost: (stack: Wide, now_ms: Wide) => number;

  /**
   * Point an account at a transport and an address again.
   *
   * `remote` is the far end this account's requests go to now, as
   * `host:port`. `contact` is where this endpoint can be reached, as it
   * goes in `Contact`; it is not optional, because after a change of
   * address the old one names somewhere the far end cannot reach, and a
   * stack that let it stand would register a binding that silently
   * receives nothing.
   *
   * `transport` must be one this stack already has —
   * SIPRAL_TRANSPORT_MAIN or
   * a further one sipral_stack_transport_bind
   * has bound — and any other number is `SIPRAL_STATUS_INVALID_ARGUMENT`:
   * this call points an account at a transport, it does not open one.
   *
   * Safe to call whether or not this stack is waiting for it. When it is,
   * answering climbs the next rung at once rather than waiting out the
   * rest of the back-off — the application answering in milliseconds is
   * the normal case, and there is nothing to be gained by making a wake
   * take a further half minute. When it is not, this still repoints the
   * account, and the next REGISTER this stack sends for it — a refresh, or
   * the next rung of a ladder started afterwards — uses what was given
   * here.
   *
   * Safety
   *
   * `remote` must be readable for `remote_len` bytes and `contact` for
   * `contact_len` bytes.
   */
  readonly sipral_account_rebind: (stack: Wide, account: Wide, transport: number, remote: Pointer, remote_len: number, contact: Pointer, contact_len: number, now_ms: Wide) => number;

  /**
   * Say the process has just started, so that time to ready is measured
   * from somewhere.
   *
   * The zero of sipral_account_time_to_ready, and a declaration rather
   * than something this library could observe: a stack is created long
   * before the launch it belongs to is over, and only the application
   * knows which moment its users are waiting from. Every account's
   * measurement is cleared and taken again, so calling this twice restarts
   * the clock rather than confusing two launches.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_stack_cold_start: (stack: Wide, now_ms: Wide) => number;

  /**
   * Write an account's registration down, so a later start can carry it on
   * instead of paying for a whole handshake.
   *
   * `out_len` receives how many bytes it takes whether or not there was
   * room, so a caller passing a null `buffer` and a `capacity` of zero is
   * asking how much room to bring and gets `SIPRAL_STATUS_BUFFER_TOO_SMALL`
   * with the answer — that is the question, not a failure. Nothing is
   * written to a buffer too short.
   *
   * **The bytes are opaque, and reading them is not part of this ABI.**
   * They carry a version, and a build reads only the layouts it was made
   * for; an application that parses them is an application that stops
   * working when the layout grows a field. Storing them is the
   * application's, and so is protecting them: a snapshot is not a secret,
   * but it names an address of record, which is a record of who uses this
   * device.
   *
   * `SIPRAL_STATUS_WRONG_STATE` when there is nothing worth keeping — an
   * account that has never registered, one that never will, one whose
   * registration failed, or one whose binding has been given up. A cold
   * start after that is an ordinary cold start, which is what would have
   * happened anyway.
   *
   * The clock is read and not moved: this writes nothing and sends
   * nothing, so a snapshot taken on the way into suspend cannot be what
   * stops a later `now_ms` from being accepted.
   *
   * Safety
   *
   * `buffer` must be writable for `capacity` bytes or be null with a
   * `capacity` of zero, and `out_len` must point at one `size_t` or be
   * null.
   */
  readonly sipral_account_freeze: (stack: Wide, account: Wide, buffer: Pointer, capacity: number, out_len: Pointer, now_ms: Wide) => number;

  /**
   * Read one back, on an account that has been added and has not
   * registered.
   *
   * `asleep_ms` is how long the snapshot sat unused, and it is the
   * caller's to supply because nothing here reads a wall clock and a
   * monotonic instant does not survive the process that minted it. The
   * application is the only one that knows whether this is a wake from
   * suspend or a cold launch a week later. What is left of the binding's
   * life is what was left when it was written down, less that.
   *
   * The account comes up in
   * SIPRAL_REGISTRATION_STATE_RESTORED
   * rather than registered: a binding nobody has confirmed since the
   * machine slept is a belief, not evidence, and the refresh this books is
   * what turns one into the other.
   *
   * Refused, with the account left exactly as it was:
   * `SIPRAL_STATUS_UNSUPPORTED_VERSION` for bytes a newer build wrote,
   * `SIPRAL_STATUS_NOT_SUPPORTED` for an account that does not register at
   * all, and `SIPRAL_STATUS_INVALID_ARGUMENT` for bytes that are not a
   * snapshot, are damaged, or are another account's — an address of record
   * that is not this account's is the one mix-up that would otherwise send
   * a REGISTER for somebody else.
   *
   * Safety
   *
   * `snapshot` must be readable for `snapshot_len` bytes.
   */
  readonly sipral_account_thaw: (stack: Wide, account: Wide, snapshot: Pointer, snapshot_len: number, asleep_ms: Wide, now_ms: Wide) => number;

  /**
   * How long this account took to become reachable, measured from
   * sipral_stack_cold_start.
   *
   * The number a queue needs: how long it rings each agent before giving
   * up and trying the next one has to be longer than this, or a phone that
   * was asleep is skipped every time and its owner is told the queue was
   * quiet.
   *
   * `out_has_value` is zero, and `out_ms` zero with it, until there is an
   * answer — before the account has registered, for an account that never
   * registers, and always when no cold start was ever declared, because
   * nothing marks the moment those became reachable. Zero milliseconds
   * with `out_has_value` set is a real answer and a different one.
   *
   * Safety
   *
   * `out_has_value` must point at one `uint32_t` and `out_ms` at one
   * `uint64_t`.
   */
  readonly sipral_account_time_to_ready: (stack: Wide, account: Wide, out_has_value: Pointer, out_ms: Pointer) => number;

  /**
   * Say where a dialog's next hop actually is.
   *
   * The answer to
   * SIPRAL_EVENT_KIND_RESOLVE_NEEDED,
   * with `dialog` the handle that event carried. `addresses` is
   * comma-separated `host:port`, **in RFC 3263 §4.3 priority order**: the
   * first one this stack already has an open transport of the wanted
   * protocol for is taken, and the ones after it are kept for this stack
   * to try in turn if that one goes on to fail. A list is therefore not a
   * convenience — it is what makes failover possible at all, and one
   * address is a list of one that cannot fail over.
   *
   * `protocol` is a sipral_transport_t when
   * the lookup named one, which a NAPTR or SRV answer does, and zero when
   * it did not — an A lookup with nothing above it — in which case the flow
   * keeps speaking whatever it already spoke. It is looked for, never
   * opened: nothing here owns a socket, so a protocol nothing has bound is
   * not something this can invent. An address on one is passed over, and
   * answering again after
   * sipral_stack_transport_bind
   * is how it gets another chance.
   *
   * `SIPRAL_STATUS_OK` with nothing changed is the honest answer when none
   * of the addresses is one this stack can reach on the protocol asked
   * for: the flow stands exactly as it did. A dialog that has ended by the
   * time the answer comes is `SIPRAL_STATUS_STALE_HANDLE`, like every
   * other handle to something that is gone, and changes nothing either;
   * an application that resolves in the background treats the two alike.
   *
   * There is no `now_ms` here on purpose. Every other call that changes
   * what this stack will send takes the time because something it does is
   * timed; this one only writes an address down.
   *
   * Safety
   *
   * `addresses` must be readable for `addresses_len` bytes.
   */
  readonly sipral_stack_resolved: (stack: Wide, dialog: Wide, addresses: Pointer, addresses_len: number, protocol: number) => number;

  /**
   * Point an account's registration at another address.
   *
   * For a registrar named by a record with more than one target, and for
   * the one after it when the first stops answering. The binding's
   * `Call-ID`, its sequence number and its credentials are all kept, so
   * the next REGISTER reads to the registrar as the same device
   * continuing, not as a second one arriving — which is the whole of the
   * saving and the reason this is not "remove the account and add it
   * again".
   *
   * A REGISTER already in flight or already booked for this account is
   * superseded at once rather than waited out. Retargeting to the address
   * an account is already using is `SIPRAL_STATUS_OK` and sends nothing.
   *
   * `registrar_address` is `host:port`, not a name: resolving one is the
   * application's, here as everywhere else in this module.
   * `SIPRAL_STATUS_NOT_SUPPORTED` for an account with no registrar — a
   * trunk authenticated by address has nothing to retarget, and
   * `sipral_account_config_t::registrar_address` is where its outbound
   * proxy is set.
   *
   * Safety
   *
   * `registrar_address` must be readable for `registrar_address_len`
   * bytes.
   */
  readonly sipral_account_retarget: (stack: Wide, account: Wide, registrar_address: Pointer, registrar_address_len: number, now_ms: Wide) => number;

  /**
   * Copy one call's diagnostic record into `buffer`, as the JSON
   * `docs/14-diagnostics.md` describes.
   *
   * Readable at any point in the call's life, and for as long after it as
   * the endpoint has not evicted the record to make room for a newer one —
   * how many are kept is `sipral_stack_config_t::diagnostic_records`,
   * 32 when it is zero. A call whose
   * record has been evicted, or that has had nothing decided about it yet,
   * answers `SIPRAL_STATUS_OK` with `{}`: an empty record is still a
   * record, and refusing to read one that happens to be empty would make
   * a caller unable to tell "nothing yet" from "something went wrong".
   *
   * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
   * document, with the length needed in `out_needed`.
   *
   * Safety
   *
   * `buffer` must be writable for `capacity` bytes or be null with a
   * capacity of zero, and `out_needed` must point at one `size_t` or be null.
   */
  readonly sipral_call_record_json: (stack: Wide, call: Wide, buffer: Pointer, capacity: number, out_needed: Pointer) => number;

  /**
   * Copy the whole diagnostic document into `buffer`: what a bug report
   * carries, as the JSON `docs/14-diagnostics.md` describes.
   *
   * That is the endpoint's own record — everything decided outside any
   * call — and then one record per call still held, in the same document,
   * with the number of records evicted to make room. It is deliberately
   * the whole of it rather than the endpoint's half: a report that arrives
   * without the calls it is about answers nothing, and
   * sipral_call_record_json is already the way to ask about one call.
   *
   * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
   * document, with the length needed in `out_needed`.
   *
   * Safety
   *
   * `buffer` must be writable for `capacity` bytes or be null with a
   * capacity of zero, and `out_needed` must point at one `size_t` or be null.
   */
  readonly sipral_stack_diagnostics_json: (stack: Wide, buffer: Pointer, capacity: number, out_needed: Pointer) => number;

  /**
   * What a `conference` subscription holds about the conference as a
   * whole (RFC 4575 §5.5).
   *
   * `SIPRAL_STATUS_NOT_SUPPORTED` for a subscription that holds no
   * conference: one to another package, one no document has reached yet,
   * or one that is not live.
   *
   * Safety
   *
   * `out_conference` must point at a `sipral_conference_t` whose `size`
   * member says how long it is.
   */
  readonly sipral_subscription_conference: (stack: Wide, subscription: Wide, out_conference: Pointer) => number;

  /**
   * One user of the conference, by index, in the order the focus first
   * named them. The index is stable only until the next
   * `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED`.
   *
   * Safety
   *
   * `out_user` must point at a `sipral_conference_user_t` whose `size`
   * member says how long it is.
   */
  readonly sipral_subscription_conference_user_at: (stack: Wide, subscription: Wide, index: number, out_user: Pointer) => number;

  /**
   * A piece of text about the conference or one of its users, copied into
   * the caller's buffer the way `sipral_subscription_dialog_text` copies
   * one: `out_needed` receives the bytes it needs including the NUL, a
   * buffer too small is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing
   * written, and a piece the focus did not send is one byte, the NUL.
   *
   * `which` is a sipral_conference_text_t; `index` names the user for the
   * pieces about one, and is ignored for the others.
   *
   * Safety
   *
   * `buffer` must be writable for `capacity` bytes or be null with a
   * capacity of zero, and `out_needed` must point at one `size_t` or be
   * null.
   */
  readonly sipral_subscription_conference_text: (stack: Wide, subscription: Wide, index: number, which: number, buffer: Pointer, capacity: number, out_needed: Pointer) => number;

  /**
   * Say, or stop saying, that this end is the focus of a conference the
   * call belongs to (RFC 4579 §4.2): `isfocus` on the `Contact` of every
   * request and response the call sends from here on — the answer, for a
   * call not answered yet, and the next re-INVITE or UPDATE for one that
   * is up, which is how the far end learns it.
   *
   * `focus` is one to say it and zero to stop.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_call_set_focus: (stack: Wide, call: Wide, focus: number) => number;

  /**
   * The URI of the conference a call belongs to, when its far end said it
   * is a focus (`isfocus` in its `Contact`, RFC 4579 §4.2), copied into
   * the caller's buffer as `sipral_subscription_conference_text` copies.
   *
   * `SIPRAL_STATUS_NOT_A_FOCUS` for a call whose far end said nothing of
   * the kind.
   *
   * Safety
   *
   * `buffer` must be writable for `capacity` bytes or be null with a
   * capacity of zero, and `out_needed` must point at one `size_t` or be
   * null.
   */
  readonly sipral_call_conference_uri: (stack: Wide, call: Wide, buffer: Pointer, capacity: number, out_needed: Pointer) => number;

  /**
   * Subscribe to the conference package of the call's focus (RFC 4579
   * §3.4), outside the call's dialog, from the call's own account, and
   * write the subscription's handle. It is kept like any subscription and
   * outlives the call; `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED` says what it
   * learns.
   *
   * `SIPRAL_STATUS_NOT_A_FOCUS` for a call whose far end did not say it is
   * a focus.
   *
   * Safety
   *
   * `out_subscription` must point at one `sipral_handle_t`.
   */
  readonly sipral_call_subscribe_conference: (stack: Wide, call: Wide, out_subscription: Pointer, now_ms: Wide) => number;

  /**
   * Publish this account's presence (RFC 3903, RFC 3856 §6.2): a PIDF
   * document for its address of record, open or closed, with the activity
   * and the note `presence` gives. The first call publishes it and every
   * later one modifies the same publication; the stack keeps it refreshed
   * until sipral_account_unpublish_presence.
   *
   * Nothing has happened when this returns: the PUBLISH is in the
   * transmit queue, and `SIPRAL_EVENT_KIND_PRESENCE_CHANGED` with
   * `SIPRAL_PRESENCE_KIND_PUBLICATION` says what the compositor did with
   * it.
   *
   * Safety
   *
   * `presence` must point at a `sipral_presence_t` whose `size` member
   * says how long it is, with its pointer readable for the length beside
   * it.
   */
  readonly sipral_account_publish_presence: (stack: Wide, account: Wide, presence: Pointer, now_ms: Wide) => number;

  /**
   * Take this account's published presence away (RFC 3903 §4.5):
   * `SIPRAL_PUBLICATION_STATE_REMOVED` says when it is gone.
   *
   * `SIPRAL_STATUS_WRONG_STATE` for an account that has published none.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_account_unpublish_presence: (stack: Wide, account: Wide, now_ms: Wide) => number;

  /**
   * Queue text the user typed for the far end, UTF-8.
   *
   * It goes in the next transmission interval (300 ms), at no more
   * characters a second than the far end said it takes, each block sent
   * twice more as redundancy where both ends agreed `red`. A CR LF, a
   * lone CR or a lone LF goes as a new line, and BACKSPACE (U+0008) erases
   * the far end's last character.
   *
   * `SIPRAL_STATUS_NOT_NEGOTIATED` on a call that agreed no text stream,
   * and `SIPRAL_STATUS_EXHAUSTED` when more is waiting unsent than a
   * stream holds; nothing is queued then, and a later call finds room as
   * the far end reads.
   *
   * Safety
   *
   * `text` must be readable for `text_len` bytes.
   */
  readonly sipral_media_send_text: (media: Wide, text: Pointer, text_len: number) => number;

  /**
   * The next datagram due on the call's text socket.
   *
   * A `len` of zero in the packet means nothing is due; call it again at
   * the deadline `sipral_stack_poll` names, or with every frame of audio.
   * Send what it writes from the socket at `text_address`, never the
   * audio one.
   *
   * `now_ms` is read as the stack reads it and moves nothing, as with
   * every media entry point.
   *
   * Safety
   *
   * `packet` must point at a `sipral_media_packet_t` as
   * `sipral_media_capture` describes.
   */
  readonly sipral_media_poll_text: (media: Wide, now_ms: Wide, packet: Pointer) => number;

  /**
   * Take a datagram off the call's text socket.
   *
   * `out_taken` is written with 1 when it was this call's text, and 0
   * when it was not: not RTP, another payload type, from somewhere other
   * than where the stream has latched, or on a call with no text. What it
   * carried arrives as `SIPRAL_EVENT_KIND_TEXT_RECEIVED`.
   *
   * Safety
   *
   * `data` must be readable for `len` bytes, `from` for `from_len`, and
   * `out_taken` must point at one `uint32_t` or be null.
   */
  readonly sipral_media_receive_text: (media: Wide, data: Pointer, len: number, from: Pointer, from_len: number, now_ms: Wide, out_taken: Pointer) => number;

  /**
   * Record a call to a recording server (RFC 7866), and write the
   * recording session's handle to `out_recording`.
   *
   * The call must be one this stack runs the media of, with its audio
   * started: `SIPRAL_STATUS_WRONG_STATE` before
   * `SIPRAL_EVENT_KIND_MEDIA_STARTED`, and for a call already being
   * recorded to a server. The recording session goes from the recorded
   * call's account, over a stream transport when the INVITE, which
   * carries the metadata beside the offer, is too large for UDP.
   *
   * Hanging the recording session up with
   * sipral_call_stop_recording_to or `sipral_call_hangup` stops the
   * recording; the server hanging it up does the same.
   *
   * Safety
   *
   * `config` must point at a `sipral_record_config_t` whose `size` member
   * says how long it is, with every pointer in it readable for the length
   * beside it, and `out_recording` at one `sipral_handle_t`.
   */
  readonly sipral_call_record_to: (stack: Wide, call: Wide, config: Pointer, out_recording: Pointer, now_ms: Wide) => number;

  /**
   * Stop recording a call to its recording server: the copies stop at
   * once, and the recording session is hung up.
   *
   * `call` is the recorded call, not the recording session.
   * `SIPRAL_STATUS_WRONG_STATE` for a call nothing records.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_call_stop_recording_to: (stack: Wide, call: Wide, now_ms: Wide) => number;

  /**
   * The next copy of this call's audio for its recording server.
   *
   * A `len` of zero in the packet means none is waiting. Otherwise
   * `out_far_end` says which socket to send it from: 0 for `this_end`,
   * the copy of what this end sent, and 1 for `far_end`, the copy of what
   * it received. Collect them with every frame, in a loop to empty: a
   * copy nobody collects for a second is dropped, the oldest first.
   *
   * Safety
   *
   * `packet` must point at a `sipral_media_packet_t` as
   * `sipral_media_capture` describes, and `out_far_end` at one
   * `uint32_t`.
   */
  readonly sipral_media_poll_recording: (media: Wide, packet: Pointer, out_far_end: Pointer) => number;

  /**
   * Start recording the signalling this stack is fed from here on
   * (`docs/18-replay.md`), on a seed of its own. Starting moves every
   * branch, tag and `Call-ID` the stack draws from here on onto a fresh
   * seed, derived one way from the `entropy` `sipral_stack_create` was
   * given; the recording carries that seed and never `entropy`, and
   * stopping moves the stack on again, so nothing drawn after the stop
   * can be worked out from the file. Read `docs/18-replay.md` before
   * reaching for this: it records what arrives, exactly as it arrived,
   * and never what this end sent.
   *
   * `note` is one line of prose for whoever opens the file later, or null
   * for none.
   *
   * A recording already running is replaced, not refused. Nothing is
   * written until `sipral_stack_recording_stop`, so a second start costs
   * only the frames taken since the first; `sipral_media_record_start`
   * refuses a second start because its file is already open on disk.
   *
   * Safety
   *
   * `note` must be readable for `note_len` bytes or be null with a length
   * of zero.
   */
  readonly sipral_stack_recording_start: (stack: Wide, note: Pointer, note_len: number) => number;

  /**
   * Stop the recording sipral_stack_recording_start began, and copy
   * the text of it into `buffer` (`docs/18-replay.md`).
   *
   * `SIPRAL_STATUS_WRONG_STATE` when no recording is running, the same
   * answer `sipral_media_record_stop` gives for the same question about
   * an audio recording. `SIPRAL_STATUS_WRONG_STATE` again, with the reason
   * in the last error, when something this session was fed could not go
   * in the recording — a message with a body that is not text is the one
   * way that happens — in which case nothing is written to `buffer` and
   * the recording is not produced at all: a text format that quietly left
   * out the one message it could not spell would replay into a different
   * session and say nothing about it.
   *
   * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
   * text, with the length needed in `out_needed` — asking again with a bigger
   * buffer answers the same recording rather than stopping a new one,
   * so a caller that does not yet know how big a buffer to bring may ask
   * twice: once to be told, once to be handed the text. Once a call here
   * copies the whole of it out, the recording is gone from the stack, the
   * same as `sipral_last_error_message` empties the slot it reads on a
   * call that succeeds.
   *
   * Safety
   *
   * `buffer` must be writable for `capacity` bytes or be null with a
   * capacity of zero, and `out_needed` must point at one `size_t` or be null.
   */
  readonly sipral_stack_recording_stop: (stack: Wide, buffer: Pointer, capacity: number, out_needed: Pointer) => number;

  /**
   * Ask the platform what devices there are, and say how many the list
   * holds now.
   *
   * A device seen before keeps its id; one that has gone keeps its row,
   * marked absent; a new one gets the next id. The engine refreshes by
   * itself when the platform announces a change, so this is for a
   * settings screen opening, not for polling.
   * `SIPRAL_STATUS_DEVICE_TIMED_OUT` when the platform did not answer
   * within `audio_probe_ms`, with the list left as it was.
   *
   * Safety
   *
   * `out_count` must point at one `size_t` or be null.
   */
  readonly sipral_audio_refresh: (stack: Wide, out_count: Pointer) => number;

  /**
   * How many devices the list holds, present or not.
   *
   * The first read of a stack's list, here or through
   * `sipral_audio_device_at`, asks the platform when nothing has yet, so
   * a new stack lists every device without `sipral_audio_refresh`
   * (ABI 0.35); `SIPRAL_STATUS_DEVICE_TIMED_OUT` when the platform did not
   * answer within `audio_probe_ms`, and the next read asks again.
   *
   * Safety
   *
   * `out_count` must point at one `size_t`.
   */
  readonly sipral_audio_device_count: (stack: Wide, out_count: Pointer) => number;

  /**
   * The device at `index` in the list, and its name into `buffer`.
   *
   * `SIPRAL_STATUS_INVALID_ARGUMENT` for an index past the end. The name
   * is written the way every other text this ABI hands out is: UTF-8 with
   * a trailing NUL, and `out_needed`, when it is not null, receives the
   * bytes it needs with that NUL counted. When the name does not fit, the
   * answer is `SIPRAL_STATUS_BUFFER_TOO_SMALL` and nothing is written,
   * neither to `buffer` nor to `out_device`: ask with a capacity of zero
   * to learn the length, then again with room.
   *
   * Safety
   *
   * `out_device` must point at a `sipral_audio_device_t` whose `size`
   * member says how long it is; `buffer` must be writable for `capacity`
   * bytes or null with a capacity of zero; `out_needed` must point at one
   * `size_t` or be null.
   */
  readonly sipral_audio_device_at: (stack: Wide, index: number, out_device: Pointer, buffer: Pointer, capacity: number, out_needed: Pointer) => number;

  /**
   * Put a role on a device, or back on the system's route with a
   * `device` of zero.
   *
   * Refused before any platform call is made: `SIPRAL_STATUS_NO_SUCH_DEVICE`
   * for an id the list never held, `SIPRAL_STATUS_DEVICE_UNUSABLE` for a
   * device with no channels in the role's direction or one that is not
   * plugged in, `SIPRAL_STATUS_NOT_SUPPORTED` where the platform cannot
   * put that role on a device of its own — macOS runs the call's
   * microphone and loudspeaker as one unit, and the microphone follows
   * the system's input. A refused selection changes nothing.
   *
   * While the engine is active the role is reopened at once, the gain and
   * the mute of its direction carried over, and
   * `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED` says `SIPRAL_AUDIO_CHANGE_SELECTED`
   * from the engine. A device chosen and later unplugged is a preference:
   * the role runs on the system's route meanwhile and goes back to the
   * device when it returns.
   *
   * Safety
   *
   * Reads no memory the caller owns.
   */
  readonly sipral_audio_select: (stack: Wide, role: number, device: number) => number;

  /**
   * What a role was asked to be on, and what it is running on: the id
   * chosen with `sipral_audio_select` or zero for the system's route, and
   * the id of the device the role is actually open on or zero when it is
   * not open. The two differ while a chosen device is unplugged.
   *
   * Safety
   *
   * Each out parameter must point at one `uint32_t` or be null.
   */
  readonly sipral_audio_selection: (stack: Wide, role: number, out_selected: Pointer, out_running: Pointer) => number;

  /**
   * Set the gain of one direction, as a fixed-point ratio with 256 for
   * unity: 128 halves, 512 doubles, 0 is silence, and anything above 1024
   * is taken as 1024. The input direction's gain is the microphone gain;
   * the output's is the volume. Applied to the frames rather than to the
   * operating system's own control, so a film playing beside the call is
   * not turned down with it, and kept across every device change.
   *
   * Safety
   *
   * Reads no memory the caller owns.
   */
  readonly sipral_audio_set_gain: (stack: Wide, direction: number, gain: number) => number;

  /**
   * The gain of one direction, in the steps `sipral_audio_set_gain` takes.
   *
   * Safety
   *
   * `out_gain` must point at one `uint32_t`.
   */
  readonly sipral_audio_gain: (stack: Wide, direction: number, out_gain: Pointer) => number;

  /**
   * Mute one direction, or unmute it, kept across every device change. A
   * muted microphone still runs and sends silence, so the far end hears a
   * stream rather than a gap.
   *
   * Safety
   *
   * Reads no memory the caller owns.
   */
  readonly sipral_audio_set_muted: (stack: Wide, direction: number, muted: number) => number;

  /**
   * Whether one direction is muted: one or zero into `out_muted`.
   *
   * Safety
   *
   * `out_muted` must point at one `uint32_t`.
   */
  readonly sipral_audio_muted: (stack: Wide, direction: number, out_muted: Pointer) => number;

  /**
   * The meter of one direction: the loudest sample of the last tenth of a
   * second, 0 to 32767, held for between one window and two so that a
   * bar drawn from it neither flickers nor sticks. Cheap enough to poll
   * at a window's frame rate; zero while nothing is open.
   *
   * Safety
   *
   * `out_peak` must point at one `uint32_t`.
   */
  readonly sipral_audio_level: (stack: Wide, direction: number, out_peak: Pointer) => number;

  /**
   * Open the devices and start the pump now, whatever the calls are
   * doing. Under `SIPRAL_AUDIO_ACTIVATION_MANUAL` this is the only thing
   * that does; under automatic activation it opens them early.
   *
   * `SIPRAL_STATUS_DEVICE_UNUSABLE` or `SIPRAL_STATUS_DEVICE_TIMED_OUT`
   * when a direction could not be opened: the engine is active all the
   * same, silent in that direction, and `sipral_audio_info` says which.
   *
   * Safety
   *
   * Reads no memory the caller owns.
   */
  readonly sipral_audio_activate: (stack: Wide) => number;

  /**
   * Close the devices and stop the pump. The calls stay attached and get
   * their audio back on the next activation.
   *
   * Safety
   *
   * Reads no memory the caller owns.
   */
  readonly sipral_audio_deactivate: (stack: Wide) => number;

  /**
   * Play a ring tone on the ringer — the device `SIPRAL_AUDIO_ROLE_RINGER`
   * is on, or the loudspeaker when it is on none of its own — until
   * `sipral_audio_stop_ringing`, or once through when `looped` is zero.
   * The tone is mono sixteen-bit samples at `sample_rate_hz`, copied, so
   * the caller's buffer is its own again when this returns. Under
   * automatic activation a ring opens the devices.
   *
   * Safety
   *
   * `samples` must be readable for `sample_count` `int16_t`.
   */
  readonly sipral_audio_ring: (stack: Wide, samples: Pointer, sample_count: number, sample_rate_hz: number, looped: number) => number;

  /**
   * Stop the ring. Under automatic activation, with no call up, the
   * devices close with it.
   *
   * Safety
   *
   * Reads no memory the caller owns.
   */
  readonly sipral_audio_stop_ringing: (stack: Wide) => number;

  /**
   * What the engine is doing: whether it is active, whether the platform
   * cancels echo, the delay a canceller needs, and where each role runs.
   *
   * Safety
   *
   * `out_info` must point at a `sipral_audio_info_t` whose `size` member
   * says how long it is.
   */
  readonly sipral_audio_info: (stack: Wide, out_info: Pointer) => number;

  /**
   * Turn the platform's own echo cancellation on or off on a running
   * stack: `on` is a `sipral_toggle_t`, and zero leaves it as it is
   * (ABI 1.1). What `sipral_stack_config_t::system_echo_cancellation`
   * chose at creation, without a new stack.
   *
   * Takes effect at once. While the devices are open the microphone and
   * the loudspeaker are reopened with or without the platform's
   * processing — the voice-processing unit on macOS and iOS, the
   * communications stream on Windows, the voice-communication preset on
   * Android — on the devices they were on, with the gain and the mute of
   * each direction, and each says so with `SIPRAL_AUDIO_CHANGE_REOPENED`
   * from the engine. A call in progress keeps its media and hears a gap
   * of as long as the platform takes to open them; a direction the
   * platform refuses is `SIPRAL_AUDIO_CHANGE_UNAVAILABLE`, as after any
   * reopen. With the devices closed, the next open uses it.
   * `sipral_audio_info_t::system_echo_cancellation` says what the
   * platform did, and `sipral_stack_settings_t::system_echo_cancellation`
   * what is asked for. `SIPRAL_STATUS_WRONG_STATE` in application mode,
   * where the devices are the application's, whatever `on` says.
   *
   * Safety
   *
   * Reads no memory the caller owns.
   */
  readonly sipral_audio_set_system_echo_cancellation: (stack: Wide, on: number) => number;

  /**
   * Send this stack's log to `callback`, at `level` and louder — or turn
   * it off with `SIPRAL_LOG_LEVEL_OFF` or a null callback.
   *
   * A stack is created with its log off, and a log that is off costs
   * nothing: no line is formatted for it. Calling this again replaces the
   * callback and the level, on this stack alone; lines already waiting go
   * to the new callback. Turning the log off drops what was waiting.
   *
   * What each level carries, how lines are rate-limited and how they are
   * redacted is in this module's documentation and in
   * `docs/17-observability.md`. A level above `SIPRAL_LOG_LEVEL_TRACE` is
   * `SIPRAL_STATUS_INVALID_ARGUMENT` and changes nothing.
   *
   * Safety
   *
   * `callback`, when not null, is called from inside later calls into this
   * stack on whichever thread made them, once the stack has been let go
   * (see sipral_log_callback_t). `user_data` is handed back to it untouched
   * and must stay valid until the log is turned off or replaced and no
   * thread is inside this stack any more.
   */
  readonly sipral_stack_log: (stack: Wide, level: number, callback: Pointer, user_data: Pointer) => number;

  /**
   * Copy a snapshot of everything this stack is holding into `buffer`, as
   * text for a crash report: its accounts and their registrations, its
   * calls and their states, its transports, its media sessions, the last
   * calls into it that were refused, its queues, its RTP port range and
   * its counters — redacted, and never longer than
   * `SIPRAL_STATE_TEXT_MAX` bytes with the NUL, so a buffer that size
   * always has room.
   *
   * Safe from any thread, including one the stack is busy on, and never
   * waits. When no other thread is inside the stack the snapshot is taken
   * there and then; when one is, what comes back is the last snapshot a
   * poll kept — polls keep one at most once a second, and only when
   * something happened — and its first line says so and when it was
   * taken. A call's media session that a thread is in the middle of a
   * frame on is reported as busy rather than waited for.
   *
   * `SIPRAL_STATUS_BUFFER_TOO_SMALL`, with the length needed in `out_needed`,
   * when it does not fit; `out_needed` may be null.
   *
   * Safety
   *
   * `buffer` must be writable for `capacity` bytes or be null with a
   * capacity of zero, and `out_needed` must point at one `size_t` or be null.
   */
  readonly sipral_stack_state_text: (stack: Wide, buffer: Pointer, capacity: number, out_needed: Pointer) => number;

  /**
   * Reserve a free even port from this stack's RTP range, with the odd
   * port above it kept for RTCP, and write it to `out_port`.
   *
   * `SIPRAL_STATUS_EXHAUSTED` when every pair in the range is taken —
   * reserved, or described by a call this stack still holds — and the
   * last error says how many pairs the range has. Nothing is reserved
   * then. `SIPRAL_STATUS_WRONG_STATE` on a stack created without a range:
   * its ports are the application's to choose.
   *
   * Safety
   *
   * `out_port` must point at one `uint32_t`.
   */
  readonly sipral_stack_rtp_port_reserve: (stack: Wide, out_port: Pointer) => number;

  /**
   * Give back a port sipral_stack_rtp_port_reserve handed out that no
   * call is using: the socket could not be bound there, or the call was
   * refused. A port a call took comes back by itself when the call ends,
   * and needs no release.
   *
   * `SIPRAL_STATUS_INVALID_ARGUMENT` for a port that is not reserved,
   * which is also what a second release of the same port is.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_stack_rtp_port_release: (stack: Wide, port: number) => number;

  /**
   * Verify the callers of the calls this stack's accounts receive, against
   * `config`'s trust anchors, from now on (RFC 8224 §6.2).
   *
   * Replaces whatever an earlier call set. Every account that reports —
   * the default — verifies once there is at least one anchor, and none
   * does with none; an account set to `SIPRAL_STIR_VERIFICATION_STRICT`
   * verifies either way. `config.unix_seconds` is the wall clock at
   * `now_ms`, and the stack signs and verifies by it from here on; zero
   * keeps what an earlier call gave, and is `SIPRAL_STATUS_WRONG_STATE`
   * on the first. A stack whose accounts only sign calls makes this call
   * too, with no anchors.
   *
   * `SIPRAL_STATUS_INVALID_ARGUMENT` for anchors that are not
   * certificates, or whose key is not P-256; `SIPRAL_STATUS_NOT_SUPPORTED`
   * in a build without `SIPRAL_FEATURE_STIR`.
   *
   * Safety
   *
   * `config` must point at a `sipral_stir_config_t` whose `size` member
   * says how long it is, with `anchors` readable for `anchors_len` bytes.
   */
  readonly sipral_stack_stir: (stack: Wide, config: Pointer, now_ms: Wide) => number;

  /**
   * The certificate chain a call's `Identity` named, as fetched from the
   * URL `SIPRAL_EVENT_KIND_CALLER_VERIFICATION` gave with
   * `SIPRAL_VERIFICATION_STAGE_CERTIFICATE_WANTED` — PEM or DER, the
   * signing certificate first — or null and zero for one that could not
   * be fetched.
   *
   * The call's verdict is reached here and reported, and the call
   * delivered or refused, before this returns; the events come out of the
   * next `sipral_stack_poll`. `SIPRAL_STATUS_STALE_HANDLE` for a call no
   * longer waiting: it was already answered, its wait ran out, or the
   * caller gave up.
   *
   * Safety
   *
   * `chain` must be readable for `chain_len` bytes, or null with a length
   * of zero.
   */
  readonly sipral_call_stir_certificate: (stack: Wide, call: Wide, chain: Pointer, chain_len: number, now_ms: Wide) => number;

  /**
   * How many streams one call's encryption report has: one per stream
   * the call carries, which for this library is its one audio stream.
   *
   * Safety
   *
   * `out_count` must point at one `size_t`.
   */
  readonly sipral_media_encryption_count: (media: Wide, out_count: Pointer) => number;

  /**
   * How one stream of a call is protected, now: whether it is encrypted,
   * how its keys were exchanged, which suite it runs, and whether the
   * exchange authenticated the far end. An index past the end is
   * `SIPRAL_STATUS_INVALID_ARGUMENT`.
   *
   * Safety
   *
   * `out_stream` must point at a `sipral_stream_encryption_t` whose `size`
   * member says how long it is.
   */
  readonly sipral_media_encryption_at: (media: Wide, index: number, out_stream: Pointer) => number;

  /**
   * Listen for keypad digits in this call's far-end audio as `mode` says:
   * a sipral_dtmf_detection_t. Before the call has media as well as
   * after, for the rest of the call.
   *
   * `SIPRAL_STATUS_WRONG_STATE` for a call whose media this stack does
   * not run.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_call_dtmf_detection: (stack: Wide, call: Wide, mode: number) => number;

  /**
   * Listen for call progress on this call and decide who answers it, as
   * `config` says, or stop with `config.listen` off. Meant for a call this
   * stack placed, straight after `sipral_call_place`: the tones are
   * listened for from the first frame of early media, and who answered is
   * decided from the 2xx on. Each thing heard is a
   * `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`.
   *
   * `SIPRAL_STATUS_WRONG_STATE` for a call whose media this stack does
   * not run; `SIPRAL_STATUS_INVALID_ARGUMENT` for a value no detector
   * takes, which changes nothing.
   *
   * Safety
   *
   * `config` must point at a `sipral_progress_config_t` whose `size`
   * member says how long it is.
   */
  readonly sipral_call_detect_progress: (stack: Wide, call: Wide, config: Pointer) => number;

  /**
   * Beep on this call while it is recorded, as `tone` says, or play no
   * tone with `tone.enabled` off. A recording already running starts
   * beeping at once; one started later beeps from its first frame.
   *
   * `SIPRAL_STATUS_WRONG_STATE` for a call whose media this stack does
   * not run; `SIPRAL_STATUS_INVALID_ARGUMENT`, naming the member, for a
   * tone that is not a beep, which changes nothing.
   *
   * Safety
   *
   * `tone` must point at a `sipral_consent_tone_t` whose `size` member
   * says how long it is.
   */
  readonly sipral_call_consent_tone: (stack: Wide, call: Wide, tone: Pointer) => number;

  /**
   * Start recording this call to `path`, written as `options` say: WAV or
   * Ogg Opus, mixed or stereo with this end on the left, at a rate of the
   * file's own. Everything else is sipral_media_record_start's,
   * which is this with every option zero.
   *
   * `SIPRAL_STATUS_INVALID_ARGUMENT` for options no file can be written
   * with and for a path the file system refuses, and
   * `SIPRAL_STATUS_NOT_SUPPORTED` for Ogg Opus in a build with no Opus.
   * `SIPRAL_STATUS_RECORDING_FAILED` when the file was made and would not
   * take its header.
   *
   * Safety
   *
   * `path` must be readable for `path_len` bytes, and `options` must point
   * at a `sipral_recording_options_t` whose `size` member says how long
   * it is.
   */
  readonly sipral_media_record_start_with: (media: Wide, path: Pointer, path_len: number, options: Pointer) => number;

  /**
   * Make a local conference on this stack, empty but for this end when
   * `config` says it takes part, and write its handle to
   * `out_conference`.
   *
   * In device mode the audio engine starts carrying it at once, opening
   * the devices under automatic activation as a call's media does.
   *
   * `SIPRAL_STATUS_CONFERENCE_REFUSED` for a rate that is not 8, 16, 32
   * or 48 kHz and for more than 1024 members.
   *
   * Safety
   *
   * `config` must point at a `sipral_local_conference_config_t` whose
   * `size` member says how long it is, and `out_conference` at one
   * `sipral_handle_t`.
   */
  readonly sipral_local_conference_create: (stack: Wide, config: Pointer, out_conference: Pointer) => number;

  /**
   * End a conference. Every call still in it goes back to carrying its
   * own audio — in device mode, the audio engine takes each up again —
   * a recording running is finished, and the handle is stale.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_local_conference_destroy: (conference: Wide) => number;

  /**
   * Add a call. It takes part from the next tick, at its own codec's rate,
   * and its far end hears everybody in the conference but itself.
   *
   * The call needs media running, as for `sipral_call_media`.
   * `SIPRAL_STATUS_CONFERENCE_REFUSED` when the conference is full, for a
   * call already in this one or another or joined with
   * `sipral_call_join`, and for a codec the conference cannot mix — a
   * rate other than 8, 16, 32 or 48 kHz, or frames past 60 ms.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_local_conference_add: (conference: Wide, call: Wide) => number;

  /**
   * Take a call out. From the next tick nobody in the conference hears it
   * and it hears nobody; its media is the application's again — in device
   * mode, the audio engine carries it as it carries any call.
   *
   * `SIPRAL_STATUS_WRONG_STATE` for a call that is not in it.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_local_conference_remove: (conference: Wide, call: Wide) => number;

  /**
   * Mute or unmute one way of a member, from the next tick: its input,
   * which everybody else stops hearing, or its output, which it stops
   * hearing. `direction` is `SIPRAL_AUDIO_DIRECTION_INPUT` or
   * `SIPRAL_AUDIO_DIRECTION_OUTPUT`; `member` is a call in the conference,
   * or the conference's own handle for this end.
   *
   * `SIPRAL_STATUS_WRONG_STATE` for a member that is not in it.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_local_conference_set_muted: (conference: Wide, member: Wide, direction: number, muted: number) => number;

  /**
   * Set the level of one way of a member, from the next tick, in the
   * steps `sipral_audio_set_gain` takes: 256 is unity and 1024, four
   * times, the most. Its input's level is what everybody else hears of
   * it; its output's is what it hears.
   *
   * Safety
   *
   * Safe to call with any handle values.
   */
  readonly sipral_local_conference_set_gain: (conference: Wide, member: Wide, direction: number, gain: number) => number;

  /**
   * How the conference stands.
   *
   * Safety
   *
   * `out_info` must point at a `sipral_local_conference_info_t` whose
   * `size` member says how long it is.
   */
  readonly sipral_local_conference_info: (conference: Wide, out_info: Pointer) => number;

  /**
   * One member, by index: this end first when it takes part, then the
   * calls in the order they joined. The index is stable until the next
   * member joins or leaves.
   *
   * `SIPRAL_STATUS_INVALID_ARGUMENT` for an index past the last member.
   *
   * Safety
   *
   * `out_member` must point at a `sipral_local_conference_member_t` whose
   * `size` member says how long it is.
   */
  readonly sipral_local_conference_member_at: (conference: Wide, index: number, out_member: Pointer) => number;

  /**
   * Who was talking in the last tick, by rank: index zero is the
   * loudest. A muted member is never listed.
   *
   * `SIPRAL_STATUS_INVALID_ARGUMENT` for an index past the last talker,
   * which `sipral_local_conference_info_t::talkers` counts.
   *
   * Safety
   *
   * `out_member` must point at one `sipral_handle_t`.
   */
  readonly sipral_local_conference_talker_at: (conference: Wide, index: number, out_member: Pointer) => number;

  /**
   * Twenty milliseconds of conference, in application mode: `mic` is this
   * end's frame, `sipral_local_conference_info_t::frame_samples` long,
   * and `speaker` is filled with what this end hears, the same length,
   * written to `out_written`. A conference without this end reads no
   * microphone — `mic` may be null — and fills `speaker` with silence.
   *
   * Call it once every twenty milliseconds, from the thread that carries
   * the audio, and then drain `sipral_local_conference_poll_transmit`.
   *
   * `SIPRAL_STATUS_WRONG_STATE` in device mode, where the audio engine
   * ticks it; `SIPRAL_STATUS_INVALID_ARGUMENT` for a frame of any other
   * length, and `SIPRAL_STATUS_BUFFER_TOO_SMALL` for a speaker buffer
   * shorter than a frame, with the length needed in `out_written`.
   *
   * Safety
   *
   * `mic` must be readable for `mic_count` `int16_t`, `speaker` writable
   * for `capacity` `int16_t`, and `out_written` must point at one
   * `size_t` or be null.
   */
  readonly sipral_local_conference_tick: (conference: Wide, now_ms: Wide, mic: Pointer, mic_count: number, speaker: Pointer, capacity: number, out_written: Pointer) => number;

  /**
   * The oldest packet a member's call owes its far end, in application
   * mode: `out_call` names the call, whose media socket sends it, and
   * `packet` is filled as `sipral_media_capture` fills one. A `len`
   * of zero, with `SIPRAL_HANDLE_NONE` in `out_call`, means nothing is
   * waiting. Drain it after every tick.
   *
   * Safety
   *
   * `out_call` must point at one `sipral_handle_t`, and `packet` at a
   * `sipral_media_packet_t` as `sipral_media_capture` describes.
   */
  readonly sipral_local_conference_poll_transmit: (conference: Wide, out_call: Pointer, packet: Pointer) => number;

  /**
   * Record the whole conference to `path`: everybody it hears, each at
   * its own level, in one channel, written as `options` say — WAV or Ogg
   * Opus, at the conference's rate unless another is named.
   *
   * `SIPRAL_STATUS_WRONG_STATE` when it is already being recorded,
   * `SIPRAL_STATUS_INVALID_ARGUMENT` for a stereo layout, for options no
   * file can be written with and for a path the file system refuses, and
   * `SIPRAL_STATUS_RECORDING_FAILED` when the file would not take its
   * header.
   *
   * Safety
   *
   * `path` must be readable for `path_len` bytes, and `options` must point
   * at a `sipral_recording_options_t` whose `size` member says how long
   * it is.
   */
  readonly sipral_local_conference_record_start: (conference: Wide, path: Pointer, path_len: number, options: Pointer) => number;

  /**
   * Stop recording the conference, and finish the file.
   *
   * `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_local_conference_record_stop: (conference: Wide) => number;

  /**
   * Hand the resolver's answer to a
   * SIPRAL_EVENT_KIND_LOOKUP_WANTED
   * back to the account that asked.
   *
   * `name` and `record` are the event's, as it named them; `answer` is a
   * sipral_dns_answer_t. With `SIPRAL_DNS_ANSWER_RECORDS`, `records` is
   * what the resolver returned, every record of the kind asked for,
   * separated by commas, each its fields separated by spaces: the
   * time-to-live in seconds, then the data as a zone file writes it —
   * an address for A and AAAA (`300 192.0.2.40`); priority, weight,
   * port and target for SRV (`300 10 60 5060 sip1.example.com`); order,
   * preference, flags, service and replacement for NAPTR, the regular
   * expression left out since RFC 3263 follows none (`300 10 50 S
   * SIP+D2U _sip._udp.example.com`). Null or empty for none, which
   * reads as `SIPRAL_DNS_ANSWER_NOTHING`. Text, rather than an array of
   * structs, because it is what a platform resolver prints and what
   * every binding hands over as it is.
   *
   * Answer every lookup, a resolver that failed included: the procedure
   * waits for each. An answer to a lookup nothing is waiting for any
   * more — the account was located since, or it has been asked for
   * again — is `SIPRAL_STATUS_OK` and changes nothing, as is one for an
   * account that locates nothing.
   *
   * Safety
   *
   * `name` must be readable for `name_len` bytes and `records` for
   * `records_len`.
   */
  readonly sipral_account_looked_up: (stack: Wide, account: Wide, name: Pointer, name_len: number, record: number, answer: number, records: Pointer, records_len: number, now_ms: Wide) => number;

  /**
   * Check the certificate a TLS server presented against the one the
   * account pins, from inside the application's certificate verifier.
   *
   * `certificate` is the DER encoding of the leaf, the first certificate
   * the server sent, and `unix_seconds` the wall clock, which only the
   * dates reported in `out_pinned` are read against. The fingerprint
   * is SHA-256 over those exact bytes, compared in constant time.
   *
   * `SIPRAL_STATUS_OK` with `pinned` set: the certificate is the pinned
   * one, and the handshake is to be accepted whatever its chain, its name
   * or its dates. `SIPRAL_STATUS_CERTIFICATE_REFUSED`: the account pins a
   * certificate and this is another; refuse the handshake, and nothing is
   * written. `SIPRAL_STATUS_OK` with `pinned` zero: the account pins
   * nothing, and the platform's own checks decide.
   *
   * Safety
   *
   * `certificate` must be readable for `certificate_len` bytes, and
   * `out_pinned` must point at a `sipral_pinned_certificate_t` whose
   * `size` member says how long it is.
   */
  readonly sipral_account_check_certificate: (stack: Wide, account: Wide, certificate: Pointer, certificate_len: number, unix_seconds: Wide, out_pinned: Pointer) => number;

  /**
   * The address to advertise — in a `Contact`, a `bind_address`, a
   * `media_address` — for a socket bound at `bound` whose traffic goes to
   * `peer`, as `host:port`, written into `buffer` with a NUL after it.
   *
   * A socket bound to a specific address advertises it, unless it is a
   * loopback address and `peer` is not: `SIPRAL_STATUS_UNREACHABLE_ADDRESS`,
   * with nothing written. A socket bound to the wildcard address
   * (`0.0.0.0:5060`, `[::]:5060`) advertises the address of the
   * operating system's route toward `peer`, with its own port; the route
   * is found by connecting a datagram socket and closing it, and nothing
   * is sent. No route to `peer` at all is `SIPRAL_STATUS_TRANSPORT_DOWN`.
   * `peer` is the registrar for the signalling socket, and the far end —
   * or the registrar, while the far end is not known yet — for a media
   * socket. Both are `host:port` addresses, not names.
   *
   * Callable from any thread at any time: it names no stack. Text out as
   * every such call writes it: `out_needed` receives the length with the
   * NUL counted, `buffer` may be null with a `capacity` of zero to ask for
   * it, and `SIPRAL_STATUS_BUFFER_TOO_SMALL` writes nothing.
   *
   * Safety
   *
   * `bound` and `peer` must be readable for their lengths, `buffer` must
   * be writable for `capacity` bytes or be null with a capacity of zero,
   * and `out_needed` must point at one `size_t` or be null.
   */
  readonly sipral_advertised_address: (bound: Pointer, bound_len: number, peer: Pointer, peer_len: number, buffer: Pointer, capacity: number, out_needed: Pointer) => number;

  /**
   * Turn the diagnostic trace on or off while the stack runs: `on` is a
   * `sipral_toggle_t`, and zero leaves it as it is (ABI 0.34).
   *
   * On, the trace level of `sipral_stack_log` writes every SIP message
   * whole, with the peer it went to or came from, and prose lines
   * without pseudonyms: for a diagnosis, where pseudonyms would hide the
   * difference between two runs. What is never written, on or off, is a
   * credential or a key — `sipral_stack_config_t::diagnostic_trace` has
   * the list. Off, the trace is pseudonymised as it always was. Nothing
   * is written at all unless the log is at `SIPRAL_LOG_LEVEL_TRACE`.
   *
   * Safety
   *
   * Safe to call with any handle value.
   */
  readonly sipral_stack_diagnostic_trace: (stack: Wide, on: number) => number;

  /**
   * The SRTP suites this stack's calls offer and accept unless their
   * account names its own, in the order they are offered, as
   * `sipral_srtp_suite_t` numbers: the ones `srtp_suites` named at
   * creation, or this build's own (ABI 0.35). `out_count` always receives
   * how many there are — `sipral_stack_settings_t::srtp_suite_count` — so a
   * caller that passes a capacity of zero and a null buffer learns how
   * much room to bring and gets `SIPRAL_STATUS_BUFFER_TOO_SMALL`, as
   * `sipral_stack_codec_order` does.
   *
   * Safety
   *
   * `out_suites` must be writable for `capacity` `uint32_t` or null with a
   * capacity of zero, and `out_count` must point at one `size_t` or be null.
   */
  readonly sipral_stack_srtp_suite_order: (stack: Wide, out_suites: Pointer, capacity: number, out_count: Pointer) => number;

  /**
   * Set one call's own gain in one direction, on top of the stack's
   * (`sipral_audio_set_gain`), in the same steps: the input direction is
   * what the microphone sends that call alone, the output how loud that
   * call is in the loudspeaker beside the others (ABI 0.35). Applied in
   * the engine's mix from the next frame; kept while the call is held or
   * moved into a conference and back, and gone when it ends. While the
   * call is a member of a local conference they go with it and act on
   * its path there, on top of the conference's own member controls
   * (`sipral_local_conference_set_muted` and `_set_gain`): the input
   * direction on what the conference sends the call, which is what its
   * far end hears, and the output direction on what the call says into
   * the conference, which is what this end and every other member hear
   * of it.
   * `SIPRAL_STATUS_WRONG_STATE` for a call whose media the engine is not
   * carrying — before its media starts, after it ends, or in application
   * mode, where the frames are the application's own.
   *
   * Safety
   *
   * Reads no memory the caller owns.
   */
  readonly sipral_audio_call_set_gain: (stack: Wide, call: Wide, direction: number, gain: number) => number;

  /**
   * One call's own gain in one direction, in the steps
   * `sipral_audio_call_set_gain` takes (ABI 0.35).
   *
   * Safety
   *
   * `out_gain` must point at one `uint32_t`.
   */
  readonly sipral_audio_call_gain: (stack: Wide, call: Wide, direction: number, out_gain: Pointer) => number;

  /**
   * Mute one call in one direction, or unmute it (ABI 0.35): the far end
   * of that call alone hears silence, or that call alone is silent in the
   * loudspeaker, while every other call goes on — the other half of a
   * consultation. In a local conference the mute goes with the call: its
   * far end hears nobody there, or nobody there hears it (see
   * `sipral_audio_call_set_gain`). A muted
   * direction still runs and sends silence. Kept and dropped as
   * `sipral_audio_call_set_gain` is, and refused the same way.
   *
   * Safety
   *
   * Reads no memory the caller owns.
   */
  readonly sipral_audio_call_set_muted: (stack: Wide, call: Wide, direction: number, muted: number) => number;

  /**
   * Whether one call is muted in one direction: one or zero into
   * `out_muted` (ABI 0.35).
   *
   * Safety
   *
   * `out_muted` must point at one `uint32_t`.
   */
  readonly sipral_audio_call_muted: (stack: Wide, call: Wide, direction: number, out_muted: Pointer) => number;

  /**
   * One call's meter in one direction (ABI 0.35): the loudest sample of
   * the last tenth of a second of what the microphone sent that call, or
   * of what the call played, after its own gain and mute, 0 to 32767 —
   * `sipral_audio_level`'s reading for one call of several. Cheap enough
   * to poll at a window's frame rate.
   *
   * Safety
   *
   * `out_peak` must point at one `uint32_t`.
   */
  readonly sipral_audio_call_level: (stack: Wide, call: Wide, direction: number, out_peak: Pointer) => number;

  private constructor(library: ReturnType<typeof koffi.load>, path: string) {
    this.path = path;
    this.sipral_last_error_message = library.func('sipral_status_t sipral_last_error_message(char *buffer, size_t capacity, size_t *out_needed)');
    this.sipral_status_name = library.func('const char *sipral_status_name(int32_t status)');
    this.sipral_abi_version = library.func('sipral_status_t sipral_abi_version(sipral_abi_version_t *out_version)');
    this.sipral_abi_check = library.func('sipral_status_t sipral_abi_check(uint32_t major, uint32_t minor)');
    this.sipral_abi_struct_size = library.func('sipral_status_t sipral_abi_struct_size(const char *name, size_t name_len, size_t *out_size)');
    this.sipral_abi_versioned_count = library.func('sipral_status_t sipral_abi_versioned_count(size_t *out_count)');
    this.sipral_capabilities = library.func('sipral_status_t sipral_capabilities(sipral_capabilities_t *out_capabilities)');
    this.sipral_stack_create = library.func('sipral_status_t sipral_stack_create(const sipral_stack_config_t *config, sipral_handle_t *out_stack)');
    this.sipral_stack_settings = library.func('sipral_status_t sipral_stack_settings(sipral_handle_t stack, sipral_stack_settings_t *out_settings)');
    this.sipral_stack_destroy = library.func('sipral_status_t sipral_stack_destroy(sipral_handle_t stack)');
    this.sipral_stack_poll = library.func('sipral_status_t sipral_stack_poll(sipral_handle_t stack, uint64_t now_ms, sipral_poll_result_t *result)');
    this.sipral_stack_counters = library.func('sipral_status_t sipral_stack_counters(sipral_handle_t stack, sipral_counters_t *out_counters)');
    this.sipral_stack_screen = library.func('sipral_status_t sipral_stack_screen(sipral_handle_t stack, sipral_screen_callback_t *callback, void *user_data)');
    this.sipral_stack_invite_limit = library.func('sipral_status_t sipral_stack_invite_limit(sipral_handle_t stack, uint64_t every_ms, uint32_t burst)');
    this.sipral_account_subscribe = library.func('sipral_status_t sipral_account_subscribe(sipral_handle_t stack, sipral_handle_t account, const sipral_subscribe_config_t *config, sipral_handle_t *out_subscription, uint64_t now_ms)');
    this.sipral_subscription_end = library.func('sipral_status_t sipral_subscription_end(sipral_handle_t stack, sipral_handle_t subscription, uint64_t now_ms)');
    this.sipral_subscription_state = library.func('sipral_status_t sipral_subscription_state(sipral_handle_t stack, sipral_handle_t subscription, sipral_subscription_state_t *out_state)');
    this.sipral_subscription_lamp = library.func('sipral_status_t sipral_subscription_lamp(sipral_handle_t stack, sipral_handle_t subscription, sipral_dialog_phase_t *out_phase)');
    this.sipral_subscription_dialog_count = library.func('sipral_status_t sipral_subscription_dialog_count(sipral_handle_t stack, sipral_handle_t subscription, size_t *out_count)');
    this.sipral_subscription_dialog_at = library.func('sipral_status_t sipral_subscription_dialog_at(sipral_handle_t stack, sipral_handle_t subscription, size_t index, sipral_watched_dialog_t *out_dialog)');
    this.sipral_subscription_dialog_text = library.func('sipral_status_t sipral_subscription_dialog_text(sipral_handle_t stack, sipral_handle_t subscription, size_t index, sipral_dialog_text_t which, char *buffer, size_t capacity, size_t *out_needed)');
    this.sipral_account_message = library.func('sipral_status_t sipral_account_message(sipral_handle_t stack, sipral_handle_t account, const char *target, size_t target_len, const char *content_type, size_t content_type_len, const uint8_t *body, size_t body_len, sipral_handle_t *out_message, uint64_t now_ms)');
    this.sipral_account_announce = library.func('sipral_status_t sipral_account_announce(sipral_handle_t stack, sipral_handle_t account, const char *caller, size_t caller_len, sipral_handle_t *out_announcement, sipral_handle_t *out_call, uint64_t now_ms)');
    this.sipral_account_refresh_binding = library.func('sipral_status_t sipral_account_refresh_binding(sipral_handle_t stack, sipral_handle_t account, uint64_t now_ms)');
    this.sipral_announcement_forget = library.func('sipral_status_t sipral_announcement_forget(sipral_handle_t stack, sipral_handle_t announcement)');
    this.sipral_account_push_echo = library.func('sipral_status_t sipral_account_push_echo(sipral_handle_t stack, sipral_handle_t account, sipral_push_echo_t *out_echo)');
    this.sipral_account_add = library.func('sipral_status_t sipral_account_add(sipral_handle_t stack, const sipral_account_config_t *config, sipral_handle_t *out_account)');
    this.sipral_account_remove = library.func('sipral_status_t sipral_account_remove(sipral_handle_t stack, sipral_handle_t account)');
    this.sipral_account_register = library.func('sipral_status_t sipral_account_register(sipral_handle_t stack, sipral_handle_t account, uint64_t now_ms)');
    this.sipral_account_unregister = library.func('sipral_status_t sipral_account_unregister(sipral_handle_t stack, sipral_handle_t account, uint64_t now_ms)');
    this.sipral_account_registration_state = library.func('sipral_status_t sipral_account_registration_state(sipral_handle_t stack, sipral_handle_t account, sipral_registration_state_t *out_state)');
    this.sipral_account_set_access_token = library.func('sipral_status_t sipral_account_set_access_token(sipral_handle_t stack, sipral_handle_t account, const char *token, size_t token_len)');
    this.sipral_stack_network_test = library.func('sipral_status_t sipral_stack_network_test(sipral_handle_t stack, const sipral_network_test_config_t *config, uint64_t now_ms, uint32_t *out_test)');
    this.sipral_call_place = library.func('sipral_status_t sipral_call_place(sipral_handle_t stack, sipral_handle_t account, const sipral_call_config_t *config, sipral_handle_t *out_call, uint64_t now_ms)');
    this.sipral_call_ring = library.func('sipral_status_t sipral_call_ring(sipral_handle_t stack, sipral_handle_t call, const uint8_t *sdp, size_t sdp_len, uint64_t now_ms)');
    this.sipral_call_ring_media = library.func('sipral_status_t sipral_call_ring_media(sipral_handle_t stack, sipral_handle_t call, const sipral_call_config_t *config, uint64_t now_ms)');
    this.sipral_call_answer = library.func('sipral_status_t sipral_call_answer(sipral_handle_t stack, sipral_handle_t call, const uint8_t *sdp, size_t sdp_len, uint64_t now_ms)');
    this.sipral_call_answer_media = library.func('sipral_status_t sipral_call_answer_media(sipral_handle_t stack, sipral_handle_t call, const char *media_address, size_t media_address_len, uint64_t now_ms)');
    this.sipral_call_answer_with = library.func('sipral_status_t sipral_call_answer_with(sipral_handle_t stack, sipral_handle_t call, const sipral_call_config_t *config, uint64_t now_ms)');
    this.sipral_call_reject = library.func('sipral_status_t sipral_call_reject(sipral_handle_t stack, sipral_handle_t call, uint32_t code, uint64_t now_ms)');
    this.sipral_call_hangup = library.func('sipral_status_t sipral_call_hangup(sipral_handle_t stack, sipral_handle_t call, uint64_t now_ms)');
    this.sipral_call_set_headers = library.func('sipral_status_t sipral_call_set_headers(sipral_handle_t stack, sipral_handle_t call, const sipral_header_t *headers, size_t headers_len)');
    this.sipral_call_hold = library.func('sipral_status_t sipral_call_hold(sipral_handle_t stack, sipral_handle_t call, uint64_t now_ms)');
    this.sipral_call_resume = library.func('sipral_status_t sipral_call_resume(sipral_handle_t stack, sipral_handle_t call, uint64_t now_ms)');
    this.sipral_call_change_codecs = library.func('sipral_status_t sipral_call_change_codecs(sipral_handle_t stack, sipral_handle_t call, const char *codecs, size_t codecs_len, uint64_t now_ms)');
    this.sipral_call_restart_ice = library.func('sipral_status_t sipral_call_restart_ice(sipral_handle_t stack, sipral_handle_t call, uint64_t now_ms)');
    this.sipral_call_media_readdress = library.func('sipral_status_t sipral_call_media_readdress(sipral_handle_t stack, sipral_handle_t call, const char *media_address, size_t media_address_len, const char *public_address, size_t public_address_len, uint64_t now_ms)');
    this.sipral_call_hangup_for = library.func('sipral_status_t sipral_call_hangup_for(sipral_handle_t stack, sipral_handle_t call, uint32_t sip_cause, uint32_t q850_cause, const char *text, size_t text_len, uint64_t now_ms)');
    this.sipral_call_redirect = library.func('sipral_status_t sipral_call_redirect(sipral_handle_t stack, sipral_handle_t call, uint32_t status_code, const char *targets, size_t targets_len, const char *reason, size_t reason_len, uint64_t now_ms)');
    this.sipral_call_identity_count = library.func('sipral_status_t sipral_call_identity_count(sipral_handle_t stack, sipral_handle_t call, sipral_identity_text_t which, size_t *out_count)');
    this.sipral_call_identity_text = library.func('sipral_status_t sipral_call_identity_text(sipral_handle_t stack, sipral_handle_t call, size_t index, sipral_identity_text_t which, char *buffer, size_t capacity, size_t *out_needed)');
    this.sipral_call_join = library.func('sipral_status_t sipral_call_join(sipral_handle_t stack, sipral_handle_t call_a, sipral_handle_t call_b)');
    this.sipral_call_leave = library.func('sipral_status_t sipral_call_leave(sipral_handle_t stack, sipral_handle_t call)');
    this.sipral_call_accept_session = library.func('sipral_status_t sipral_call_accept_session(sipral_handle_t stack, sipral_handle_t call, const uint8_t *sdp, size_t sdp_len, uint64_t now_ms)');
    this.sipral_call_reject_session = library.func('sipral_status_t sipral_call_reject_session(sipral_handle_t stack, sipral_handle_t call, uint32_t code, uint64_t now_ms)');
    this.sipral_call_send_dtmf = library.func('sipral_status_t sipral_call_send_dtmf(sipral_handle_t stack, sipral_handle_t call, const char *digits, size_t digits_len, sipral_dtmf_t via, uint32_t duration_ms, uint64_t now_ms)');
    this.sipral_call_transfer = library.func('sipral_status_t sipral_call_transfer(sipral_handle_t stack, sipral_handle_t call, const char *target, size_t target_len, uint64_t now_ms)');
    this.sipral_call_consult = library.func('sipral_status_t sipral_call_consult(sipral_handle_t stack, sipral_handle_t call, const sipral_call_config_t *config, sipral_handle_t *out_consultation, uint64_t now_ms)');
    this.sipral_call_transfer_to = library.func('sipral_status_t sipral_call_transfer_to(sipral_handle_t stack, sipral_handle_t call, sipral_handle_t other, uint64_t now_ms)');
    this.sipral_call_accept_transfer = library.func('sipral_status_t sipral_call_accept_transfer(sipral_handle_t stack, sipral_handle_t call, const sipral_call_config_t *config, sipral_handle_t *out_placed, uint64_t now_ms)');
    this.sipral_call_reject_transfer = library.func('sipral_status_t sipral_call_reject_transfer(sipral_handle_t stack, sipral_handle_t call, uint32_t code, uint64_t now_ms)');
    this.sipral_call_accept_transfer_placed = library.func('sipral_status_t sipral_call_accept_transfer_placed(sipral_handle_t stack, sipral_handle_t call, sipral_handle_t placed, uint64_t now_ms)');
    this.sipral_call_state = library.func('sipral_status_t sipral_call_state(sipral_handle_t stack, sipral_handle_t call, sipral_call_state_t *out_state)');
    this.sipral_call_hold_state = library.func('sipral_status_t sipral_call_hold_state(sipral_handle_t stack, sipral_handle_t call, uint32_t *out_here, uint32_t *out_there)');
    this.sipral_codec_name = library.func('const char *sipral_codec_name(sipral_codec_t codec)');
    this.sipral_codec_count = library.func('sipral_status_t sipral_codec_count(size_t *out_count)');
    this.sipral_codec_at = library.func('sipral_status_t sipral_codec_at(size_t index, sipral_codec_info_t *out_info)');
    this.sipral_stack_codec_order = library.func('sipral_status_t sipral_stack_codec_order(sipral_handle_t stack, sipral_codec_t *out_codecs, size_t capacity, size_t *out_count)');
    this.sipral_call_media = library.func('sipral_status_t sipral_call_media(sipral_handle_t stack, sipral_handle_t call, sipral_handle_t *out_media)');
    this.sipral_media_release = library.func('sipral_status_t sipral_media_release(sipral_handle_t media)');
    this.sipral_media_info = library.func('sipral_status_t sipral_media_info(sipral_handle_t media, sipral_media_info_t *out_info)');
    this.sipral_media_codec_candidate_count = library.func('sipral_status_t sipral_media_codec_candidate_count(sipral_handle_t media, size_t *out_count)');
    this.sipral_media_codec_candidate_at = library.func('sipral_status_t sipral_media_codec_candidate_at(sipral_handle_t media, size_t index, sipral_codec_candidate_t *out_candidate)');
    this.sipral_media_path_candidate_count = library.func('sipral_status_t sipral_media_path_candidate_count(sipral_handle_t media, size_t *out_count)');
    this.sipral_media_path_candidate_at = library.func('sipral_status_t sipral_media_path_candidate_at(sipral_handle_t media, size_t index, sipral_path_candidate_t *out_candidate)');
    this.sipral_media_statistics = library.func('sipral_status_t sipral_media_statistics(sipral_handle_t media, uint64_t now_ms, sipral_stream_stats_t *out_stats)');
    this.sipral_media_receive = library.func('sipral_status_t sipral_media_receive(sipral_handle_t media, uint8_t *data, size_t len, const char *from, size_t from_len, uint64_t now_ms, sipral_arrival_t *out_arrival)');
    this.sipral_media_playback = library.func('sipral_status_t sipral_media_playback(sipral_handle_t media, int16_t *samples, size_t capacity, size_t *out_written, sipral_playback_t *out_source)');
    this.sipral_media_capture = library.func('sipral_status_t sipral_media_capture(sipral_handle_t media, uint64_t now_ms, const int16_t *samples, size_t sample_count, sipral_media_packet_t *packet)');
    this.sipral_media_set_app_rate = library.func('sipral_status_t sipral_media_set_app_rate(sipral_handle_t media, uint32_t hz)');
    this.sipral_media_attach_processor = library.func('sipral_status_t sipral_media_attach_processor(sipral_handle_t media, sipral_processor_callback_t *callback, void *user_data)');
    this.sipral_media_detach_processor = library.func('sipral_status_t sipral_media_detach_processor(sipral_handle_t media, uint32_t *out_was_attached)');
    this.sipral_media_reset_processor = library.func('sipral_status_t sipral_media_reset_processor(sipral_handle_t media, uint32_t *out_was_attached)');
    this.sipral_media_mix = library.func('sipral_status_t sipral_media_mix(sipral_handle_t media_a, sipral_handle_t media_b, uint64_t now_ms, const int16_t *mic, size_t mic_count, int16_t *local, size_t local_count, sipral_media_packet_t *packet_a, sipral_media_packet_t *packet_b)');
    this.sipral_media_poll_rtcp = library.func('sipral_status_t sipral_media_poll_rtcp(sipral_handle_t media, uint64_t now_ms, sipral_media_packet_t *packet)');
    this.sipral_media_poll_transmit = library.func('sipral_status_t sipral_media_poll_transmit(sipral_handle_t media, uint64_t now_ms, sipral_media_packet_t *packet)');
    this.sipral_stack_poll_farewell = library.func('sipral_status_t sipral_stack_poll_farewell(sipral_handle_t stack, sipral_handle_t *out_call, sipral_media_packet_t *packet)');
    this.sipral_media_dialling = library.func('sipral_status_t sipral_media_dialling(sipral_handle_t media, uint32_t *out_dialling, size_t *out_waiting)');
    this.sipral_media_stop_dialling = library.func('sipral_status_t sipral_media_stop_dialling(sipral_handle_t media)');
    this.sipral_media_record_start = library.func('sipral_status_t sipral_media_record_start(sipral_handle_t media, const char *path, size_t path_len)');
    this.sipral_media_record_stop = library.func('sipral_status_t sipral_media_record_stop(sipral_handle_t media)');
    this.sipral_media_record_state = library.func('sipral_status_t sipral_media_record_state(sipral_handle_t media, uint32_t *out_recording, uint64_t *out_recorded_ms)');
    this.sipral_stack_poll_transmit = library.func('sipral_status_t sipral_stack_poll_transmit(sipral_handle_t stack, sipral_transmit_t *transmit)');
    this.sipral_stack_receive_datagram = library.func('sipral_status_t sipral_stack_receive_datagram(sipral_handle_t stack, uint32_t transport, const uint8_t *data, size_t len, const char *from, size_t from_len, const char *to, size_t to_len, uint64_t now_ms)');
    this.sipral_stack_receive_stream = library.func('sipral_status_t sipral_stack_receive_stream(sipral_handle_t stack, uint32_t transport, const uint8_t *data, size_t len, uint64_t now_ms)');
    this.sipral_stack_transport_bind = library.func('sipral_status_t sipral_stack_transport_bind(sipral_handle_t stack, uint32_t transport, sipral_transport_t protocol, const char *local, size_t local_len, const char *remote, size_t remote_len, uint64_t now_ms, uint32_t *out_transport_id)');
    this.sipral_stack_transport_failed = library.func('sipral_status_t sipral_stack_transport_failed(sipral_handle_t stack, uint32_t transport, sipral_transport_error_t error, uint64_t now_ms)');
    this.sipral_stack_transport_failed_with = library.func('sipral_status_t sipral_stack_transport_failed_with(sipral_handle_t stack, const sipral_transport_failure_t *failure, uint64_t now_ms)');
    this.sipral_stack_stream_closed = library.func('sipral_status_t sipral_stack_stream_closed(sipral_handle_t stack, uint32_t transport, uint64_t now_ms)');
    this.sipral_stack_stun_servers = library.func('sipral_status_t sipral_stack_stun_servers(sipral_handle_t stack, const char *servers, size_t servers_len, uint64_t now_ms)');
    this.sipral_stack_nat_map = library.func('sipral_status_t sipral_stack_nat_map(sipral_handle_t stack, const char *local, size_t local_len, uint64_t now_ms)');
    this.sipral_stack_nat_unmap = library.func('sipral_status_t sipral_stack_nat_unmap(sipral_handle_t stack, const char *local, size_t local_len, uint64_t now_ms)');
    this.sipral_stack_poll_stun = library.func('sipral_status_t sipral_stack_poll_stun(sipral_handle_t stack, sipral_transmit_t *transmit)');
    this.sipral_stack_receive_stun = library.func('sipral_status_t sipral_stack_receive_stun(sipral_handle_t stack, const uint8_t *data, size_t len, const char *from, size_t from_len, const char *to, size_t to_len, uint64_t now_ms)');
    this.sipral_stack_turn_connected = library.func('sipral_status_t sipral_stack_turn_connected(sipral_handle_t stack, const char *local, size_t local_len, uint64_t now_ms)');
    this.sipral_stack_turn_receive = library.func('sipral_status_t sipral_stack_turn_receive(sipral_handle_t stack, const char *local, size_t local_len, const uint8_t *data, size_t len, uint64_t now_ms)');
    this.sipral_stack_turn_closed = library.func('sipral_status_t sipral_stack_turn_closed(sipral_handle_t stack, const char *local, size_t local_len, uint64_t now_ms)');
    this.sipral_event_kind_name = library.func('const char *sipral_event_kind_name(sipral_event_kind_t kind)');
    this.sipral_message_header_count = library.func('sipral_status_t sipral_message_header_count(const uint8_t *message, size_t message_len, const char *name, size_t name_len, size_t *out_count)');
    this.sipral_message_header = library.func('sipral_status_t sipral_message_header(const uint8_t *message, size_t message_len, const char *name, size_t name_len, size_t index, size_t *out_offset, size_t *out_len)');
    this.sipral_message_header_element_count = library.func('sipral_status_t sipral_message_header_element_count(const uint8_t *message, size_t message_len, const char *name, size_t name_len, size_t *out_count)');
    this.sipral_message_header_element = library.func('sipral_status_t sipral_message_header_element(const uint8_t *message, size_t message_len, const char *name, size_t name_len, size_t index, size_t *out_offset, size_t *out_len)');
    this.sipral_stack_suspending = library.func('sipral_status_t sipral_stack_suspending(sipral_handle_t stack, uint64_t now_ms, sipral_suspending_t *out_report)');
    this.sipral_stack_resumed = library.func('sipral_status_t sipral_stack_resumed(sipral_handle_t stack, uint64_t now_ms)');
    this.sipral_stack_network_changed = library.func('sipral_status_t sipral_stack_network_changed(sipral_handle_t stack, sipral_link_t from_link, const char *from_address, size_t from_address_len, const char *from_interface, size_t from_interface_len, uint32_t from_resolves, sipral_link_t to_link, const char *to_address, size_t to_address_len, const char *to_interface, size_t to_interface_len, uint32_t to_resolves, uint64_t now_ms, sipral_recovery_t *out_recovery)');
    this.sipral_stack_interface_lost = library.func('sipral_status_t sipral_stack_interface_lost(sipral_handle_t stack, uint64_t now_ms)');
    this.sipral_stack_name_resolution_lost = library.func('sipral_status_t sipral_stack_name_resolution_lost(sipral_handle_t stack, uint64_t now_ms)');
    this.sipral_account_rebind = library.func('sipral_status_t sipral_account_rebind(sipral_handle_t stack, sipral_handle_t account, uint32_t transport, const char *remote, size_t remote_len, const char *contact, size_t contact_len, uint64_t now_ms)');
    this.sipral_stack_cold_start = library.func('sipral_status_t sipral_stack_cold_start(sipral_handle_t stack, uint64_t now_ms)');
    this.sipral_account_freeze = library.func('sipral_status_t sipral_account_freeze(sipral_handle_t stack, sipral_handle_t account, uint8_t *buffer, size_t capacity, size_t *out_len, uint64_t now_ms)');
    this.sipral_account_thaw = library.func('sipral_status_t sipral_account_thaw(sipral_handle_t stack, sipral_handle_t account, const uint8_t *snapshot, size_t snapshot_len, uint64_t asleep_ms, uint64_t now_ms)');
    this.sipral_account_time_to_ready = library.func('sipral_status_t sipral_account_time_to_ready(sipral_handle_t stack, sipral_handle_t account, uint32_t *out_has_value, uint64_t *out_ms)');
    this.sipral_stack_resolved = library.func('sipral_status_t sipral_stack_resolved(sipral_handle_t stack, sipral_handle_t dialog, const char *addresses, size_t addresses_len, sipral_transport_t protocol)');
    this.sipral_account_retarget = library.func('sipral_status_t sipral_account_retarget(sipral_handle_t stack, sipral_handle_t account, const char *registrar_address, size_t registrar_address_len, uint64_t now_ms)');
    this.sipral_call_record_json = library.func('sipral_status_t sipral_call_record_json(sipral_handle_t stack, sipral_handle_t call, char *buffer, size_t capacity, size_t *out_needed)');
    this.sipral_stack_diagnostics_json = library.func('sipral_status_t sipral_stack_diagnostics_json(sipral_handle_t stack, char *buffer, size_t capacity, size_t *out_needed)');
    this.sipral_subscription_conference = library.func('sipral_status_t sipral_subscription_conference(sipral_handle_t stack, sipral_handle_t subscription, sipral_conference_t *out_conference)');
    this.sipral_subscription_conference_user_at = library.func('sipral_status_t sipral_subscription_conference_user_at(sipral_handle_t stack, sipral_handle_t subscription, size_t index, sipral_conference_user_t *out_user)');
    this.sipral_subscription_conference_text = library.func('sipral_status_t sipral_subscription_conference_text(sipral_handle_t stack, sipral_handle_t subscription, size_t index, sipral_conference_text_t which, char *buffer, size_t capacity, size_t *out_needed)');
    this.sipral_call_set_focus = library.func('sipral_status_t sipral_call_set_focus(sipral_handle_t stack, sipral_handle_t call, uint32_t focus)');
    this.sipral_call_conference_uri = library.func('sipral_status_t sipral_call_conference_uri(sipral_handle_t stack, sipral_handle_t call, char *buffer, size_t capacity, size_t *out_needed)');
    this.sipral_call_subscribe_conference = library.func('sipral_status_t sipral_call_subscribe_conference(sipral_handle_t stack, sipral_handle_t call, sipral_handle_t *out_subscription, uint64_t now_ms)');
    this.sipral_account_publish_presence = library.func('sipral_status_t sipral_account_publish_presence(sipral_handle_t stack, sipral_handle_t account, const sipral_presence_t *presence, uint64_t now_ms)');
    this.sipral_account_unpublish_presence = library.func('sipral_status_t sipral_account_unpublish_presence(sipral_handle_t stack, sipral_handle_t account, uint64_t now_ms)');
    this.sipral_media_send_text = library.func('sipral_status_t sipral_media_send_text(sipral_handle_t media, const char *text, size_t text_len)');
    this.sipral_media_poll_text = library.func('sipral_status_t sipral_media_poll_text(sipral_handle_t media, uint64_t now_ms, sipral_media_packet_t *packet)');
    this.sipral_media_receive_text = library.func('sipral_status_t sipral_media_receive_text(sipral_handle_t media, const uint8_t *data, size_t len, const char *from, size_t from_len, uint64_t now_ms, uint32_t *out_taken)');
    this.sipral_call_record_to = library.func('sipral_status_t sipral_call_record_to(sipral_handle_t stack, sipral_handle_t call, const sipral_record_config_t *config, sipral_handle_t *out_recording, uint64_t now_ms)');
    this.sipral_call_stop_recording_to = library.func('sipral_status_t sipral_call_stop_recording_to(sipral_handle_t stack, sipral_handle_t call, uint64_t now_ms)');
    this.sipral_media_poll_recording = library.func('sipral_status_t sipral_media_poll_recording(sipral_handle_t media, sipral_media_packet_t *packet, uint32_t *out_far_end)');
    this.sipral_stack_recording_start = library.func('sipral_status_t sipral_stack_recording_start(sipral_handle_t stack, const char *note, size_t note_len)');
    this.sipral_stack_recording_stop = library.func('sipral_status_t sipral_stack_recording_stop(sipral_handle_t stack, char *buffer, size_t capacity, size_t *out_needed)');
    this.sipral_audio_refresh = library.func('sipral_status_t sipral_audio_refresh(sipral_handle_t stack, size_t *out_count)');
    this.sipral_audio_device_count = library.func('sipral_status_t sipral_audio_device_count(sipral_handle_t stack, size_t *out_count)');
    this.sipral_audio_device_at = library.func('sipral_status_t sipral_audio_device_at(sipral_handle_t stack, size_t index, sipral_audio_device_t *out_device, char *buffer, size_t capacity, size_t *out_needed)');
    this.sipral_audio_select = library.func('sipral_status_t sipral_audio_select(sipral_handle_t stack, sipral_audio_role_t role, uint32_t device)');
    this.sipral_audio_selection = library.func('sipral_status_t sipral_audio_selection(sipral_handle_t stack, sipral_audio_role_t role, uint32_t *out_selected, uint32_t *out_running)');
    this.sipral_audio_set_gain = library.func('sipral_status_t sipral_audio_set_gain(sipral_handle_t stack, sipral_audio_direction_t direction, uint32_t gain)');
    this.sipral_audio_gain = library.func('sipral_status_t sipral_audio_gain(sipral_handle_t stack, sipral_audio_direction_t direction, uint32_t *out_gain)');
    this.sipral_audio_set_muted = library.func('sipral_status_t sipral_audio_set_muted(sipral_handle_t stack, sipral_audio_direction_t direction, uint32_t muted)');
    this.sipral_audio_muted = library.func('sipral_status_t sipral_audio_muted(sipral_handle_t stack, sipral_audio_direction_t direction, uint32_t *out_muted)');
    this.sipral_audio_level = library.func('sipral_status_t sipral_audio_level(sipral_handle_t stack, sipral_audio_direction_t direction, uint32_t *out_peak)');
    this.sipral_audio_activate = library.func('sipral_status_t sipral_audio_activate(sipral_handle_t stack)');
    this.sipral_audio_deactivate = library.func('sipral_status_t sipral_audio_deactivate(sipral_handle_t stack)');
    this.sipral_audio_ring = library.func('sipral_status_t sipral_audio_ring(sipral_handle_t stack, const int16_t *samples, size_t sample_count, uint32_t sample_rate_hz, uint32_t looped)');
    this.sipral_audio_stop_ringing = library.func('sipral_status_t sipral_audio_stop_ringing(sipral_handle_t stack)');
    this.sipral_audio_info = library.func('sipral_status_t sipral_audio_info(sipral_handle_t stack, sipral_audio_info_t *out_info)');
    this.sipral_audio_set_system_echo_cancellation = library.func('sipral_status_t sipral_audio_set_system_echo_cancellation(sipral_handle_t stack, sipral_toggle_t on)');
    this.sipral_stack_log = library.func('sipral_status_t sipral_stack_log(sipral_handle_t stack, sipral_log_level_t level, sipral_log_callback_t *callback, void *user_data)');
    this.sipral_stack_state_text = library.func('sipral_status_t sipral_stack_state_text(sipral_handle_t stack, char *buffer, size_t capacity, size_t *out_needed)');
    this.sipral_stack_rtp_port_reserve = library.func('sipral_status_t sipral_stack_rtp_port_reserve(sipral_handle_t stack, uint32_t *out_port)');
    this.sipral_stack_rtp_port_release = library.func('sipral_status_t sipral_stack_rtp_port_release(sipral_handle_t stack, uint32_t port)');
    this.sipral_stack_stir = library.func('sipral_status_t sipral_stack_stir(sipral_handle_t stack, const sipral_stir_config_t *config, uint64_t now_ms)');
    this.sipral_call_stir_certificate = library.func('sipral_status_t sipral_call_stir_certificate(sipral_handle_t stack, sipral_handle_t call, const uint8_t *chain, size_t chain_len, uint64_t now_ms)');
    this.sipral_media_encryption_count = library.func('sipral_status_t sipral_media_encryption_count(sipral_handle_t media, size_t *out_count)');
    this.sipral_media_encryption_at = library.func('sipral_status_t sipral_media_encryption_at(sipral_handle_t media, size_t index, sipral_stream_encryption_t *out_stream)');
    this.sipral_call_dtmf_detection = library.func('sipral_status_t sipral_call_dtmf_detection(sipral_handle_t stack, sipral_handle_t call, sipral_dtmf_detection_t mode)');
    this.sipral_call_detect_progress = library.func('sipral_status_t sipral_call_detect_progress(sipral_handle_t stack, sipral_handle_t call, const sipral_progress_config_t *config)');
    this.sipral_call_consent_tone = library.func('sipral_status_t sipral_call_consent_tone(sipral_handle_t stack, sipral_handle_t call, const sipral_consent_tone_t *tone)');
    this.sipral_media_record_start_with = library.func('sipral_status_t sipral_media_record_start_with(sipral_handle_t media, const char *path, size_t path_len, const sipral_recording_options_t *options)');
    this.sipral_local_conference_create = library.func('sipral_status_t sipral_local_conference_create(sipral_handle_t stack, const sipral_local_conference_config_t *config, sipral_handle_t *out_conference)');
    this.sipral_local_conference_destroy = library.func('sipral_status_t sipral_local_conference_destroy(sipral_handle_t conference)');
    this.sipral_local_conference_add = library.func('sipral_status_t sipral_local_conference_add(sipral_handle_t conference, sipral_handle_t call)');
    this.sipral_local_conference_remove = library.func('sipral_status_t sipral_local_conference_remove(sipral_handle_t conference, sipral_handle_t call)');
    this.sipral_local_conference_set_muted = library.func('sipral_status_t sipral_local_conference_set_muted(sipral_handle_t conference, sipral_handle_t member, sipral_audio_direction_t direction, uint32_t muted)');
    this.sipral_local_conference_set_gain = library.func('sipral_status_t sipral_local_conference_set_gain(sipral_handle_t conference, sipral_handle_t member, sipral_audio_direction_t direction, uint32_t gain)');
    this.sipral_local_conference_info = library.func('sipral_status_t sipral_local_conference_info(sipral_handle_t conference, sipral_local_conference_info_t *out_info)');
    this.sipral_local_conference_member_at = library.func('sipral_status_t sipral_local_conference_member_at(sipral_handle_t conference, size_t index, sipral_local_conference_member_t *out_member)');
    this.sipral_local_conference_talker_at = library.func('sipral_status_t sipral_local_conference_talker_at(sipral_handle_t conference, size_t index, sipral_handle_t *out_member)');
    this.sipral_local_conference_tick = library.func('sipral_status_t sipral_local_conference_tick(sipral_handle_t conference, uint64_t now_ms, const int16_t *mic, size_t mic_count, int16_t *speaker, size_t capacity, size_t *out_written)');
    this.sipral_local_conference_poll_transmit = library.func('sipral_status_t sipral_local_conference_poll_transmit(sipral_handle_t conference, sipral_handle_t *out_call, sipral_media_packet_t *packet)');
    this.sipral_local_conference_record_start = library.func('sipral_status_t sipral_local_conference_record_start(sipral_handle_t conference, const char *path, size_t path_len, const sipral_recording_options_t *options)');
    this.sipral_local_conference_record_stop = library.func('sipral_status_t sipral_local_conference_record_stop(sipral_handle_t conference)');
    this.sipral_account_looked_up = library.func('sipral_status_t sipral_account_looked_up(sipral_handle_t stack, sipral_handle_t account, const char *name, size_t name_len, sipral_dns_record_type_t record, sipral_dns_answer_t answer, const char *records, size_t records_len, uint64_t now_ms)');
    this.sipral_account_check_certificate = library.func('sipral_status_t sipral_account_check_certificate(sipral_handle_t stack, sipral_handle_t account, const uint8_t *certificate, size_t certificate_len, uint64_t unix_seconds, sipral_pinned_certificate_t *out_pinned)');
    this.sipral_advertised_address = library.func('sipral_status_t sipral_advertised_address(const char *bound, size_t bound_len, const char *peer, size_t peer_len, char *buffer, size_t capacity, size_t *out_needed)');
    this.sipral_stack_diagnostic_trace = library.func('sipral_status_t sipral_stack_diagnostic_trace(sipral_handle_t stack, sipral_toggle_t on)');
    this.sipral_stack_srtp_suite_order = library.func('sipral_status_t sipral_stack_srtp_suite_order(sipral_handle_t stack, sipral_srtp_suite_t *out_suites, size_t capacity, size_t *out_count)');
    this.sipral_audio_call_set_gain = library.func('sipral_status_t sipral_audio_call_set_gain(sipral_handle_t stack, sipral_handle_t call, sipral_audio_direction_t direction, uint32_t gain)');
    this.sipral_audio_call_gain = library.func('sipral_status_t sipral_audio_call_gain(sipral_handle_t stack, sipral_handle_t call, sipral_audio_direction_t direction, uint32_t *out_gain)');
    this.sipral_audio_call_set_muted = library.func('sipral_status_t sipral_audio_call_set_muted(sipral_handle_t stack, sipral_handle_t call, sipral_audio_direction_t direction, uint32_t muted)');
    this.sipral_audio_call_muted = library.func('sipral_status_t sipral_audio_call_muted(sipral_handle_t stack, sipral_handle_t call, sipral_audio_direction_t direction, uint32_t *out_muted)');
    this.sipral_audio_call_level = library.func('sipral_status_t sipral_audio_call_level(sipral_handle_t stack, sipral_handle_t call, sipral_audio_direction_t direction, uint32_t *out_peak)');
  }
}

/**
 * Every struct and union the header declares, with how long tools/abi-gen
 * worked it out to be on each of the three layouts the ABI ships for:
 * 64-bit pointers (p64), then 32-bit pointers with 64-bit integers aligned
 * to four (p32a4, i386) and to eight (p32a8, ARM and Windows x86). A size
 * test holds this binding's own layout of each record, and the library's
 * answer from sipral_abi_struct_size, to the number for the layout it runs
 * on; bindings/c/abi-layout.c holds a C compiler to all three.
 */
export const RECORD_LAYOUTS: Readonly<Record<string, readonly [number, number, number]>> = {
  sipral_abi_version_t: [24, 20, 20],
  sipral_capabilities_t: [24, 16, 16],
  sipral_counters_t: [232, 228, 232],
  sipral_stack_config_t: [432, 296, 304],
  sipral_poll_result_t: [48, 28, 32],
  sipral_stack_settings_t: [136, 128, 136],
  sipral_header_t: [32, 16, 16],
  sipral_account_config_t: [464, 256, 264],
  sipral_call_config_t: [152, 84, 84],
  sipral_codec_info_t: [32, 28, 28],
  sipral_codec_candidate_t: [24, 20, 20],
  sipral_path_candidate_t: [88, 60, 64],
  sipral_media_info_t: [104, 92, 96],
  sipral_stream_stats_t: [328, 312, 328],
  sipral_media_packet_t: [64, 36, 36],
  sipral_processor_frame_t: [64, 32, 32],
  sipral_transmit_t: [88, 48, 48],
  sipral_transport_failure_t: [40, 24, 24],
  sipral_registration_event_t: [40, 36, 40],
  sipral_call_event_t: [328, 208, 216],
  sipral_transfer_event_t: [24, 16, 16],
  sipral_media_event_t: [96, 80, 80],
  sipral_recovery_event_t: [16, 16, 16],
  sipral_transport_wanted_event_t: [40, 20, 20],
  sipral_subscription_event_t: [56, 56, 56],
  sipral_announce_event_t: [16, 16, 16],
  sipral_resolve_event_t: [32, 24, 24],
  sipral_message_event_t: [96, 64, 64],
  sipral_nat_event_t: [64, 40, 40],
  sipral_nat_relay_event_t: [72, 40, 40],
  sipral_referral_event_t: [40, 24, 24],
  sipral_turn_stream_event_t: [40, 24, 24],
  sipral_audio_event_t: [20, 20, 20],
  sipral_stun_server_event_t: [40, 20, 20],
  sipral_verification_event_t: [96, 60, 60],
  sipral_progress_event_t: [80, 80, 80],
  sipral_conference_event_t: [24, 20, 24],
  sipral_text_event_t: [24, 12, 12],
  sipral_presence_event_t: [88, 64, 72],
  sipral_transport_failed_event_t: [32, 24, 24],
  sipral_local_conference_event_t: [40, 40, 40],
  sipral_locate_event_t: [48, 32, 32],
  sipral_challenge_event_t: [40, 20, 20],
  sipral_token_event_t: [88, 48, 48],
  sipral_network_test_event_t: [104, 88, 88],
  sipral_event_payload_t: [328, 208, 216],
  sipral_event_t: [384, 248, 264],
  sipral_suspending_t: [32, 16, 16],
  sipral_screen_request_t: [48, 28, 32],
  sipral_subscribe_config_t: [88, 48, 48],
  sipral_watched_dialog_t: [32, 28, 32],
  sipral_push_echo_t: [24, 20, 24],
  sipral_audio_device_t: [32, 28, 28],
  sipral_audio_info_t: [48, 44, 48],
  sipral_audio_transmit_t: [56, 36, 40],
  sipral_log_record_t: [64, 40, 48],
  sipral_stir_config_t: [56, 44, 48],
  sipral_stream_encryption_t: [32, 28, 28],
  sipral_progress_config_t: [72, 68, 68],
  sipral_consent_tone_t: [32, 28, 28],
  sipral_recording_options_t: [32, 28, 28],
  sipral_conference_t: [32, 28, 28],
  sipral_conference_user_t: [24, 20, 20],
  sipral_presence_t: [32, 20, 20],
  sipral_record_config_t: [80, 40, 40],
  sipral_local_conference_config_t: [24, 20, 20],
  sipral_local_conference_info_t: [56, 48, 48],
  sipral_local_conference_member_t: [40, 36, 40],
  sipral_pinned_certificate_t: [40, 36, 40],
  sipral_network_test_config_t: [48, 36, 40],
};
