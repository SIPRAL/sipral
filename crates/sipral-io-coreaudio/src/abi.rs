// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The structures and constants the frameworks read, declared from Apple's
//! public headers.
//!
//! These are plain data, so they are compiled everywhere; only the calls that
//! take them need a framework to link against. That is deliberate: a wrong
//! field order or a missed pad byte produces audio that is noise rather than a
//! diagnostic, and the layout tests at the bottom of this file are cheap
//! enough to run on every target the workspace builds for.
//!
//! Every field keeps the width the header gives it and the order the header
//! gives it in. The names are ours.

use core::ffi::c_void;

/// A four-character code: the four bytes read as one big-endian integer, which
/// is how `OSType` is spelled in a header and how it prints in a debugger.
pub(crate) const fn code(text: [u8; 4]) -> u32 {
    u32::from_be_bytes(text)
}

/// `AudioStreamBasicDescription`, from `CoreAudioTypes/CoreAudioBaseTypes.h`:
/// one `Float64` followed by eight `UInt32`, so forty bytes aligned to eight.
///
/// Every other field in it is derived from the first three for linear PCM, and
/// getting one of them wrong is the classic way to end up with a stream that
/// opens, runs, and sounds like static.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct StreamDescription {
    pub(crate) sample_rate: f64,
    pub(crate) format_id: u32,
    pub(crate) format_flags: u32,
    pub(crate) bytes_per_packet: u32,
    pub(crate) frames_per_packet: u32,
    pub(crate) bytes_per_frame: u32,
    pub(crate) channels_per_frame: u32,
    pub(crate) bits_per_channel: u32,
    pub(crate) reserved: u32,
}

impl StreamDescription {
    /// One channel of packed signed sixteen-bit samples at the given rate,
    /// which is the only format that crosses this crate's boundary.
    ///
    /// Interleaving does not arise with one channel, and the native-endian
    /// flag is zero on every Apple target, so neither is set. Packet and frame
    /// are the same thing for linear PCM: one sample of one channel.
    pub(crate) fn mono_pcm(sample_rate_hz: u32) -> Self {
        let bytes_per_frame = u32::from(SAMPLE_BITS / 8);
        Self {
            sample_rate: f64::from(sample_rate_hz),
            format_id: FORMAT_LINEAR_PCM,
            format_flags: FORMAT_FLAG_SIGNED_INTEGER | FORMAT_FLAG_PACKED,
            bytes_per_packet: bytes_per_frame,
            frames_per_packet: 1,
            bytes_per_frame,
            channels_per_frame: 1,
            bits_per_channel: u32::from(SAMPLE_BITS),
            reserved: 0,
        }
    }
}

/// `AudioBuffer`, from `CoreAudioTypes/CoreAudioBaseTypes.h`: two `UInt32` and
/// a pointer, which the pointer's alignment pads to sixteen bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Buffer {
    pub(crate) channels: u32,
    pub(crate) byte_size: u32,
    pub(crate) data: *mut c_void,
}

/// `AudioBufferList`, from the same header: a count and a trailing array
/// declared as one element.
///
/// A list that carries more than one buffer is longer than this struct, so
/// anything that reads a list the framework allocated walks it by offset
/// rather than by dereferencing this type. What we hand to `AudioUnitRender`
/// is mono, and one buffer is all of it.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct BufferList {
    pub(crate) count: u32,
    pub(crate) buffers: [Buffer; 1],
}

/// `SMPTETime`, from `CoreAudioTypes/CoreAudioBaseTypes.h`. Nothing here reads
/// it; it is declared because it sits in the middle of [`TimeStamp`] and its
/// twenty-four bytes decide where the fields after it begin.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SmpteTime {
    pub(crate) subframes: i16,
    pub(crate) subframe_divisor: i16,
    pub(crate) counter: u32,
    pub(crate) time_type: u32,
    pub(crate) flags: u32,
    pub(crate) hours: i16,
    pub(crate) minutes: i16,
    pub(crate) seconds: i16,
    pub(crate) frames: i16,
}

/// `AudioTimeStamp`, from `CoreAudioTypes/CoreAudioBaseTypes.h`: four
/// eight-byte fields, the SMPTE block, then two `UInt32`. Sixty-four bytes.
///
/// It is passed through to `AudioUnitRender` unread. The stack does not take
/// its clock from the device.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct TimeStamp {
    pub(crate) sample_time: f64,
    pub(crate) host_time: u64,
    pub(crate) rate_scalar: f64,
    pub(crate) word_clock_time: u64,
    pub(crate) smpte: SmpteTime,
    pub(crate) flags: u32,
    pub(crate) reserved: u32,
}

/// `AudioComponentDescription`, from `AudioToolbox/AudioComponent.h`: five
/// `UInt32`, no padding.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ComponentDescription {
    pub(crate) component_type: u32,
    pub(crate) subtype: u32,
    pub(crate) manufacturer: u32,
    pub(crate) flags: u32,
    pub(crate) flags_mask: u32,
}

/// Bits in the one sample format this crate deals in.
pub(crate) const SAMPLE_BITS: u16 = 16;

/// The output unit family, `kAudioUnitType_Output`.
pub(crate) const UNIT_TYPE_OUTPUT: u32 = code(*b"auou");

/// `kAudioUnitSubType_VoiceProcessingIO`: duplex, with the system's own echo
/// cancellation and the voice-chat behaviour of the audio session behind it.
pub(crate) const UNIT_SUBTYPE_VOICE_PROCESSING: u32 = code(*b"vpio");

/// `kAudioUnitManufacturer_Apple`.
pub(crate) const MANUFACTURER_APPLE: u32 = code(*b"appl");

/// `kAudioFormatLinearPCM`.
pub(crate) const FORMAT_LINEAR_PCM: u32 = code(*b"lpcm");

/// `kAudioFormatFlagIsSignedInteger`.
pub(crate) const FORMAT_FLAG_SIGNED_INTEGER: u32 = 1 << 2;

/// `kAudioFormatFlagIsPacked`: no unused bits between samples, which for
/// sixteen-bit samples is the only sane reading anyway.
pub(crate) const FORMAT_FLAG_PACKED: u32 = 1 << 3;

/// `kAudioUnitScope_Global`.
pub(crate) const SCOPE_GLOBAL: u32 = 0;

/// `kAudioUnitScope_Input`: what the unit is given.
pub(crate) const SCOPE_INPUT: u32 = 1;

/// `kAudioUnitScope_Output`: what the unit hands back.
pub(crate) const SCOPE_OUTPUT: u32 = 2;

/// The bus that carries what goes to the speaker.
pub(crate) const BUS_OUTPUT: u32 = 0;

/// The bus that carries what came from the microphone.
pub(crate) const BUS_INPUT: u32 = 1;

/// `kAudioUnitProperty_StreamFormat`.
pub(crate) const PROPERTY_STREAM_FORMAT: u32 = 8;

/// `kAudioUnitProperty_MaximumFramesPerSlice`.
pub(crate) const PROPERTY_MAXIMUM_FRAMES_PER_SLICE: u32 = 14;

/// `kAudioUnitProperty_SetRenderCallback`.
pub(crate) const PROPERTY_SET_RENDER_CALLBACK: u32 = 23;

/// `kAudioOutputUnitProperty_CurrentDevice`. macOS only: iOS has no device to
/// name, only a route the audio session decides.
#[cfg(target_os = "macos")]
pub(crate) const PROPERTY_CURRENT_DEVICE: u32 = 2000;

/// `kAudioOutputUnitProperty_EnableIO`.
pub(crate) const PROPERTY_ENABLE_IO: u32 = 2003;

/// `kAudioOutputUnitProperty_SetInputCallback`.
pub(crate) const PROPERTY_SET_INPUT_CALLBACK: u32 = 2005;

/// `kAudioUnitRenderAction_OutputIsSilence`, set on the way out when there was
/// nothing to play.
pub(crate) const RENDER_ACTION_OUTPUT_IS_SILENCE: u32 = 1 << 4;

/// `kAudioUnitErr_FormatNotSupported`, one of the audio unit statuses that are
/// numbers rather than four-character codes.
pub(crate) const FORMAT_NOT_SUPPORTED: i32 = -10868;

/// `kAudioHardwareBadPropertySizeError`, which is what the frameworks say when
/// a property is not the size the caller expected. Reporting their own code
/// for that beats inventing one.
pub(crate) const BAD_PROPERTY_SIZE: i32 = i32::from_be_bytes(*b"!siz");

/// The hardware abstraction layer: what the machine has, rather than what one
/// audio unit is doing.
///
/// macOS only. iOS has no equivalent — routing there belongs to
/// `AVAudioSession`, which is Objective-C and is the embedding application's
/// to configure, not this crate's.
#[cfg(target_os = "macos")]
pub(crate) mod hardware {
    use super::code;

    /// `AudioObjectPropertyAddress`, from `CoreAudio/AudioHardwareBase.h`:
    /// three `UInt32`, being what to ask for, on which side of the device, and
    /// which channel.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct PropertyAddress {
        pub(crate) selector: u32,
        pub(crate) scope: u32,
        pub(crate) element: u32,
    }

    impl PropertyAddress {
        pub(crate) const fn new(selector: u32, scope: u32) -> Self {
            Self {
                selector,
                scope,
                // element zero is the main element; the per-channel elements
                // start at one and nothing here asks about one channel
                element: 0,
            }
        }
    }

    /// `kAudioObjectSystemObject`: the one object that answers questions about
    /// the machine rather than about a device.
    pub(crate) const SYSTEM_OBJECT: u32 = 1;

    /// `kAudioObjectPropertyScopeGlobal`.
    pub(crate) const SCOPE_GLOBAL: u32 = code(*b"glob");

    /// `kAudioObjectPropertyScopeInput`.
    pub(crate) const SCOPE_INPUT: u32 = code(*b"inpt");

    /// `kAudioObjectPropertyScopeOutput`.
    pub(crate) const SCOPE_OUTPUT: u32 = code(*b"outp");

    /// `kAudioObjectPropertyName`, a `CFStringRef` the caller then owns.
    pub(crate) const PROPERTY_NAME: u32 = code(*b"lnam");

    /// `kAudioHardwarePropertyDevices`.
    pub(crate) const PROPERTY_DEVICES: u32 = code(*b"dev#");

    /// `kAudioHardwarePropertyDefaultInputDevice`.
    pub(crate) const PROPERTY_DEFAULT_INPUT: u32 = code(*b"dIn ");

    /// `kAudioHardwarePropertyDefaultOutputDevice`.
    pub(crate) const PROPERTY_DEFAULT_OUTPUT: u32 = code(*b"dOut");

    /// `kAudioDevicePropertyDeviceUID`: the identifier that survives a replug,
    /// which the numeric object identifier does not.
    pub(crate) const PROPERTY_UID: u32 = code(*b"uid ");

    /// `kAudioDevicePropertyStreamConfiguration`: an `AudioBufferList`
    /// describing how many channels a device has on one side.
    pub(crate) const PROPERTY_STREAM_CONFIGURATION: u32 = code(*b"slay");

    /// `kAudioDevicePropertyDeviceIsAlive`: a `UInt32` that is zero once the
    /// hardware behind a device object has gone. The object outlives the
    /// hardware for a while, which is why the question can be asked at all.
    pub(crate) const PROPERTY_DEVICE_IS_ALIVE: u32 = code(*b"livn");

    /// `kCFStringEncodingUTF8`.
    pub(crate) const ENCODING_UTF8: u32 = 0x0800_0100;

    #[cfg(test)]
    mod tests {
        use super::{PROPERTY_DEVICES, PropertyAddress, SCOPE_GLOBAL, code};
        use core::mem::{align_of, offset_of, size_of};

        #[test]
        fn a_property_address_is_three_words_and_asks_about_the_main_element() {
            assert_eq!(size_of::<PropertyAddress>(), 12);
            assert_eq!(align_of::<PropertyAddress>(), 4);
            assert_eq!(offset_of!(PropertyAddress, selector), 0);
            assert_eq!(offset_of!(PropertyAddress, scope), 4);
            assert_eq!(offset_of!(PropertyAddress, element), 8);

            let address = PropertyAddress::new(PROPERTY_DEVICES, SCOPE_GLOBAL);
            assert_eq!(address.element, 0);
            assert_eq!(address.selector, code(*b"dev#"));
            assert_eq!(address.scope, code(*b"glob"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BufferList, ComponentDescription, StreamDescription, TimeStamp, code};
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn a_four_character_code_reads_left_to_right() {
        assert_eq!(code(*b"lpcm"), 0x6c70_636d);
        assert_eq!(code(*b"vpio"), 0x7670_696f);
        assert_eq!(code(*b"dIn "), 0x6449_6e20);
    }

    // Sizes and offsets are what a 64-bit Apple target compiles to. Nothing
    // else links these structures, so a 32-bit host is not worth asserting on.
    //
    // What these prove is narrower than it looks. For a `repr(C)` struct the
    // offsets follow from the field order in the source, so an assertion can
    // only catch a later edit that reorders or resizes a field. It cannot
    // catch the transcription from the header being wrong in the first place:
    // if a field were missing here, both the struct and the assertion would
    // agree with each other and disagree with Apple. Only reading the header,
    // or a stream that comes out as noise, catches that.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn the_stream_description_is_forty_bytes() {
        assert_eq!(size_of::<StreamDescription>(), 40);
        assert_eq!(align_of::<StreamDescription>(), 8);
        assert_eq!(offset_of!(StreamDescription, sample_rate), 0);
        assert_eq!(offset_of!(StreamDescription, format_id), 8);
        assert_eq!(offset_of!(StreamDescription, format_flags), 12);
        assert_eq!(offset_of!(StreamDescription, bytes_per_packet), 16);
        assert_eq!(offset_of!(StreamDescription, frames_per_packet), 20);
        assert_eq!(offset_of!(StreamDescription, bytes_per_frame), 24);
        assert_eq!(offset_of!(StreamDescription, channels_per_frame), 28);
        assert_eq!(offset_of!(StreamDescription, bits_per_channel), 32);
        assert_eq!(offset_of!(StreamDescription, reserved), 36);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn a_buffer_list_pads_its_count_out_to_the_pointer() {
        assert_eq!(size_of::<super::Buffer>(), 16);
        assert_eq!(offset_of!(super::Buffer, channels), 0);
        assert_eq!(offset_of!(super::Buffer, byte_size), 4);
        assert_eq!(offset_of!(super::Buffer, data), 8);
        assert_eq!(size_of::<BufferList>(), 24);
        assert_eq!(offset_of!(BufferList, count), 0);
        assert_eq!(offset_of!(BufferList, buffers), 8);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn the_time_stamp_is_sixty_four_bytes() {
        assert_eq!(size_of::<super::SmpteTime>(), 24);
        assert_eq!(size_of::<TimeStamp>(), 64);
        assert_eq!(align_of::<TimeStamp>(), 8);
        assert_eq!(offset_of!(TimeStamp, host_time), 8);
        assert_eq!(offset_of!(TimeStamp, rate_scalar), 16);
        assert_eq!(offset_of!(TimeStamp, word_clock_time), 24);
        assert_eq!(offset_of!(TimeStamp, smpte), 32);
        assert_eq!(offset_of!(TimeStamp, flags), 56);
        assert_eq!(offset_of!(TimeStamp, reserved), 60);
    }

    #[test]
    fn the_component_description_has_no_padding_at_all() {
        assert_eq!(size_of::<ComponentDescription>(), 20);
        assert_eq!(align_of::<ComponentDescription>(), 4);
        assert_eq!(offset_of!(ComponentDescription, component_type), 0);
        assert_eq!(offset_of!(ComponentDescription, flags_mask), 16);
    }

    #[test]
    fn the_description_of_narrowband_mono() {
        let description = StreamDescription::mono_pcm(8000);
        assert!((description.sample_rate - 8000.0).abs() < f64::EPSILON);
        assert_eq!(description.format_id, code(*b"lpcm"));
        // signed integer and packed, and nothing else: no float bit, no
        // big-endian bit, no non-interleaved bit
        assert_eq!(description.format_flags, 0b1100);
        assert_eq!(description.channels_per_frame, 1);
        assert_eq!(description.bits_per_channel, 16);
        assert_eq!(description.bytes_per_frame, 2);
        assert_eq!(description.bytes_per_packet, 2);
        assert_eq!(description.frames_per_packet, 1);
        assert_eq!(description.reserved, 0);
    }

    #[test]
    fn only_the_rate_changes_with_the_rate() {
        let narrowband = StreamDescription::mono_pcm(8000);
        let wideband = StreamDescription::mono_pcm(48000);
        assert!((wideband.sample_rate - 48000.0).abs() < f64::EPSILON);
        assert_eq!(
            StreamDescription {
                sample_rate: narrowband.sample_rate,
                ..wideband
            },
            narrowband
        );
    }
}
