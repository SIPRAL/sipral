// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Printed from the declarations in crates/sipral-ffi by tools/abi-gen. Do
// not edit: `cargo run -p sipral-abi-gen` writes it again, and
// `scripts/check.sh` fails when what is committed is not what came out.
//
// The raw dart:ffi surface over the C ABI: one class per struct and
// union, laid out as `bindings/c/include/sipral.h` lays it out, the
// enumerations as integer constants, the callbacks as function types,
// and every entry point in `Sipral`, looked up in the library
// `Sipral.open` opened and checked. Names are Dart's: `SipralEvent`
// for `sipral_event_t`, `bindAddressLen` for `bind_address_len`,
// `stackCreate` for `sipral_stack_create`; a reserved word has a `$`
// after it.
//
// Nothing here is idiomatic. The stack, the account, the call and the
// event stream in `bindings/dart/lib/src/` are written against this
// file by hand, and are what an application reaches for.

// ignore_for_file: constant_identifier_names, non_constant_identifier_names

import 'dart:ffi' as ffi;
import 'dart:io' show FileSystemEntity, Platform;

/// What names one thing the library holds.
typedef SipralHandle = ffi.Uint64;

/// What the library calls when something happens.
typedef SipralEventCallback = ffi.Void Function(ffi.Pointer<SipralEvent> event, ffi.Pointer<ffi.Void> userData);

/// The Dart function a `NativeCallable<SipralEventCallback>` is built from.
typedef SipralEventCallbackDart = void Function(ffi.Pointer<SipralEvent> event, ffi.Pointer<ffi.Void> userData);

/// Asked before the library goes on, and answered with whether to
/// continue. A listener that throws instead of answering is read as
/// zero, which every callback here that answers is defined to take
/// as "no".
typedef SipralScreenCallback = ffi.Uint32 Function(ffi.Pointer<SipralScreenEvent> event, ffi.Pointer<ffi.Void> userData);

/// The Dart function a `NativeCallable<SipralScreenCallback>` is built from.
typedef SipralScreenCallbackDart = int Function(ffi.Pointer<SipralScreenEvent> event, ffi.Pointer<ffi.Void> userData);

/// Run over one frame, and hand back what replaces it.
typedef SipralProcessCallback = ffi.Void Function(ffi.Pointer<SipralProcessorEvent> event, ffi.Pointer<ffi.Void> userData);

/// The Dart function a `NativeCallable<SipralProcessCallback>` is built from.
typedef SipralProcessCallbackDart = void Function(ffi.Pointer<SipralProcessorEvent> event, ffi.Pointer<ffi.Void> userData);

/// What a call across the boundary answered.
///
/// Numbers already spent on features this build does not have:
/// - 9: video
abstract final class SipralStatus {
  /// It worked.
  static const int ok = 0;

  /// Something handed in was not usable.
  static const int invalidArgument = 1;

  /// A panic was caught before it reached C.
  static const int panic = 2;

  /// A word three of the four languages will not take plain.
  static const int default$ = 3;
}

/// On or off, where C has no bool worth relying on.
abstract final class SipralToggle {
  static const int off = 0;

  static const int on = 1;
}

/// What a stack has done since it was made.
final class SipralCounters extends ffi.Struct {
  @ffi.Size()
  external int size;

  /// How many went out.
  @ffi.Uint64()
  external int requestsSent;

  /// The fraction lost, which crosses JNI as its own bits.
  @ffi.Float()
  external double loss;
}

/// One header field: a name and a value.
final class SipralHeader extends ffi.Struct {
  external ffi.Pointer<ffi.Char> name;

  @ffi.Size()
  external int nameLen;

  external ffi.Pointer<ffi.Char> value;

  @ffi.Size()
  external int valueLen;
}

/// What a stack is made with.
///
/// Holds buffers of the caller's and the library only reads it, so it
/// crosses behind a `const` pointer as a struct going in.
final class SipralStackConfig extends ffi.Struct {
  @ffi.Size()
  external int size;

  /// Called for every event, from inside the poll.
  external ffi.Pointer<ffi.NativeFunction<SipralEventCallback>> eventCallback;

  /// Handed back to the callback untouched.
  external ffi.Pointer<ffi.Void> eventUserData;

  /// Where to listen, as UTF-8.
  external ffi.Pointer<ffi.Char> bindAddress;

  @ffi.Size()
  external int bindAddressLen;

  @ffi.Uint32()
  external int echo;

  /// A SipralToggle, read as a number and checked where it is used.
  @ffi.Uint32()
  external int record;

  /// Header fields to send, `headers_len` of them.
  external ffi.Pointer<SipralHeader> headers;

  @ffi.Size()
  external int headersLen;
}

/// One datagram, in room the caller brought.
///
/// Holds writable buffers of the caller's, so it crosses behind a
/// mutable pointer as a struct going both ways.
final class SipralMediaPacket extends ffi.Struct {
  @ffi.Size()
  external int size;

  /// Where to write the datagram.
  external ffi.Pointer<ffi.Uint8> data;

  @ffi.Size()
  external int capacity;

  @ffi.Size()
  external int len;

  /// Where to write the address it goes to, as UTF-8.
  external ffi.Pointer<ffi.Char> destination;

  @ffi.Size()
  external int destinationCapacity;

  @ffi.Size()
  external int destinationLen;
}

/// What a registration event says.
final class SipralRegistrationEvent extends ffi.Struct {
  /// Where it got to.
  @ffi.Uint32()
  external int state;

  @ffi.Uint32()
  external int statusCode;
}

/// What a media event says.
///
/// Lifetime
///
/// Everything a pointer here names is the library's and lives until
/// the callback returns.
final class SipralMediaEvent extends ffi.Struct {
  @ffi.Uint32()
  external int codec;

  /// Why, as UTF-8, or null.
  external ffi.Pointer<ffi.Char> reason;

  @ffi.Size()
  external int reasonLen;

  /// What the stream has done, or null when there is none.
  external ffi.Pointer<SipralCounters> statistics;
}

/// The one arm SipralEvent.kind names, and no other.
final class SipralEventPayload extends ffi.Union {
  /// Read when the kind is a registration one.
  external SipralRegistrationEvent registration;

  /// Read when the kind is a media one.
  external SipralMediaEvent media;
}

/// One thing that happened, as the callback is handed it.
final class SipralEvent extends ffi.Struct {
  @ffi.Size()
  external int size;

  /// Which stack it came from.
  @ffi.Uint64()
  external int stack;

  /// Which of them, from SipralStatus.
  @ffi.Uint32()
  external int kind;

  /// The message behind it, or null. It is the library's, and
  /// it lives as long as SipralStatus.ok is being reported
  /// -- see sipral_stack_create for who owns what.
  external ffi.Pointer<ffi.Uint8> message;

  @ffi.Size()
  external int messageLen;

  /// The arm the kind names.
  external SipralEventPayload payload;
}

/// What a policy callback is asked before the library goes on.
final class SipralScreenEvent extends ffi.Struct {
  @ffi.Size()
  external int size;

  /// Who is calling, as UTF-8, or null.
  external ffi.Pointer<ffi.Char> from;

  @ffi.Size()
  external int fromLen;
}

/// What a processing callback is handed: a frame to read and one to fill.
final class SipralProcessorEvent extends ffi.Struct {
  @ffi.Size()
  external int size;

  /// The frame just captured, to read.
  external ffi.Pointer<ffi.Int16> near;

  @ffi.Size()
  external int nearLen;

  /// Where the processed frame is written.
  external ffi.Pointer<ffi.Int16> far;

  @ffi.Size()
  external int farLen;
}

/// Why the library could not be opened, or cannot serve this binding.
final class SipralLoadError extends Error {
  SipralLoadError(this.message);

  /// What went wrong, in a sentence.
  final String message;

  @override
  String toString() => 'sipral: $message';
}

/// The library, opened and checked, with every entry point it has.
///
/// [open] is the only way to get one: it opens the library and asks
/// `sipral_abi_check` whether it can serve the ABI this file was printed
/// from, and throws [SipralLoadError] naming both versions when it
/// cannot, rather than letting whichever call first reads a member
/// that is not there fail instead. Each entry point is looked up the
/// first time it is read.
final class Sipral {
  Sipral._(this.library);

  /// Open the library and check it. [path] names the library file,
  /// or the directory holding it; without one, `SIPRAL_LIBRARY` does,
  /// and without that it is looked for by name where the platform
  /// looks for libraries, or found in the process itself on iOS, where
  /// it is linked in.
  static Sipral open({String? path}) {
    final sipral = Sipral._(_openLibrary(path));
    final status = sipral.abiCheck(abiVersionMajor, abiVersionMinor);
    if (status != SipralStatus.ok) {
      throw SipralLoadError(
        'this build of the library does not implement ABI $abiVersionMajor.$abiVersionMinor, '
        'which this binding was generated against; regenerate the binding or '
        'rebuild the library',
      );
    }
    return sipral;
  }

  /// What the library is called on this platform.
  static String libraryName() {
    if (Platform.isMacOS || Platform.isIOS) return 'libsipral_ffi.dylib';
    if (Platform.isWindows) return 'sipral_ffi.dll';
    return 'libsipral_ffi.so';
  }

  static ffi.DynamicLibrary _openLibrary(String? path) {
    final named = path ?? Platform.environment['SIPRAL_LIBRARY'];
    try {
      if (named != null && named.isNotEmpty) {
        final file = FileSystemEntity.isDirectorySync(named)
            ? '$named${Platform.pathSeparator}${libraryName()}'
            : named;
        return ffi.DynamicLibrary.open(file);
      }
      if (Platform.isIOS) return ffi.DynamicLibrary.process();
      return ffi.DynamicLibrary.open(libraryName());
    } on ArgumentError catch (refused) {
      throw SipralLoadError(
        'could not open ${named ?? libraryName()} (${refused.message}); build it '
        'with `cargo build --release -p sipral-ffi`, or set SIPRAL_LIBRARY to '
        'its path or its directory',
      );
    }
  }

  /// The library every entry point below is looked up in.
  final ffi.DynamicLibrary library;


  /// The handle that names nothing.
  static const int handleNone = 0;

  /// The bit a hardware customer is told to check for.
  static const int featureOpus = 64;

  /// The longest message that crosses.
  static const int messageBytes = 65535;

  /// How long a refused request waits before it is tried again.
  static const int retryEveryMs = 2000;

  /// Nothing built against another major works against this one.
  static const int abiVersionMajor = 0;

  /// Raised by anything the header gains.
  static const int abiVersionMinor = 8;

  /// Every struct and union the header declares, with how long tools/abi-gen
  /// worked it out to be on each of the three layouts the ABI ships for:
  /// 64-bit pointers (p64), then 32-bit pointers with 64-bit integers aligned
  /// to four (p32a4, i386) and to eight (p32a8, ARM and Windows x86). A size
  /// test holds this binding's own layout of each record, and the library's
  /// answer from sipral_abi_struct_size, to the number for the layout it runs
  /// on; bindings/c/abi-layout.c holds a C compiler to all three.
  /// Each list is this binding's own length first, then p64, p32a4
  /// and p32a8.
  static Map<String, List<int>> recordLayouts() => {
        'sipral_counters_t': [ffi.sizeOf<SipralCounters>(), 24, 16, 24],
        'sipral_header_t': [ffi.sizeOf<SipralHeader>(), 32, 16, 16],
        'sipral_stack_config_t': [ffi.sizeOf<SipralStackConfig>(), 64, 36, 36],
        'sipral_media_packet_t': [ffi.sizeOf<SipralMediaPacket>(), 56, 28, 28],
        'sipral_registration_event_t': [ffi.sizeOf<SipralRegistrationEvent>(), 8, 8, 8],
        'sipral_media_event_t': [ffi.sizeOf<SipralMediaEvent>(), 32, 16, 16],
        'sipral_event_payload_t': [ffi.sizeOf<SipralEventPayload>(), 32, 16, 16],
        'sipral_event_t': [ffi.sizeOf<SipralEvent>(), 72, 40, 48],
        'sipral_screen_event_t': [ffi.sizeOf<SipralScreenEvent>(), 24, 12, 12],
        'sipral_processor_event_t': [ffi.sizeOf<SipralProcessorEvent>(), 40, 20, 20],
      };

  /// Whether this library can serve a binding generated against `major`.`minor`.
  late final int Function(int major, int minor) abiCheck = library.lookupFunction<
      ffi.Int32 Function(ffi.Uint32 major, ffi.Uint32 minor),
      int Function(int major, int minor)>('sipral_abi_check');

  /// The calling thread's last error.
  late final int Function(ffi.Pointer<ffi.Char> buffer, int capacity, ffi.Pointer<ffi.Size> outNeeded) lastErrorMessage = library.lookupFunction<
      ffi.Int32 Function(ffi.Pointer<ffi.Char> buffer, ffi.Size capacity, ffi.Pointer<ffi.Size> outNeeded),
      int Function(ffi.Pointer<ffi.Char> buffer, int capacity, ffi.Pointer<ffi.Size> outNeeded)>('sipral_last_error_message');

  /// The name of one SipralStatus, for a log line.
  late final ffi.Pointer<ffi.Char> Function(int code) statusName = library.lookupFunction<
      ffi.Pointer<ffi.Char> Function(ffi.Int32 code),
      ffi.Pointer<ffi.Char> Function(int code)>('sipral_status_name');

  /// Make one.
  late final int Function(ffi.Pointer<SipralStackConfig> config, ffi.Pointer<SipralHandle> outStack) stackCreate = library.lookupFunction<
      ffi.Int32 Function(ffi.Pointer<SipralStackConfig> config, ffi.Pointer<SipralHandle> outStack),
      int Function(ffi.Pointer<SipralStackConfig> config, ffi.Pointer<SipralHandle> outStack)>('sipral_stack_create');

  /// Read SipralCounters off it.
  late final int Function(int stack, ffi.Pointer<SipralCounters> outCounters) stackCounters = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Pointer<SipralCounters> outCounters),
      int Function(int stack, ffi.Pointer<SipralCounters> outCounters)>('sipral_stack_counters');

  /// Turn the echo on or off, and say what it was.
  late final int Function(int stack, int echo, ffi.Pointer<ffi.Uint32> outWas) stackSetEcho = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Uint32 echo, ffi.Pointer<ffi.Uint32> outWas),
      int Function(int stack, int echo, ffi.Pointer<ffi.Uint32> outWas)>('sipral_stack_set_echo');

  /// Every setting it has, one SipralToggle each.
  late final int Function(int stack, ffi.Pointer<ffi.Uint32> outToggles, int capacity, ffi.Pointer<ffi.Size> outCount) stackToggles = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Pointer<ffi.Uint32> outToggles, ffi.Size capacity, ffi.Pointer<ffi.Size> outCount),
      int Function(int stack, ffi.Pointer<ffi.Uint32> outToggles, int capacity, ffi.Pointer<ffi.Size> outCount)>('sipral_stack_toggles');

  /// Hand it bytes to send.
  late final int Function(int stack, ffi.Pointer<ffi.Uint8> message, int messageLen) stackSend = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Pointer<ffi.Uint8> message, ffi.Size messageLen),
      int Function(int stack, ffi.Pointer<ffi.Uint8> message, int messageLen)>('sipral_stack_send');

  /// Hand it header fields, an array of them with its length beside it.
  late final int Function(int stack, ffi.Pointer<SipralHeader> headers, int headersLen) stackLabel = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Pointer<SipralHeader> headers, ffi.Size headersLen),
      int Function(int stack, ffi.Pointer<SipralHeader> headers, int headersLen)>('sipral_stack_label');

  /// Hand it text, which crosses as UTF-8 and not as a String.
  late final int Function(int stack, ffi.Pointer<ffi.Char> note, int noteLen) stackDescribe = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Pointer<ffi.Char> note, ffi.Size noteLen),
      int Function(int stack, ffi.Pointer<ffi.Char> note, int noteLen)>('sipral_stack_describe');

  /// Fill a buffer the caller brings.
  late final int Function(int stack, ffi.Pointer<ffi.Char> name, int capacity, ffi.Pointer<ffi.Size> outLen) stackName = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Pointer<ffi.Char> name, ffi.Size capacity, ffi.Pointer<ffi.Size> outLen),
      int Function(int stack, ffi.Pointer<ffi.Char> name, int capacity, ffi.Pointer<ffi.Size> outLen)>('sipral_stack_name');

  /// Fill a buffer of numbers the caller brings.
  late final int Function(int stack, ffi.Pointer<ffi.Uint32> outCodecs, int capacity, ffi.Pointer<ffi.Size> outCount) stackCodecOrder = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Pointer<ffi.Uint32> outCodecs, ffi.Size capacity, ffi.Pointer<ffi.Size> outCount),
      int Function(int stack, ffi.Pointer<ffi.Uint32> outCodecs, int capacity, ffi.Pointer<ffi.Size> outCount)>('sipral_stack_codec_order');

  /// Fill a buffer of opaque bytes the caller brings.
  late final int Function(int stack, ffi.Pointer<ffi.Uint8> buffer, int capacity, ffi.Pointer<ffi.Size> outLen) stackFreeze = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Pointer<ffi.Uint8> buffer, ffi.Size capacity, ffi.Pointer<ffi.Size> outLen),
      int Function(int stack, ffi.Pointer<ffi.Uint8> buffer, int capacity, ffi.Pointer<ffi.Size> outLen)>('sipral_stack_freeze');

  /// Fill a buffer of samples the caller brings.
  late final int Function(int stack, ffi.Pointer<ffi.Int16> samples, int capacity, ffi.Pointer<ffi.Size> outWritten) callPlayback = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Pointer<ffi.Int16> samples, ffi.Size capacity, ffi.Pointer<ffi.Size> outWritten),
      int Function(int stack, ffi.Pointer<ffi.Int16> samples, int capacity, ffi.Pointer<ffi.Size> outWritten)>('sipral_call_playback');

  /// Hand it samples, and get one datagram back in the struct.
  late final int Function(int stack, ffi.Pointer<ffi.Int16> samples, int sampleCount, ffi.Pointer<SipralMediaPacket> packet) callCapture = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Pointer<ffi.Int16> samples, ffi.Size sampleCount, ffi.Pointer<SipralMediaPacket> packet),
      int Function(int stack, ffi.Pointer<ffi.Int16> samples, int sampleCount, ffi.Pointer<SipralMediaPacket> packet)>('sipral_call_capture');

  /// Hand it one buffer of samples and fill another, in the same call,
  /// neither one named `capacity` — two buffers going in, one of them
  /// writable, which is not the same shape as one being filled.
  late final int Function(int stack, ffi.Pointer<ffi.Int16> mic, int micCount, ffi.Pointer<ffi.Int16> local, int localCount) callMix = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Pointer<ffi.Int16> mic, ffi.Size micCount, ffi.Pointer<ffi.Int16> local, ffi.Size localCount),
      int Function(int stack, ffi.Pointer<ffi.Int16> mic, int micCount, ffi.Pointer<ffi.Int16> local, int localCount)>('sipral_call_mix');

  /// Hand it a datagram that arrived, in a buffer it may rewrite in
  /// place, and hear what became of it.
  late final int Function(int stack, ffi.Pointer<ffi.Uint8> data, int len, ffi.Pointer<ffi.Uint32> outArrival) callMediaReceive = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Pointer<ffi.Uint8> data, ffi.Size len, ffi.Pointer<ffi.Uint32> outArrival),
      int Function(int stack, ffi.Pointer<ffi.Uint8> data, int len, ffi.Pointer<ffi.Uint32> outArrival)>('sipral_call_media_receive');

  /// Install a policy on it, replace the one installed, or remove it.
  ///
  /// The callback and the pointer after it are one listener, the same
  /// pair a struct going in already means by them, and a null callback
  /// removes whatever was installed.
  late final int Function(int stack, ffi.Pointer<ffi.NativeFunction<SipralScreenCallback>> callback, ffi.Pointer<ffi.Void> userData) stackScreen = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Pointer<ffi.NativeFunction<SipralScreenCallback>> callback, ffi.Pointer<ffi.Void> userData),
      int Function(int stack, ffi.Pointer<ffi.NativeFunction<SipralScreenCallback>> callback, ffi.Pointer<ffi.Void> userData)>('sipral_stack_screen');

  /// Install a processor on it, replace the one installed, or remove it.
  ///
  /// The callback and the pointer after it are one listener, the same
  /// pair a struct going in already means by them, and a null callback
  /// removes whatever was installed.
  late final int Function(int stack, ffi.Pointer<ffi.NativeFunction<SipralProcessCallback>> callback, ffi.Pointer<ffi.Void> userData) stackProcess = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack, ffi.Pointer<ffi.NativeFunction<SipralProcessCallback>> callback, ffi.Pointer<ffi.Void> userData),
      int Function(int stack, ffi.Pointer<ffi.NativeFunction<SipralProcessCallback>> callback, ffi.Pointer<ffi.Void> userData)>('sipral_stack_process');

  /// Take it apart.
  late final int Function(int stack) stackDestroy = library.lookupFunction<
      ffi.Int32 Function(SipralHandle stack),
      int Function(int stack)>('sipral_stack_destroy');
}
