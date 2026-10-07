// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// A call's media: the `sipral_call_media` handle, the socket's datagrams
// into it, and a frame clock that plays, captures and sends.

part of 'idiomatic.dart';

/// One reusable `sipral_media_packet_t` with its own buffers.
final class _MediaPacket {
  final ffi.Pointer<SipralMediaPacket> packet = calloc<SipralMediaPacket>();
  final ffi.Pointer<ffi.Uint8> _data = calloc<ffi.Uint8>(_packetBytes);
  final ffi.Pointer<ffi.Uint8> _to = calloc<ffi.Uint8>(_addressBytes);

  void prepare() {
    packet.ref
      ..size = ffi.sizeOf<SipralMediaPacket>()
      ..data = _data
      ..capacity = _packetBytes
      ..len = 0
      ..destination = _to.cast()
      ..destinationCapacity = _addressBytes
      ..destinationLen = 0;
  }

  Uint8List payload() => Uint8List.fromList(_data.asTypedList(packet.ref.len));

  String destination() => _decode(_to, packet.ref.destinationLen);

  void free() {
    calloc
      ..free(packet)
      ..free(_data)
      ..free(_to);
  }
}

/// What a call's media has done so far, from `sipral_media_statistics`.
final class SipralMediaStatistics {
  SipralMediaStatistics._(SipralStreamStats stats)
    : packetsSent = stats.packetsSent,
      packetsReceived = stats.packetsReceived,
      packetsLost = stats.packetsLost,
      jitterUs = stats.jitterUs,
      roundTripUs = stats.hasRoundTrip != 0 ? stats.roundTripUs : null,
      framesUnderrun = stats.framesUnderrun,
      lossRate = stats.lossRate,
      score = stats.score;

  /// RTP packets sent.
  final int packetsSent;

  /// RTP packets received.
  final int packetsReceived;

  /// RTP packets the far end sent that never arrived.
  final int packetsLost;

  /// Interarrival jitter, in microseconds.
  final int jitterUs;

  /// The round trip RTCP measured, in microseconds, or null before it has.
  final int? roundTripUs;

  /// Frames played as nothing, because nothing had arrived in time.
  final int framesUnderrun;

  /// The fraction of packets lost.
  final double lossRate;

  /// How the call sounds, as the library scores it.
  final double score;
}

/// A call's media, from `SipralEventKind.mediaStarted` on: [SipralCall.media].
///
/// Each frame tick plays the far end's audio into [frames] and sends one
/// frame of what [sendAudio] queued, or silence.
final class SipralMedia {
  SipralMedia._(this.call, this._socket) {
    final sipral = call.stack._sipral;
    using((arena) {
      final out = arena<SipralHandle>();
      _check(
        sipral,
        'sipral_call_media',
        sipral.callMedia(call.stack.handle, call.handle, out),
      );
      handle = out.value;
      final info = arena<SipralMediaInfo>();
      info.ref.size = ffi.sizeOf<SipralMediaInfo>();
      _check(sipral, 'sipral_media_info', sipral.mediaInfo(handle, info));
      _sampleRate = info.ref.sampleRate;
      _frameSamples = info.ref.frameSamples;
      frameMs = max(info.ref.frameMs, 1);
    });
    _playback = calloc<ffi.Int16>(frameSamples);
    _capture = calloc<ffi.Int16>(frameSamples);
    _reading = _socket.listen((event) {
      if (event == RawSocketEvent.read) {
        _receive();
      }
    });
    _due = call.stack.nowMs();
    _schedule();
  }

  /// The call it carries.
  final SipralCall call;

  /// The media handle.
  late final int handle;

  /// The rate of the PCM in [frames] and [sendAudio], in hertz: the
  /// codec's, or the one [setAppRate] chose.
  int get sampleRate => _sampleRate;
  late int _sampleRate;

  /// How many samples one frame is, at [sampleRate].
  int get frameSamples => _frameSamples;
  late int _frameSamples;

  /// How long one frame is, in milliseconds.
  late final int frameMs;

  final RawDatagramSocket _socket;
  late final StreamSubscription<RawSocketEvent> _reading;
  late ffi.Pointer<ffi.Int16> _playback;
  late ffi.Pointer<ffi.Int16> _capture;
  final ffi.Pointer<ffi.Uint8> _received = calloc<ffi.Uint8>(_packetBytes);
  final ffi.Pointer<ffi.Uint8> _from = calloc<ffi.Uint8>(_addressBytes);
  final ffi.Pointer<ffi.Uint32> _arrival = calloc<ffi.Uint32>();
  final ffi.Pointer<ffi.Size> _written = calloc<ffi.Size>();
  final ffi.Pointer<ffi.Uint32> _source = calloc<ffi.Uint32>();
  final _MediaPacket _packet = _MediaPacket();
  final StreamController<Int16List> _frames = StreamController.broadcast();
  final List<int> _toSend = [];
  Timer? _clock;
  int _due = 0;
  bool _running = true;

  /// The far end's audio, 16-bit mono PCM at [sampleRate], one frame at a
  /// time.
  Stream<Int16List> get frames => _frames.stream;

  /// Queue [pcm], 16-bit mono at [sampleRate], to go out a frame at a time.
  void sendAudio(Int16List pcm) {
    _toSend.addAll(pcm);
  }

  /// `sipral_media_set_app_rate`: the PCM rate of [frames] and [sendAudio],
  /// independent of the codec: 8000, 16000, 24000 or 48000, or 0 for the
  /// codec's own (the default). The library resamples; [sampleRate] and
  /// [frameSamples] follow the new rate. Audio queued and not yet sent is
  /// dropped. Any other rate throws [SipralException] with
  /// `SipralStatus.invalidArgument`, device mode with
  /// `SipralStatus.wrongState`.
  void setAppRate(int hz) {
    final sipral = call.stack._sipral;
    _check(
      sipral,
      'sipral_media_set_app_rate',
      sipral.mediaSetAppRate(handle, hz),
    );
    using((arena) {
      final info = arena<SipralMediaInfo>();
      info.ref.size = ffi.sizeOf<SipralMediaInfo>();
      _check(sipral, 'sipral_media_info', sipral.mediaInfo(handle, info));
      _sampleRate = info.ref.sampleRate;
      _frameSamples = info.ref.frameSamples;
    });
    calloc
      ..free(_playback)
      ..free(_capture);
    _playback = calloc<ffi.Int16>(frameSamples);
    _capture = calloc<ffi.Int16>(frameSamples);
    _toSend.clear();
  }

  /// The media statistics so far. After the call ends this returns
  /// [SipralCall.finalStatistics] once it has arrived.
  SipralMediaStatistics statistics() => using((arena) {
    final stats = arena<SipralStreamStats>();
    stats.ref.size = ffi.sizeOf<SipralStreamStats>();
    final status = call.stack._sipral.mediaStatistics(
      handle,
      call.stack.nowMs(),
      stats,
    );
    final kept = call.finalStatistics;
    if (status == SipralStatus.wrongState && kept != null) {
      return kept;
    }
    _check(call.stack._sipral, 'sipral_media_statistics', status);
    return SipralMediaStatistics._(stats.ref);
  });

  void _receive() {
    final sipral = call.stack._sipral;
    while (_running) {
      final datagram = _socket.receive();
      if (datagram == null) {
        return;
      }
      final length = min(datagram.data.length, _packetBytes);
      _received.asTypedList(length).setAll(0, datagram.data.take(length));
      final from = utf8.encode(_formatAddress(datagram.address, datagram.port));
      _from.asTypedList(from.length).setAll(0, from);
      sipral.mediaReceive(
        handle,
        _received,
        length,
        _from.cast(),
        from.length,
        call.stack.nowMs(),
        _arrival,
      );
    }
  }

  void _schedule() {
    _due += frameMs;
    var wait = _due - call.stack.nowMs();
    if (wait < 0) {
      // a whole frame behind: restart from now rather than burst to catch up
      _due = call.stack.nowMs();
      wait = 0;
    }
    _clock = Timer(Duration(milliseconds: wait), _tick);
  }

  void _tick() {
    if (!_running) {
      return;
    }
    try {
      _frame();
    } catch (error, trace) {
      _report(error, trace);
    }
    if (_running) {
      _schedule();
    }
  }

  void _frame() {
    final sipral = call.stack._sipral;
    final now = call.stack.nowMs();
    final played = sipral.mediaPlayback(
      handle,
      _playback,
      frameSamples,
      _written,
      _source,
    );
    if (played == SipralStatus.ok && _written.value > 0 && !_frames.isClosed) {
      _frames.add(Int16List.fromList(_playback.asTypedList(_written.value)));
    }
    final samples = _capture.asTypedList(frameSamples)
      ..fillRange(0, frameSamples, 0);
    final taken = min(_toSend.length, frameSamples);
    if (taken > 0) {
      samples.setAll(0, _toSend.take(taken));
      _toSend.removeRange(0, taken);
    }
    _packet.prepare();
    if (sipral.mediaCapture(
              handle,
              now,
              _capture,
              frameSamples,
              _packet.packet,
            ) ==
            SipralStatus.ok &&
        _packet.packet.ref.len > 0) {
      call._sendPacket(_packet);
    }
    _drain((packet) => sipral.mediaPollRtcp(handle, now, packet));
    _drain((packet) => sipral.mediaPollTransmit(handle, now, packet));
  }

  void _drain(int Function(ffi.Pointer<SipralMediaPacket>) poll) {
    while (_running) {
      _packet.prepare();
      if (poll(_packet.packet) != SipralStatus.ok ||
          _packet.packet.ref.len == 0) {
        return;
      }
      call._sendPacket(_packet);
    }
  }

  void _close() {
    if (!_running) {
      return;
    }
    _running = false;
    _clock?.cancel();
    _reading.cancel();
    call.stack._sipral.mediaRelease(handle);
    calloc
      ..free(_playback)
      ..free(_capture)
      ..free(_received)
      ..free(_from)
      ..free(_arrival)
      ..free(_written)
      ..free(_source);
    _packet.free();
    _frames.close();
  }
}
