// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// One `sipral_stack_create` handle, its signalling socket and its poll.

part of 'idiomatic.dart';

/// A SIP stack on one UDP socket: the class an application opens first.
///
/// [open] binds the socket and creates the stack; [close] hangs up what is
/// still up, destroys the stack exactly once and closes every socket this
/// layer opened. Everything happens on the isolate that opened it.
final class SipralStack {
  SipralStack._(this._sipral, this._socket)
      : bindAddress = _formatAddress(_socket.address, _socket.port);

  /// Bind a socket on [bindHost]:[bindPort] (0 for any port) and create a
  /// stack on it, in application mode: this layer carries each call's PCM.
  /// [userAgent] names the stack in `User-Agent` and `Server`. [library] is
  /// the library to use, [Sipral.open]'s by default.
  static Future<SipralStack> open({
    String bindHost = '127.0.0.1',
    int bindPort = 0,
    String? userAgent,
    Sipral? library,
  }) async {
    final sipral = library ?? _library();
    final socket = await RawDatagramSocket.bind(bindHost, bindPort);
    final stack = SipralStack._(sipral, socket);
    try {
      stack._create(userAgent);
    } catch (_) {
      stack._release();
      socket.close();
      rethrow;
    }
    stack._start();
    return stack;
  }

  final Sipral _sipral;
  final RawDatagramSocket _socket;

  /// Where the signalling socket is bound, `host:port`: what every `Via`
  /// this stack writes carries, and where another stack reaches it.
  final String bindAddress;

  /// The stack's handle.
  int get handle => _handle;
  int _handle = 0;

  final Stopwatch _clock = Stopwatch();
  late final ffi.NativeCallable<SipralEventCallback> _callback;
  final StreamController<SipralStackEvent> _events =
      StreamController.broadcast();
  final Map<int, SipralCall> _calls = {};
  final Map<int, SipralAccount> _accounts = {};
  StreamSubscription<RawSocketEvent>? _reading;
  Timer? _ticker;
  bool _closed = false;

  final ffi.Pointer<ffi.Uint8> _received = calloc<ffi.Uint8>(_packetBytes);
  final ffi.Pointer<ffi.Uint8> _from = calloc<ffi.Uint8>(_addressBytes);
  final ffi.Pointer<SipralPollResult> _result = calloc<SipralPollResult>();
  final ffi.Pointer<SipralTransmit> _transmit = calloc<SipralTransmit>();
  final ffi.Pointer<ffi.Uint8> _transmitData = calloc<ffi.Uint8>(_packetBytes);
  final ffi.Pointer<ffi.Uint8> _transmitTo = calloc<ffi.Uint8>(_addressBytes);
  final ffi.Pointer<SipralHandle> _farewellCall = calloc<SipralHandle>();
  final _MediaPacket _farewell = _MediaPacket();

  /// Every event this stack raises, in order, as it raises them. A call's
  /// own are also on [SipralCall.events].
  Stream<SipralStackEvent> get events => _events.stream;

  /// Milliseconds since the stack was created: what every `now_ms` the
  /// library takes is measured in.
  int nowMs() => _clock.elapsedMilliseconds;

  void _create(String? userAgent) {
    _callback = ffi.NativeCallable<SipralEventCallback>.isolateLocal(_onEvent);
    using((arena) {
      final random = Random.secure();
      ffi.Pointer<ffi.Uint8> seed() {
        final bytes = arena<ffi.Uint8>(32);
        for (var index = 0; index < 32; index++) {
          bytes[index] = random.nextInt(256);
        }
        return bytes;
      }

      final config = arena<SipralStackConfig>();
      final bind = _text(arena, bindAddress);
      final agent = _text(arena, userAgent);
      config.ref
        ..size = ffi.sizeOf<SipralStackConfig>()
        ..eventCallback = _callback.nativeFunction
        ..transport = SipralTransport.udp
        ..bindAddress = bind.$1
        ..bindAddressLen = bind.$2
        ..userAgent = agent.$1
        ..userAgentLen = agent.$2
        ..entropy = seed()
        ..entropyLen = 32
        ..mediaSeed = seed()
        ..mediaSeedLen = 32
        // the wall clock the RTCP sender reports carry (RFC 3550 §6.4.1)
        ..mediaClockUnixSeconds = DateTime.now().millisecondsSinceEpoch ~/ 1000
        ..audio = SipralAudio.application;
      final out = arena<SipralHandle>();
      _clock.start();
      _check(_sipral, 'sipral_stack_create', _sipral.stackCreate(config, out));
      _handle = out.value;
    });
  }

  void _start() {
    _reading = _socket.listen((event) {
      if (event == RawSocketEvent.read) {
        _readSignalling();
      }
    });
    _ticker = Timer.periodic(const Duration(milliseconds: 10), (_) => _poll());
  }

  /// Add an account whose requests go to [registrarAddress], `host:port`.
  /// With [registrar] it can register there ([SipralAccount.register]), as
  /// [authUser] with [authPassword] when challenged; without one it never
  /// registers, and [registrarAddress] is only its outbound proxy.
  /// [contact] is where the account is reached; by default the user part of
  /// [aor] at this stack's [bindAddress].
  SipralAccount addAccount(
    String aor, {
    required String registrarAddress,
    String? registrar,
    String? contact,
    String? authUser,
    String? authPassword,
    String? displayName,
  }) {
    _ensureOpen();
    final handle = using((arena) {
      final config = arena<SipralAccountConfig>();
      final aorText = _text(arena, aor);
      final proxy = _text(arena, registrarAddress);
      final registrarText = _text(arena, registrar);
      final contactText = _text(arena, contact ?? _defaultContact(aor));
      final user = _text(arena, authUser);
      final password = _text(arena, authPassword);
      final display = _text(arena, displayName);
      config.ref
        ..size = ffi.sizeOf<SipralAccountConfig>()
        ..aor = aorText.$1
        ..aorLen = aorText.$2
        ..registrarAddress = proxy.$1
        ..registrarAddressLen = proxy.$2
        ..registrar = registrarText.$1
        ..registrarLen = registrarText.$2
        ..contact = contactText.$1
        ..contactLen = contactText.$2
        ..authUser = user.$1
        ..authUserLen = user.$2
        ..authPassword = password.$1
        ..authPasswordLen = password.$2
        ..displayName = display.$1
        ..displayNameLen = display.$2;
      final out = arena<SipralHandle>();
      _check(_sipral, 'sipral_account_add',
          _sipral.accountAdd(_handle, config, out));
      return out.value;
    });
    final account = SipralAccount._(this, handle, aor);
    _accounts[handle] = account;
    return account;
  }

  /// `scheme:user@host:port` for [aor] at [bindAddress], or
  /// `scheme:host:port` for an address of record with no user part.
  String _defaultContact(String aor) {
    final colon = aor.indexOf(':');
    final scheme = colon < 0 ? 'sip' : aor.substring(0, colon);
    final rest = colon < 0 ? aor : aor.substring(colon + 1);
    final at = rest.indexOf('@');
    return at < 0
        ? '$scheme:$bindAddress'
        : '$scheme:${rest.substring(0, at)}@$bindAddress';
  }

  /// Place a call from [account] to [target], its media socket bound on
  /// [mediaHost]: the socket is open, and its address offered, before the
  /// INVITE goes out. [destination] sends the INVITE somewhere other than
  /// the account's registrar address.
  Future<SipralCall> placeCall(
    SipralAccount account,
    String target, {
    String mediaHost = '127.0.0.1',
    String? destination,
  }) async {
    _ensureOpen();
    final media = await RawDatagramSocket.bind(mediaHost, 0);
    final mediaAddress = _formatAddress(media.address, media.port);
    final int handle;
    try {
      handle = using((arena) {
        final config = arena<SipralCallConfig>();
        final targetText = _text(arena, target);
        final mediaText = _text(arena, mediaAddress);
        final destinationText = _text(arena, destination);
        config.ref
          ..size = ffi.sizeOf<SipralCallConfig>()
          ..target = targetText.$1
          ..targetLen = targetText.$2
          ..mediaAddress = mediaText.$1
          ..mediaAddressLen = mediaText.$2
          ..destination = destinationText.$1
          ..destinationLen = destinationText.$2;
        final out = arena<SipralHandle>();
        _check(
          _sipral,
          'sipral_call_place',
          _sipral.callPlace(_handle, account.handle, config, out, nowMs()),
        );
        return out.value;
      });
    } catch (_) {
      media.close();
      rethrow;
    }
    final call =
        SipralCall._(this, handle, media, mediaAddress, incoming: false);
    _calls[handle] = call;
    _poll();
    return call;
  }

  /// Answer the `SipralEventKind.incomingCall` [incoming], with a media
  /// socket bound on [mediaHost].
  Future<SipralCall> answerCall(
    SipralStackEvent incoming, {
    String mediaHost = '127.0.0.1',
  }) async {
    _ensureOpen();
    if (incoming.kind != SipralEventKind.incomingCall) {
      throw ArgumentError.value(
          incoming, 'incoming', 'is not an incoming call');
    }
    final media = await RawDatagramSocket.bind(mediaHost, 0);
    final mediaAddress = _formatAddress(media.address, media.port);
    final call =
        SipralCall._(this, incoming.call, media, mediaAddress, incoming: true);
    _calls[incoming.call] = call;
    try {
      using((arena) {
        final text = _text(arena, mediaAddress);
        _check(
          _sipral,
          'sipral_call_answer_media',
          _sipral.callAnswerMedia(
              _handle, incoming.call, text.$1, text.$2, nowMs()),
        );
      });
    } catch (_) {
      _calls.remove(incoming.call);
      media.close();
      rethrow;
    }
    _poll();
    return call;
  }

  /// Refuse the `SipralEventKind.incomingCall` [incoming] with [code].
  void rejectCall(SipralStackEvent incoming, {int code = 486}) {
    _ensureOpen();
    _check(
      _sipral,
      'sipral_call_reject',
      _sipral.callReject(_handle, incoming.call, code, nowMs()),
    );
    _poll();
  }

  /// Hang up every call still up, give the goodbyes a moment to go out,
  /// then destroy the stack and close every socket. Calling it again does
  /// nothing.
  Future<void> close() async {
    if (_closed) {
      return;
    }
    final open = _calls.values.toList();
    var hungUp = false;
    for (final call in open) {
      if (!call.ended) {
        try {
          call.hangup();
          hungUp = true;
        } on SipralException {
          // already on its way down
        }
      }
    }
    if (hungUp) {
      await Future<void>.delayed(const Duration(milliseconds: 200));
    }
    for (final call in open) {
      call.close();
    }
    _closed = true;
    _ticker?.cancel();
    await _reading?.cancel();
    _sipral.stackDestroy(_handle);
    _socket.close();
    _callback.close();
    _release();
    await _events.close();
  }

  void _release() {
    calloc
      ..free(_received)
      ..free(_from)
      ..free(_result)
      ..free(_transmit)
      ..free(_transmitData)
      ..free(_transmitTo)
      ..free(_farewellCall);
    _farewell.free();
  }

  void _ensureOpen() {
    if (_closed) {
      throw StateError('sipral: the stack is closed');
    }
  }

  void _readSignalling() {
    while (!_closed) {
      final datagram = _socket.receive();
      if (datagram == null) {
        break;
      }
      final length = min(datagram.data.length, _packetBytes);
      _received.asTypedList(length).setAll(0, datagram.data.take(length));
      final from = utf8.encode(_formatAddress(datagram.address, datagram.port));
      _from.asTypedList(from.length).setAll(0, from);
      _sipral.stackReceiveDatagram(
        _handle,
        Sipral.transportMain,
        _received,
        length,
        _from.cast(),
        from.length,
        ffi.nullptr,
        0,
        nowMs(),
      );
    }
    _poll();
  }

  void _poll() {
    if (_closed) {
      return;
    }
    _result.ref.size = ffi.sizeOf<SipralPollResult>();
    if (_sipral.stackPoll(_handle, nowMs(), _result) != SipralStatus.ok) {
      return;
    }
    _drainTransmit();
    _drainFarewells();
  }

  void _drainTransmit() {
    while (!_closed) {
      _transmit.ref
        ..size = ffi.sizeOf<SipralTransmit>()
        ..data = _transmitData
        ..capacity = _packetBytes
        ..destination = _transmitTo.cast()
        ..destinationCapacity = _addressBytes
        ..source = ffi.nullptr
        ..sourceCapacity = 0;
      if (_sipral.stackPollTransmit(_handle, _transmit) != SipralStatus.ok ||
          _transmit.ref.len == 0) {
        return;
      }
      final to =
          _parseAddress(_decode(_transmitTo, _transmit.ref.destinationLen));
      if (to != null) {
        _socket.send(
            Uint8List.fromList(_transmitData.asTypedList(_transmit.ref.len)),
            to.$1,
            to.$2);
      }
    }
  }

  /// What a call that ended still owes its far end -- its RTCP BYE -- sent
  /// from the call's own socket while that is still open.
  void _drainFarewells() {
    while (!_closed) {
      _farewell.prepare();
      if (_sipral.stackPollFarewell(_handle, _farewellCall, _farewell.packet) !=
              SipralStatus.ok ||
          _farewell.packet.ref.len == 0) {
        return;
      }
      _calls[_farewellCall.value]?._sendPacket(_farewell);
    }
  }

  void _onEvent(ffi.Pointer<SipralEvent> raw, ffi.Pointer<ffi.Void> userData) {
    try {
      final event = SipralStackEvent._read(raw.ref);
      final call = _calls[event.call];
      if (call != null && event.kind == SipralEventKind.callEnded) {
        _drainFarewells();
      }
      call?._deliver(event);
      _accounts[event.account]?._deliver(event);
      if (!_events.isClosed) {
        _events.add(event);
      }
    } catch (error, trace) {
      _report(error, trace);
    }
  }

  void _forget(SipralCall call) {
    _calls.remove(call.handle);
  }
}
