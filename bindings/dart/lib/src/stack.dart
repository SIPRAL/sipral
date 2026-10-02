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
  SipralStack._(
    this._sipral,
    this._socket,
    this._bindAddress,
    this._resolver,
    this._routes,
    this._tlsServerName,
  );

  /// Bind a socket on [bindHost]:[bindPort] (0 for any port) and create a
  /// stack on it, in application mode: this layer carries each call's PCM.
  /// [userAgent] names the stack in `User-Agent` and `Server`. [library] is
  /// the library to use, [Sipral.open]'s by default.
  ///
  /// [bindHost] left out listens on every interface, and the stack
  /// advertises the address of the operating system's route toward the
  /// server of its first account (`sipral_advertised_address`): the address
  /// a PBX on the network reaches this machine at, and `127.0.0.1` for one on
  /// this machine. Each account is reached at the route toward its own
  /// server, and a call's media socket, when `mediaHost` is left out, at the
  /// route toward the far end or the account's server. A loopback address is
  /// never advertised to a peer elsewhere: the library refuses that with
  /// `SipralStatus.unreachableAddress`.
  ///
  /// [srtp] is a `SipralSrtp` value -- `SipralSrtp.bestEffort` offers SDES on
  /// plain `RTP/AVP`, the call encrypted when the answer takes a key and
  /// plain when it takes none -- and [srtpSuites] the SRTP suites every call
  /// offers and accepts, most preferred first, by their RFC 4568 and RFC 7714
  /// names. [pathMtu] is the MTU of the path toward the server when the
  /// deployment knows it (0 for unknown, else 576 or more).
  /// [datagramWithoutStreamBytes] is a deliberate deviation from RFC 3261
  /// §18.1.1 for a server that takes SIP over UDP alone: this layer opens no
  /// stream, and a request up to this many bytes goes over UDP anyway (0 for
  /// never, at most 65 507), [diagnosticsJson] saying so as
  /// `transport.kept.datagram`. [pseudonymSalt] (16 bytes or more, kept by
  /// the installation) keys the pseudonyms the log writes, so that two runs
  /// compare line by line; it is a secret, like a key. [diagnosticTrace]
  /// writes whole SIP messages at the trace level, credentials and keys
  /// taken out; [setDiagnosticTrace] turns it on and off later. [resolver]
  /// answers `SipralEventKind.lookupWanted` for the accounts added with a
  /// `serverUri`; [SipralDns.platform] by default. [tlsServerName] is the
  /// name a TLS connection of an account's own is checked against (the
  /// server's host by default), for an account added with
  /// `streamProtocol: SipralTransport.tls` and no `tlsPin`. [heldAudio] is a
  /// `SipralHeldAudio` value: what a party this end holds is sent while the
  /// hold lasts -- silence by default, since the frames sent may be a
  /// microphone's; `SipralHeldAudio.application` sends the frames the
  /// application sends (hold music, an announcement, a voice agent's own
  /// speech).
  ///
  /// [maxDialogs] is the most calls the stack holds at once, either way (0
  /// for 128): past it an incoming call is answered 503 with `Retry-After:
  /// 2` before it rings, and [placeCall] throws a [SipralException] with
  /// `SipralStatus.limitReached`. [maxServerTransactions] is the most
  /// requests from other ends it works on at once (0 for 256); a server
  /// raising [maxDialogs] raises it beside, to three a call and 256 more,
  /// since an answered INVITE and a BYE each hold one for 32 seconds over
  /// UDP (`docs/08-ffi.md`, "Limits, and what went out twice").
  static Future<SipralStack> open({
    String? bindHost,
    int bindPort = 0,
    String? userAgent,
    Sipral? library,
    int srtp = 0,
    List<String> srtpSuites = const [],
    int pathMtu = 0,
    int datagramWithoutStreamBytes = 0,
    List<int>? pseudonymSalt,
    bool? diagnosticTrace,
    SipralResolver? resolver,
    String? tlsServerName,
    int heldAudio = SipralHeldAudio.default$,
    int maxDialogs = 0,
    int maxServerTransactions = 0,
  }) async {
    for (final (name, value) in [
      ('maxDialogs', maxDialogs),
      ('maxServerTransactions', maxServerTransactions),
    ]) {
      if (value < 0 || value > 0xFFFFFFFF) {
        throw ArgumentError.value(value, name, 'is 0 to 4294967295');
      }
    }
    final sipral = library ?? _library();
    final socket = await RawDatagramSocket.bind(
      bindHost ?? InternetAddress.anyIPv4,
      bindPort,
    );
    final bound =
        bindHost == null
            ? '127.0.0.1:${socket.port}'
            : _formatAddress(socket.address, socket.port);
    final stack = SipralStack._(
      sipral,
      socket,
      bound,
      resolver ?? SipralDns.platform,
      bindHost == null,
      tlsServerName,
    );
    try {
      stack._create(
        userAgent,
        srtp: srtp,
        srtpSuites: srtpSuites,
        pathMtu: pathMtu,
        datagramWithoutStreamBytes: datagramWithoutStreamBytes,
        pseudonymSalt: pseudonymSalt,
        diagnosticTrace: diagnosticTrace,
        heldAudio: heldAudio,
        maxDialogs: maxDialogs,
        maxServerTransactions: maxServerTransactions,
      );
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

  /// Where the signalling socket is reached, `host:port`: what every `Via`
  /// this stack writes carries, and where another stack reaches it. A stack
  /// opened with no `bindHost` listens on every interface, and this is the
  /// route toward its first account's server.
  String get bindAddress => _bindAddress;
  String _bindAddress;

  /// Whether this stack picks the address peers reach it at -- it was opened
  /// with no `bindHost` -- and whether it has picked it yet.
  final bool _routes;
  bool _routeChosen = false;

  /// Answers `SipralEventKind.lookupWanted`.
  final SipralResolver _resolver;

  /// The name a TLS connection of an account's own is checked against;
  /// null for the server's host.
  final String? _tlsServerName;

  /// The connections opened for accounts on a connection of their own, by
  /// the transport number each is bound at, the server each goes to, and
  /// the servers one is being opened to.
  final Map<int, Socket> _streams = {};
  final Map<int, String> _streamDestinations = {};
  final Set<String> _streamsOpening = {};
  int _nextStream = _firstStream;

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

  /// Called with each event as the library hands it over, before its copy
  /// reaches [events]: the whole `sipral_event_t`, so every payload arm the
  /// ABI declares is readable through `package:sipral/sipral_abi.dart`'s
  /// [SipralEvent] (`event.payload.subscription`, `event.payload.message`,
  /// and the rest), not only what [SipralStackEvent] copies out. It runs on
  /// this isolate, inside the poll, and the struct and every pointer in it
  /// are the library's only until it returns: copy out what is kept, and
  /// call nothing on this stack from inside it.
  void Function(SipralEvent event)? onRawEvent;

  /// Milliseconds since the stack was created: what every `now_ms` the
  /// library takes is measured in.
  int nowMs() => _clock.elapsedMilliseconds;

  void _create(
    String? userAgent, {
    required int srtp,
    required List<String> srtpSuites,
    required int pathMtu,
    required int datagramWithoutStreamBytes,
    required List<int>? pseudonymSalt,
    required bool? diagnosticTrace,
    required int heldAudio,
    required int maxDialogs,
    required int maxServerTransactions,
  }) {
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
      final suites = _text(
        arena,
        srtpSuites.isEmpty ? null : srtpSuites.join(','),
      );
      final salt = pseudonymSalt ?? const <int>[];
      final saltBytes = arena<ffi.Uint8>(max(1, salt.length));
      saltBytes.asTypedList(salt.length).setAll(0, salt);
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
        ..audio = SipralAudio.application
        ..srtp = srtp
        ..srtpSuites = suites.$1
        ..srtpSuitesLen = suites.$2
        ..pathMtu = pathMtu
        ..datagramWithoutStreamBytes = datagramWithoutStreamBytes
        ..pseudonymSalt = salt.isEmpty ? ffi.nullptr : saltBytes
        ..pseudonymSaltLen = salt.length
        ..diagnosticTrace = _toggle(diagnosticTrace)
        ..heldAudio = heldAudio
        ..maxDialogs = maxDialogs
        ..maxServerTransactions = maxServerTransactions;
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
  /// [aor] at the route toward its server, or at this stack's [bindAddress].
  ///
  /// [serverUri] names the server by a URI whose host RFC 3263 locates --
  /// `sip:pbx.example.com`, `sips:example.com:5061` -- in place of
  /// [registrarAddress]: exactly one of the two is given. The lookups are
  /// the stack's resolver's; `SipralEventKind.located` says where the server
  /// was found and `SipralEventKind.locateFailed` why not. [serverNaptr] asks
  /// the domain for NAPTR records before SRV (RFC 3263 §4.1). [keepaliveMs]
  /// keeps the account's flow to its server open at that interval -- a
  /// double CRLF -- 1 000 to 120 000, 0 for never. [tlsPin] is the SHA-256
  /// fingerprint of the one TLS certificate the account trusts, in any form
  /// [sipralPinDigest] reads and an [ArgumentError] for any other, for an
  /// application that runs the account's TLS itself:
  /// [SipralAccount.checkCertificate] is its verdict.
  ///
  /// [streamProtocol] (`SipralTransport.tcp` or `SipralTransport.tls`) puts
  /// the account on a connection of its own to its server, beside accounts
  /// on this stack's UDP socket to other servers: the stack asks for it
  /// (`SipralEventKind.transportWanted`, nothing outgrown), this layer opens
  /// it to the account's server and binds it, and the REGISTER and every
  /// call of the account go over it. A TLS one with a [tlsPin] trusts the
  /// pinned certificate alone, by the library's own verdict
  /// ([SipralAccount.checkCertificate]); without one, the platform's
  /// authorities under the stack's `tlsServerName` or the server's host. One
  /// that closes is opened again. Until it is open a call the account
  /// places throws with `SipralStatus.transportDown`. Anything else is an
  /// [ArgumentError].
  ///
  /// [realms] are the realms the password answers (RFC 3261 §22.1). Left
  /// empty, the account answers the realm its server first challenges it
  /// with and every realm its REGISTERs are challenged with, and no other;
  /// an SBC or outbound proxy at the server's address that challenges calls
  /// under a realm of its own needs both named. A challenge the password is
  /// not for is not answered, and `SipralEventKind.challengeDeclined` says
  /// who asked and why ([SipralStackEvent.challengeRefusal],
  /// [SipralStackEvent.challengeServer], [SipralStackEvent.challengeRealms]).
  SipralAccount addAccount(
    String aor, {
    String? registrarAddress,
    String? registrar,
    String? contact,
    String? authUser,
    String? authPassword,
    String? displayName,
    String? serverUri,
    bool serverNaptr = false,
    int keepaliveMs = 0,
    String? tlsPin,
    int? streamProtocol,
    List<String> realms = const [],
  }) {
    _ensureOpen();
    if ((registrarAddress == null) == (serverUri == null)) {
      throw ArgumentError(
        'an account names its server by registrarAddress or by serverUri, '
        'one of the two',
      );
    }
    if (streamProtocol != null &&
        streamProtocol != SipralTransport.tcp &&
        streamProtocol != SipralTransport.tls) {
      throw ArgumentError.value(
        streamProtocol,
        'streamProtocol',
        'is SipralTransport.tcp or SipralTransport.tls',
      );
    }
    final advertised =
        contact == null && registrarAddress != null && _routes
            ? _advertiseToward(registrarAddress)
            : null;
    final handle = using((arena) {
      final config = arena<SipralAccountConfig>();
      final aorText = _text(arena, aor);
      final proxy = _text(arena, registrarAddress);
      final registrarText = _text(arena, registrar);
      final contactText = _text(
        arena,
        contact ??
            _defaultContact(
              aor,
              advertised ?? bindAddress,
              _contactParameters(streamProtocol),
            ),
      );
      final serverText = _text(arena, serverUri);
      // read here, in every form [sipralPinDigest] takes, and handed over
      // as the bare digits every library takes
      final pinText = _text(
        arena,
        tlsPin == null
            ? null
            : sipralPinDigest(
              tlsPin,
            ).map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(),
      );
      final user = _text(arena, authUser);
      final password = _text(arena, authPassword);
      final display = _text(arena, displayName);
      final realmsText = _text(
        arena,
        realms.isEmpty ? null : realms.join('\n'),
      );
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
        ..displayNameLen = display.$2
        ..serverUri = serverText.$1
        ..serverUriLen = serverText.$2
        ..serverNaptr = serverNaptr ? SipralToggle.on : 0
        ..keepaliveMs = keepaliveMs
        ..tlsPinSha256 = pinText.$1
        ..tlsPinSha256Len = pinText.$2
        ..streamProtocol = streamProtocol ?? 0
        ..realms = realmsText.$1
        ..realmsLen = realmsText.$2;
      final out = arena<SipralHandle>();
      _check(
        _sipral,
        'sipral_account_add',
        _sipral.accountAdd(_handle, config, out),
      );
      return out.value;
    });
    final account = SipralAccount._(
      this,
      handle,
      aor,
      registrarAddress ?? '',
      serverUri,
      contact == null,
      advertised,
      streamProtocol,
      tlsPin,
    );
    _accounts[handle] = account;
    return account;
  }

  /// The `host:port` an account whose server is [peer] is reached at, on a
  /// stack that picks its own address: the route toward the server, on this
  /// stack's port. The first server named also becomes the address the
  /// stack's `Via` carries.
  String _advertiseToward(String peer) {
    final port = bindAddress.substring(bindAddress.lastIndexOf(':') + 1);
    final address = '${routeHost(peer, library: _sipral)}:$port';
    if (!_routeChosen) {
      _routeChosen = true;
      if (address != bindAddress) {
        using((arena) {
          final local = _text(arena, address);
          _checkNow(
            _sipral,
            'sipral_stack_transport_bind',
            () => _sipral.stackTransportBind(
              _handle,
              Sipral.transportMain,
              SipralTransport.udp,
              local.$1,
              local.$2,
              ffi.nullptr,
              0,
              nowMs(),
              ffi.nullptr,
            ),
          );
        });
        _bindAddress = address;
      }
    }
    return address;
  }

  /// Where a call's media socket is bound: [mediaHost] when one was given,
  /// else the route toward where the media will come from --
  /// [destination], the account's server, or the address this stack is
  /// reached at.
  String _mediaHost(
    String? mediaHost,
    SipralAccount? account,
    String? destination,
  ) {
    if (mediaHost != null) {
      return mediaHost;
    }
    for (final peer in [destination, account?.registrarAddress]) {
      if (peer != null && _parseAddress(peer) != null) {
        return routeHost(peer, library: _sipral);
      }
    }
    return bindAddress.substring(0, bindAddress.lastIndexOf(':'));
  }

  /// Ask the resolver what `SipralEventKind.lookupWanted` asked, after the
  /// poll that raised it, and hand the answer back
  /// (`sipral_account_looked_up`); a resolver that threw is an answer that
  /// failed, since the procedure waits for every one.
  Future<void> _lookUp(int account, String name, int record) async {
    SipralLookup answer;
    try {
      answer = await _resolver(name, record);
    } catch (_) {
      answer = SipralLookup.failed;
    }
    if (_closed) {
      return;
    }
    using((arena) {
      final nameText = _text(arena, name);
      final records = _text(
        arena,
        answer.records.isEmpty ? null : answer.records.join(','),
      );
      // an account removed while the resolver ran is let go of quietly
      retryingClockBehind(
        () => _sipral.accountLookedUp(
          _handle,
          account,
          nameText.$1,
          nameText.$2,
          record,
          answer.answer,
          records.$1,
          records.$2,
          nowMs(),
        ),
      );
    });
    _poll();
  }

  /// An account located at [target]: pointed at it, and -- on a stack that
  /// picks its own address -- reached at the route toward it.
  void _located(int handle, String target) {
    final account = _accounts[handle];
    if (account == null || _closed) {
      return;
    }
    account.registrarAddress = target;
    if (!_routes || !account._derivesContact) {
      return;
    }
    final advertised = _advertiseToward(target);
    if (advertised == (account._advertised ?? bindAddress)) {
      return;
    }
    using((arena) {
      final remote = _text(arena, target);
      final contact = _text(
        arena,
        _defaultContact(
          account.aor,
          advertised,
          _contactParameters(account.streamProtocol),
        ),
      );
      _checkNow(
        _sipral,
        'sipral_account_rebind',
        () => _sipral.accountRebind(
          _handle,
          handle,
          Sipral.transportMain,
          remote.$1,
          remote.$2,
          contact.$1,
          contact.$2,
          nowMs(),
        ),
      );
    });
    account._advertised = advertised;
    _poll();
  }

  /// Turn the diagnostic trace on or off while the stack runs
  /// (`sipral_stack_diagnostic_trace`): whether the trace level writes every
  /// SIP message whole, with its peer, from now on -- credentials and keys
  /// taken out either way -- or pseudonymised, as by default.
  void setDiagnosticTrace(bool on) {
    _ensureOpen();
    _check(
      _sipral,
      'sipral_stack_diagnostic_trace',
      _sipral.stackDiagnosticTrace(_handle, _toggle(on)),
    );
  }

  /// What the stack runs with, every default filled in
  /// (`sipral_stack_settings`), with the SRTP suites its calls offer in
  /// order (`sipral_stack_srtp_suite_order`).
  SipralSettings settings() {
    _ensureOpen();
    return using((arena) {
      final raw = arena<SipralStackSettings>();
      raw.ref.size = ffi.sizeOf<SipralStackSettings>();
      _check(
        _sipral,
        'sipral_stack_settings',
        _sipral.stackSettings(_handle, raw),
      );
      final count = raw.ref.srtpSuiteCount;
      final suites = arena<ffi.Uint32>(max(1, count));
      final written = arena<ffi.Size>();
      _check(
        _sipral,
        'sipral_stack_srtp_suite_order',
        _sipral.stackSrtpSuiteOrder(_handle, suites, count, written),
      );
      return SipralSettings._(raw.ref, List.of(suites.asTypedList(count)));
    });
  }

  /// The diagnostic record of every call the stack keeps, as JSON
  /// (`sipral_stack_diagnostics_json`): each decision the stack made and why
  /// -- `transport.kept.datagram` among them for a request that went over
  /// UDP past RFC 3261 §18.1.1's line because `datagramWithoutStreamBytes`
  /// let it.
  String diagnosticsJson() {
    _ensureOpen();
    var capacity = 4096;
    while (true) {
      final text = using((arena) {
        final buffer = arena<ffi.Char>(capacity);
        final needed = arena<ffi.Size>();
        final status = _sipral.stackDiagnosticsJson(
          _handle,
          buffer,
          capacity,
          needed,
        );
        if (status == SipralStatus.bufferTooSmall) {
          capacity = needed.value;
          return null;
        }
        _check(_sipral, 'sipral_stack_diagnostics_json', status);
        return _decode(buffer.cast(), max(0, needed.value - 1));
      });
      if (text != null) {
        return text;
      }
    }
  }

  static int _toggle(bool? value) => switch (value) {
    null => SipralToggle.default$,
    true => SipralToggle.on,
    false => SipralToggle.off,
  };

  /// `scheme:user@host:port` for [aor] at [at], or `scheme:host:port` for an
  /// address of record with no user part, [parameters] after it.
  String _defaultContact(String aor, String at, [String parameters = '']) {
    final colon = aor.indexOf(':');
    final scheme = colon < 0 ? 'sip' : aor.substring(0, colon);
    final rest = colon < 0 ? aor : aor.substring(colon + 1);
    final user = rest.indexOf('@');
    return user < 0
        ? '$scheme:$at$parameters'
        : '$scheme:${rest.substring(0, user)}@$at$parameters';
  }

  /// The transport an account on a connection of its own names in its
  /// `Contact` (RFC 3261 §19.1.1); nothing for one on the UDP socket.
  static String _contactParameters(int? streamProtocol) =>
      switch (streamProtocol) {
        SipralTransport.tcp => ';transport=tcp',
        SipralTransport.tls => ';transport=tls',
        _ => '',
      };

  /// Open the connection an account on a connection of its own asked for
  /// (`SipralEventKind.transportWanted` with nothing outgrown) to
  /// [destination], over [protocol], and bind it; a connection that cannot
  /// be made is told to the stack, which asks again with the account's next
  /// REGISTER.
  Future<void> _openStream(String destination, int protocol) async {
    if (_closed ||
        _streamsOpening.contains(destination) ||
        _streamDestinations.containsValue(destination)) {
      return;
    }
    final address = _parseAddress(destination);
    if (address == null) {
      return;
    }
    _streamsOpening.add(destination);
    final id = _nextStream++;
    final tls = protocol == SipralTransport.tls;
    Socket socket;
    try {
      final plain = await Socket.connect(
        address.$1,
        address.$2,
        timeout: const Duration(seconds: 5),
      );
      plain.setOption(SocketOption.tcpNoDelay, true);
      if (tls) {
        final account =
            _accounts.values
                .where(
                  (one) =>
                      one.streamProtocol == SipralTransport.tls &&
                      one.registrarAddress == destination,
                )
                .firstOrNull;
        final pinned = account?._tlsPin != null;
        final secured = await SecureSocket.secure(
          plain,
          host: _tlsServerName ?? address.$1.address,
          // a pin is the whole verdict: no authority is trusted beside it.
          // The handshake is let through here and the verdict read below,
          // on the leaf: what this callback is handed is whichever
          // certificate of the chain failed, the top one, and a server
          // that sends the pinned certificate above a leaf of its own
          // would pass on it
          context: pinned ? SecurityContext(withTrustedRoots: false) : null,
          onBadCertificate: pinned ? (_) => true : null,
        );
        if (pinned) {
          final leaf = secured.peerCertificate;
          if (leaf == null || !_pinned(account!, leaf)) {
            secured.destroy();
            throw const HandshakeException(
              'the server\'s certificate is not the one the account pins',
            );
          }
        }
        socket = secured;
      } else {
        socket = plain;
      }
    } catch (refused) {
      _streamsOpening.remove(destination);
      _sayNoStream(id, destination, tls, refused);
      _poll();
      return;
    }
    _streamsOpening.remove(destination);
    if (_closed) {
      socket.destroy();
      return;
    }
    _streams[id] = socket;
    _streamDestinations[id] = destination;
    using((arena) {
      final local = _text(arena, _formatAddress(socket.address, socket.port));
      final remote = _text(arena, destination);
      _checkNow(
        _sipral,
        'sipral_stack_transport_bind',
        () => _sipral.stackTransportBind(
          _handle,
          id,
          protocol,
          local.$1,
          local.$2,
          remote.$1,
          remote.$2,
          nowMs(),
          ffi.nullptr,
        ),
      );
    });
    socket.listen(
      (bytes) => _streamReceived(id, bytes),
      onDone: () => _loseStream(id),
      onError: (Object _) => _loseStream(id),
      cancelOnError: true,
    );
    _poll();
  }

  /// Whether [certificate] is the one [account] pins, by the library's own
  /// verdict.
  static bool _pinned(SipralAccount account, X509Certificate certificate) {
    try {
      return account.checkCertificate(certificate.der) != null;
    } on SipralException {
      return false;
    }
  }

  /// `sipral_stack_transport_failed_with` for a connection that was not made.
  void _sayNoStream(int id, String destination, bool tls, Object refused) {
    final error = switch (refused) {
      SocketException(osError: OSError(errorCode: 61 || 111)) =>
        SipralTransportError.connectionRefused,
      SocketException(message: final said) when said.contains('timed out') =>
        SipralTransportError.timedOut,
      HandshakeException() => SipralTransportError.connectionReset,
      _ => SipralTransportError.other,
    };
    using((arena) {
      final said = refused.toString().replaceAll(RegExp(r'[\x00-\x1f]'), ' ');
      final detail = _text(
        arena,
        '${tls ? 'TLS' : 'TCP'} to $destination failed: $said',
      );
      final failure = arena<SipralTransportFailure>();
      failure.ref
        ..size = ffi.sizeOf<SipralTransportFailure>()
        ..transport = id
        ..error = error
        ..tls =
            refused is HandshakeException
                ? SipralTlsFailure.untrusted
                : SipralTlsFailure.none
        ..detail = detail.$1
        ..detailLen = min(detail.$2, Sipral.transportDetailBytes);
      retryingClockBehind(
        () => _sipral.stackTransportFailedWith(_handle, failure, nowMs()),
      );
    });
  }

  /// What a connection of an account's own carried, to
  /// `sipral_stack_receive_stream`, every byte and in order.
  void _streamReceived(int id, Uint8List bytes) {
    if (_closed) {
      return;
    }
    using((arena) {
      final data = arena<ffi.Uint8>(max(1, bytes.length));
      data.asTypedList(bytes.length).setAll(0, bytes);
      final status = retryingClockBehind(
        () => _sipral.stackReceiveStream(
          _handle,
          id,
          data,
          bytes.length,
          nowMs(),
        ),
      );
      if (status != SipralStatus.ok) {
        // the framing is lost: the stack retired the transport itself
        _streams.remove(id)?.destroy();
        _streamDestinations.remove(id);
      }
    });
    _poll();
  }

  /// A connection of an account's own closed or failed: told to the stack
  /// (`sipral_stack_stream_closed`), which asks for another.
  void _loseStream(int id) {
    final socket = _streams.remove(id);
    _streamDestinations.remove(id);
    if (socket == null || _closed) {
      return;
    }
    socket.destroy();
    retryingClockBehind(() => _sipral.stackStreamClosed(_handle, id, nowMs()));
    _poll();
  }

  /// Place a call from [account] to [target], its media socket bound on
  /// [mediaHost] -- by default the route toward [destination] or the
  /// account's server: the socket is open, and its address offered, before
  /// the INVITE goes out. [destination] sends the INVITE somewhere other than
  /// the account's registrar address.
  Future<SipralCall> placeCall(
    SipralAccount account,
    String target, {
    String? mediaHost,
    String? destination,
  }) async {
    _ensureOpen();
    final media = await RawDatagramSocket.bind(
      _mediaHost(mediaHost, account, destination),
      0,
    );
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
        _checkNow(
          _sipral,
          'sipral_call_place',
          () =>
              _sipral.callPlace(_handle, account.handle, config, out, nowMs()),
        );
        return out.value;
      });
    } catch (_) {
      media.close();
      rethrow;
    }
    final call = SipralCall._(
      this,
      handle,
      media,
      mediaAddress,
      incoming: false,
    );
    _calls[handle] = call;
    _poll();
    return call;
  }

  /// Answer the `SipralEventKind.incomingCall` [incoming], with a media
  /// socket bound on [mediaHost] -- by default the route toward the server
  /// of the account the call came to.
  Future<SipralCall> answerCall(
    SipralStackEvent incoming, {
    String? mediaHost,
  }) async {
    _ensureOpen();
    if (incoming.kind != SipralEventKind.incomingCall) {
      throw ArgumentError.value(
        incoming,
        'incoming',
        'is not an incoming call',
      );
    }
    final media = await RawDatagramSocket.bind(
      _mediaHost(mediaHost, _accounts[incoming.account], null),
      0,
    );
    final mediaAddress = _formatAddress(media.address, media.port);
    final call = SipralCall._(
      this,
      incoming.call,
      media,
      mediaAddress,
      incoming: true,
    );
    _calls[incoming.call] = call;
    try {
      using((arena) {
        final text = _text(arena, mediaAddress);
        _checkNow(
          _sipral,
          'sipral_call_answer_media',
          () => _sipral.callAnswerMedia(
            _handle,
            incoming.call,
            text.$1,
            text.$2,
            nowMs(),
          ),
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
    _checkNow(
      _sipral,
      'sipral_call_reject',
      () => _sipral.callReject(_handle, incoming.call, code, nowMs()),
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
    for (final socket in _streams.values) {
      socket.destroy();
    }
    _streams.clear();
    _streamDestinations.clear();
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
      retryingClockBehind(
        () => _sipral.stackReceiveDatagram(
          _handle,
          Sipral.transportMain,
          _received,
          length,
          _from.cast(),
          from.length,
          ffi.nullptr,
          0,
          nowMs(),
        ),
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
      final stream = _streams[_transmit.ref.transport];
      if (stream != null) {
        stream.add(
          Uint8List.fromList(_transmitData.asTypedList(_transmit.ref.len)),
        );
        continue;
      }
      final to = _parseAddress(
        _decode(_transmitTo, _transmit.ref.destinationLen),
      );
      if (to != null) {
        _socket.send(
          Uint8List.fromList(_transmitData.asTypedList(_transmit.ref.len)),
          to.$1,
          to.$2,
        );
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
      onRawEvent?.call(raw.ref);
    } catch (error, trace) {
      _report(error, trace);
    }
    try {
      final event = SipralStackEvent._read(raw.ref);
      final call = _calls[event.call];
      if (call != null && event.kind == SipralEventKind.callEnded) {
        _drainFarewells();
      }
      call?._deliver(event);
      _accounts[event.account]?._deliver(event);
      final name = event.lookupName;
      if (event.kind == SipralEventKind.lookupWanted && name != null) {
        // nothing may call back into the stack from inside its callback
        unawaited(_lookUp(event.account, name, event.lookupRecord ?? 0));
      }
      if (event.kind == SipralEventKind.transportWanted) {
        final wanted = raw.ref.payload.transportWanted;
        final destination =
            wanted.destination == ffi.nullptr
                ? null
                : _decode(wanted.destination.cast(), wanted.destinationLen);
        // an account on a connection of its own asks with nothing
        // outgrown; a request that outgrew a datagram is left to the
        // stack's own wait, as this layer opens no stream for one
        if (destination != null &&
            wanted.requestBytes == 0 &&
            wanted.limitBytes == 0) {
          final protocol = wanted.protocol;
          Timer.run(() => unawaited(_openStream(destination, protocol)));
        }
      }
      final targets = event.locatedTargets;
      if (event.kind == SipralEventKind.located && targets != null) {
        final first = targets.split(',').first;
        Timer.run(() {
          try {
            _located(event.account, first);
          } catch (error, trace) {
            _report(error, trace);
          }
        });
      }
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
