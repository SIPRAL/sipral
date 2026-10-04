// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Where a stack is reached and where its server is: the address a stack
// advertises when the application names none, a server named by a URI and
// located by RFC 3263, the account's keep-alive, a certificate trusted by
// its fingerprint, and the stack's ABI 0.34 options. The registrar is this
// test's own, a UDP socket on loopback that answers every REGISTER 200 and
// keeps every datagram.

import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:sipral/sipral.dart';
import 'package:sipral/sipral_abi.dart'
    show SipralEvent, SipralLogCallback, SipralLogLevel, SipralLogRecord;
import 'package:test/test.dart';

String? header(String name, String message) {
  for (final line in message.split('\r\n')) {
    if (line.toLowerCase().startsWith('${name.toLowerCase()}:')) {
      return line.substring(line.indexOf(':') + 1).trim();
    }
  }
  return null;
}

/// A registrar on a loopback UDP port: every REGISTER answered 200, every
/// datagram kept as text.
final class Registrar {
  Registrar._(this._socket) {
    _socket.listen((event) {
      if (event != RawSocketEvent.read) {
        return;
      }
      final datagram = _socket.receive();
      if (datagram == null) {
        return;
      }
      final message = utf8.decode(datagram.data, allowMalformed: true);
      received.add(message);
      if (!message.startsWith('REGISTER ')) {
        return;
      }
      final lines = ['SIP/2.0 200 OK'];
      for (final name in ['Via', 'From', 'To', 'Call-ID', 'CSeq']) {
        final value = header(name, message) ?? '';
        lines.add(name == 'To' ? 'To: $value;tag=registrar' : '$name: $value');
      }
      lines
        ..add('Contact: ${header('Contact', message)};expires=3600')
        ..add('Content-Length: 0');
      _socket.send(
        utf8.encode('${lines.join('\r\n')}\r\n\r\n'),
        datagram.address,
        datagram.port,
      );
    });
  }

  static Future<Registrar> open() async => Registrar._(
    await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0),
  );

  final RawDatagramSocket _socket;
  final List<String> received = [];

  int get port => _socket.port;
  String get address => '127.0.0.1:$port';
  List<String> get registers =>
      received.where((one) => one.startsWith('REGISTER ')).toList();

  void close() => _socket.close();
}

Future<void> until(
  bool Function() probe, {
  Duration within = const Duration(seconds: 5),
}) async {
  final deadline = DateTime.now().add(within);
  while (!probe()) {
    if (DateTime.now().isAfter(deadline)) {
      fail('nothing within $within');
    }
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
}

void main() {
  final opened = <SipralStack>[];
  final registrars = <Registrar>[];

  Future<SipralStack> stack({
    String? bindHost,
    SipralResolver? resolver,
    int srtp = 0,
  }) async {
    final made = await SipralStack.open(
      bindHost: bindHost,
      resolver: resolver,
      srtp: srtp,
    );
    opened.add(made);
    return made;
  }

  Future<Registrar> registrar() async {
    final made = await Registrar.open();
    registrars.add(made);
    return made;
  }

  tearDown(() async {
    for (final one in opened) {
      await one.close();
    }
    opened.clear();
    for (final one in registrars) {
      one.close();
    }
    registrars.clear();
  });

  test('the address of a wildcard socket is the route toward the peer', () {
    expect(
      advertisedAddress('0.0.0.0:5060', '127.0.0.1:5070'),
      '127.0.0.1:5060',
    );
    expect(
      () => advertisedAddress('127.0.0.1:5060', '192.0.2.1:5060'),
      throwsA(
        isA<SipralException>().having(
          (refused) => refused.status,
          'status',
          SipralStatus.unreachableAddress,
        ),
      ),
    );
    expect(routeHost('pbx.example.com:5060'), '127.0.0.1');
  });

  test('an account on loopback registers from loopback', () async {
    final server = await registrar();
    final client = await stack();
    final account = client.addAccount(
      'sip:alice@example.com',
      registrarAddress: server.address,
      registrar: 'sip:example.com',
    );
    await account.registered();
    final port = client.bindAddress.split(':').last;
    expect(
      header('Contact', server.registers.first),
      contains('@127.0.0.1:$port'),
    );
  });

  test(
    'an account on the network is reached at the route toward its server',
    () async {
      const remote = '192.0.2.1:5060';
      final route = routeHost(remote);
      if (route == '127.0.0.1') {
        markTestSkipped('this machine has no route off itself');
        return;
      }
      final client = await stack();
      client.addAccount(
        'sip:alice@example.com',
        registrarAddress: remote,
        registrar: 'sip:example.com',
      );
      expect(client.bindAddress.split(':').first, route);
    },
  );

  test('a loopback contact toward a registrar elsewhere is refused', () async {
    final client = await stack(bindHost: '127.0.0.1');
    final account = client.addAccount(
      'sip:alice@example.com',
      registrarAddress: '192.0.2.1:5060',
      registrar: 'sip:example.com',
    );
    expect(
      account.register,
      throwsA(
        isA<SipralException>().having(
          (refused) => refused.status,
          'status',
          SipralStatus.unreachableAddress,
        ),
      ),
    );
    expect(SipralRegistrationFailure.unreachableContact, 5);
  });

  test(
    'a call between two stacks that named nothing has media on loopback',
    () async {
      final alice = await stack();
      final bob = await stack();
      final toBob = alice.addAccount(
        'sip:alice@example.com',
        registrarAddress: bob.bindAddress,
      );
      bob.addAccount(
        'sip:bob@example.com',
        registrarAddress: alice.bindAddress,
      );
      final ringing = bob.events.firstWhere(
        (event) => event.kind == SipralEventKind.incomingCall,
      );
      final call = await alice.placeCall(toBob, 'sip:bob@example.com');
      expect(call.mediaAddress, startsWith('127.0.0.1:'));
      final answered = await bob.answerCall(
        await ringing.timeout(const Duration(seconds: 10)),
      );
      expect(answered.mediaAddress, startsWith('127.0.0.1:'));
      // carried to the end, so that the stacks close on calls whose media
      // started rather than on the way to it
      await Future.wait([
        call.confirmed(timeout: const Duration(seconds: 10)),
        answered.confirmed(timeout: const Duration(seconds: 10)),
      ]);
      await until(() => call.media != null && answered.media != null);
    },
  );

  test(
    'a host with a port is asked for its addresses and registered with',
    () async {
      final server = await registrar();
      final client = await stack();
      final located = client.events.firstWhere(
        (event) => event.kind == SipralEventKind.located,
      );
      final account = client.addAccount(
        'sip:alice@example.com',
        registrar: 'sip:example.com',
        serverUri: 'sip:localhost:${server.port}',
      );
      final registered = account.registered();
      final event = await located.timeout(const Duration(seconds: 10));
      expect(
        event.locatedTargets!.split(','),
        contains('127.0.0.1:${server.port}'),
      );
      await registered;
      expect(server.registers, hasLength(1));
    },
  );

  test('an SRV answer names the host and port the requests go to', () async {
    final server = await registrar();
    final asked = <String>[];
    final client = await stack(
      resolver: (name, record) async {
        asked.add('$record $name');
        if (record == SipralDnsRecordType.srv &&
            name == '_sip._udp.pbx.sipral.test') {
          return SipralLookup(SipralDnsAnswer.records, [
            '300 10 60 ${server.port} host.sipral.test',
          ]);
        }
        if (record == SipralDnsRecordType.a && name == 'host.sipral.test') {
          return const SipralLookup(SipralDnsAnswer.records, ['300 127.0.0.1']);
        }
        return SipralLookup.nothing;
      },
    );
    final located = client.events.firstWhere(
      (event) => event.kind == SipralEventKind.located,
    );
    final account = client.addAccount(
      'sip:alice@pbx.sipral.test',
      registrar: 'sip:pbx.sipral.test',
      serverUri: 'sip:pbx.sipral.test',
    );
    final registered = account.registered();
    final event = await located.timeout(const Duration(seconds: 10));
    expect(event.locatedTargets!.split(',').first, '127.0.0.1:${server.port}');
    await registered;
    await until(() => account.registrarAddress == '127.0.0.1:${server.port}');
    expect(
      asked,
      contains('${SipralDnsRecordType.srv} _sip._udp.pbx.sipral.test'),
    );
  });

  test('a name with no address is a locate failure that says why', () async {
    final client = await stack(resolver: (_, _) async => SipralLookup.nothing);
    final failed = client.events.firstWhere(
      (event) => event.kind == SipralEventKind.locateFailed,
    );
    client
        .addAccount(
          'sip:alice@example.com',
          registrar: 'sip:example.com',
          serverUri: 'sip:nowhere.sipral.test',
        )
        .register();
    final event = await failed.timeout(const Duration(seconds: 10));
    expect(event.locateFailure, SipralLocateFailure.notFound);
    expect(event.retryInMs, greaterThan(0));
  });

  test('the platform lookup finds localhost and has no SRV', () async {
    final found = await SipralDns.platform('localhost', SipralDnsRecordType.a);
    expect(found.answer, SipralDnsAnswer.records);
    expect(found.records, contains('60 127.0.0.1'));
    final srv = await SipralDns.platform(
      '_sip._udp.example.com',
      SipralDnsRecordType.srv,
    );
    expect(srv.answer, SipralDnsAnswer.nothing);
  });

  test('exactly one of the two names the server', () async {
    final client = await stack();
    expect(
      () => client.addAccount('sip:alice@example.com'),
      throwsArgumentError,
    );
    expect(
      () => client.addAccount(
        'sip:alice@example.com',
        registrarAddress: '127.0.0.1:5060',
        serverUri: 'sip:a.test',
      ),
      throwsArgumentError,
    );
  });

  test('a double CRLF goes to the registrar at the interval', () async {
    final server = await registrar();
    final client = await stack();
    final account = client.addAccount(
      'sip:alice@example.com',
      registrarAddress: server.address,
      registrar: 'sip:example.com',
      keepaliveMs: 1000,
    );
    await account.registered();
    await until(
      () => server.received.contains('\r\n\r\n'),
      within: const Duration(seconds: 3),
    );
    expect(
      () => client.addAccount(
        'sip:bob@example.com',
        registrarAddress: server.address,
        keepaliveMs: 999,
      ),
      throwsA(isA<SipralException>()),
    );
  });

  test(
    "the account's pin decides on the certificate a server presented",
    () async {
      final certificate = utf8.encode('the DER bytes of a leaf');
      // the SHA-256 of those bytes, as `shasum -a 256` prints it
      const pin =
          'd3faff920aa600f6630292af7fa1b77201069e3b22e418e04e88e6f8a962748f';
      final client = await stack();
      final pinned = client.addAccount(
        'sip:alice@example.com',
        registrarAddress: '127.0.0.1:5060',
        tlsPin: 'sha-256 $pin',
      );
      final verdict = pinned.checkCertificate(certificate);
      expect(verdict, isNotNull);
      expect(verdict!.expired, isFalse);
      expect(
        () => pinned.checkCertificate(utf8.encode('another certificate')),
        throwsA(
          isA<SipralException>().having(
            (refused) => refused.status,
            'status',
            SipralStatus.certificateRefused,
          ),
        ),
      );
      final unpinned = client.addAccount(
        'sip:bob@example.com',
        registrarAddress: '127.0.0.1:5060',
      );
      expect(unpinned.checkCertificate(certificate), isNull);
    },
  );

  test(
    'a suite the library does not run and a short salt are refused',
    () async {
      expect(
        () => SipralStack.open(srtpSuites: ['NOT_A_SUITE']),
        throwsA(isA<SipralException>()),
      );
      expect(
        () => SipralStack.open(pseudonymSalt: utf8.encode('short')),
        throwsA(isA<SipralException>()),
      );
      opened.add(
        await SipralStack.open(
          srtp: SipralSrtp.bestEffort,
          srtpSuites: ['AES_CM_128_HMAC_SHA1_80'],
          pseudonymSalt: List.generate(16, (index) => index),
        ),
      );
    },
  );

  test(
    'the trace writes whole messages only while the diagnostic trace is on',
    () async {
      final server = await registrar();
      final client = await stack();
      final written = <String>[];
      void line(ffi.Pointer<SipralLogRecord> record, ffi.Pointer<ffi.Void> _) {
        final text = record.ref.message.cast<Utf8>().toDartString(
          length: record.ref.messageLen,
        );
        written.add(text);
      }

      final callback = ffi.NativeCallable<SipralLogCallback>.isolateLocal(line);
      addTearDown(callback.close);
      final library = Sipral.open();
      expect(
        library.stackLog(
          client.handle,
          SipralLogLevel.trace,
          callback.nativeFunction,
          ffi.nullptr,
        ),
        SipralStatus.ok,
      );
      final account = client.addAccount(
        'sip:alice@example.com',
        registrarAddress: server.address,
        registrar: 'sip:example.com',
      );
      await account.registered();
      bool whole() =>
          written.any((one) => one.contains('sip:alice@example.com'));
      expect(whole(), isFalse, reason: 'pseudonymised');
      client.setDiagnosticTrace(true);
      account.register();
      await until(whole);
      library.stackLog(
        client.handle,
        SipralLogLevel.off,
        ffi.nullptr,
        ffi.nullptr,
      );
    },
  );

  test('best effort offers keys on plain RTP', () async {
    final alice = await stack(srtp: SipralSrtp.bestEffort);
    final bob = await stack();
    final toBob = alice.addAccount(
      'sip:alice@example.com',
      registrarAddress: bob.bindAddress,
    );
    bob.addAccount('sip:bob@example.com', registrarAddress: alice.bindAddress);
    String? offer;
    bob.onRawEvent = (SipralEvent event) {
      if (event.kind == SipralEventKind.incomingCall &&
          event.message != ffi.nullptr) {
        offer = utf8.decode(
          event.message.asTypedList(event.messageLen),
          allowMalformed: true,
        );
      }
    };
    await alice.placeCall(toBob, 'sip:bob@example.com');
    await until(() => offer != null);
    expect(offer, contains('RTP/AVP'));
    expect(offer, isNot(contains('RTP/SAVP')));
    expect(offer, contains('a=crypto:'));
  });
}
