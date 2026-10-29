// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// A client certificate on an account's own TLS connection, against servers
// on loopback that require one: this test's registrar on Dart's TLS, which
// takes a certificate its authority signed and registers the account, and
// OpenSSL's own server, which refuses one with the alert TLS defines for
// why. Each refusal arrives as `SipralEventKind.transportFailed` with its
// own `tlsFailure`; a certificate out of its dates or whose key cannot be
// used is refused before anything reaches the server. The certificates are
// made by the `openssl` command for the run.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:sipral/sipral.dart';
import 'package:test/test.dart';

import 'account_stream_test.dart' show StreamRegistrar, certificate, serverName;

const clientName = 'alice-phone.sipral.test';
const otherClientName = 'bob-phone.sipral.test';

/// What the `openssl` command made in one directory.
final class Made {
  Made(this.directory);

  final Directory directory;
  String at(String name) => '${directory.path}/$name';

  SipralClientCertificate files(String name, {String? key}) =>
      SipralClientCertificate.files(at('$name.pem'), at('${key ?? name}.key'));
}

Future<bool> openssl(List<String> arguments) async {
  try {
    return (await Process.run('openssl', arguments)).exitCode == 0;
  } on ProcessException {
    return false;
  }
}

/// A client authority, another one, a certificate each signed for
/// [clientName] with `clientAuth`, one the first signed for
/// [otherClientName], and one the first signed that expired in 2020; false
/// where there is no `openssl` command.
Future<bool> clientCertificates(Made made) async {
  Future<bool> authority(String name, String cn) => openssl([
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', //
    'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
    '-subj', '/CN=$cn',
    '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign',
    '-keyout', made.at('$name.key'), '-out', made.at('$name.pem'),
  ]);
  Future<bool> signed(
    String name,
    String by,
    List<String> dates, {
    String cn = clientName,
  }) async =>
      await openssl([
        'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', //
        '-nodes', '-subj', '/CN=$cn',
        '-keyout', made.at('$name.key'), '-out', made.at('$name.csr'),
      ]) &&
      await openssl([
        'x509', '-req', '-in', made.at('$name.csr'), //
        '-CA', made.at('$by.pem'), '-CAkey', made.at('$by.key'),
        '-CAcreateserial', '-extfile', made.at('client.ext'), ...dates,
        '-out', made.at('$name.pem'),
      ]);
  await File(
    made.at('client.ext'),
  ).writeAsString('extendedKeyUsage=clientAuth\n');
  return await authority('ca', 'Sipral test client authority') &&
      await authority('other', 'Another authority') &&
      await signed('good', 'ca', ['-days', '1']) &&
      await signed('bobs', 'ca', ['-days', '1'], cn: otherClientName) &&
      await signed('stranger', 'other', ['-days', '1']) &&
      await signed('expired', 'ca', [
        '-not_before', '20200101000000Z', //
        '-not_after', '20200102000000Z',
      ]);
}

/// OpenSSL's own TLS server, `openssl s_server`, at TLS 1.3 or 1.2,
/// requiring a client certificate the authority in [made] signed: unlike
/// Dart's, it refuses one with the alert TLS defines for why.
Future<(Process, int)> openSslServer(Made made, String version) async {
  final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = probe.port;
  await probe.close();
  final server = await Process.start('openssl', [
    's_server', '-accept', '127.0.0.1:$port', version, //
    '-Verify', '1', '-verify_return_error', '-CAfile', made.at('ca.pem'),
    '-cert', made.at('registrar.pem'), '-key', made.at('registrar.key'),
  ]);
  final listening = Completer<void>();
  server.stdout.listen((bytes) {
    if (!listening.isCompleted &&
        String.fromCharCodes(bytes).contains('ACCEPT')) {
      listening.complete();
    }
  });
  server.stderr.drain<void>();
  await listening.future.timeout(const Duration(seconds: 10));
  return (server, port);
}

/// A TCP relay to `127.0.0.1:[port]` that holds what each end sends for
/// [delay] before passing it on, as a long path would, each later segment
/// from the client 20 ms longer than the one before, as a path whose queue
/// is filling holds it. Bytes that reach a
/// server which has closed its end are answered the way its kernel answers
/// them, with a reset, passed on at once and dropping whatever the server
/// sent that has not arrived yet -- as a client's kernel drops what it held
/// unread when the reset comes. What a client wrote before the server's
/// delayed answer reached it then loses it that answer.
Future<ServerSocket> slowPath(int port, Duration delay) async {
  final relay = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  relay.listen((client) async {
    final upstream = await Socket.connect(InternetAddress.loopbackIPv4, port);
    var upstreamEnded = false;
    var reset = false;
    var segments = 0;
    client.done.ignore();
    upstream.done.ignore();
    client.listen(
      (bytes) => Timer(delay + Duration(milliseconds: 20 * segments++), () {
        if (reset) {
          return;
        }
        if (upstreamEnded) {
          reset = true;
          upstream.destroy();
          // SO_LINGER on with no time to linger: the close is a reset
          final linger = Uint8List(8);
          linger.buffer.asByteData().setInt32(0, 1, Endian.host);
          client.setRawOption(
            RawSocketOption(
              RawSocketOption.levelSocket,
              Platform.isMacOS ? 0x80 : 13,
              linger,
            ),
          );
          client.destroy();
        } else {
          upstream.add(bytes);
        }
      }),
      onError: (Object _) => upstream.destroy(),
      onDone: () => upstream.destroy(),
      cancelOnError: true,
    );
    upstream.listen(
      (bytes) => Timer(delay, () {
        if (!reset) {
          client.add(bytes);
        }
      }),
      onError: (Object _) => client.destroy(),
      onDone: () {
        upstreamEnded = true;
        Timer(delay, () {
          if (!reset) {
            client.close().ignore();
          }
        });
      },
      cancelOnError: true,
    );
  });
  return relay;
}

void main() {
  final opened = <SipralStack>[];
  late Made made;
  late String pin;
  var ready = false;

  setUpAll(() async {
    made = Made(await Directory.systemTemp.createTemp('sipral-dart-client'));
    final registrar = await certificate(made.directory);
    ready = registrar != null && await clientCertificates(made);
    pin = registrar?.$2 ?? '';
  });

  tearDownAll(() => made.directory.delete(recursive: true));

  tearDown(() async {
    for (final stack in opened) {
      await stack.close();
    }
    opened.clear();
  });

  /// This test's registrar on Dart's TLS, requiring a certificate the client
  /// authority signed.
  Future<StreamRegistrar> requiring() async {
    final context =
        SecurityContext()
          ..useCertificateChain(made.at('registrar.pem'))
          ..usePrivateKey(made.at('registrar.key'))
          ..setTrustedCertificates(made.at('ca.pem'));
    final registrar = await StreamRegistrar.open(context, true);
    addTearDown(registrar.close);
    return registrar;
  }

  /// An account on a TLS connection of its own to [address], pinned to the
  /// registrar's certificate, presenting [presents].
  Future<(SipralStack, SipralAccount)> account(
    String address,
    SipralClientCertificate? presents,
  ) async {
    final stack = await SipralStack.open(bindHost: '127.0.0.1');
    opened.add(stack);
    final account = stack.addAccount(
      'sip:alice@$serverName',
      registrarAddress: address,
      registrar: 'sip:$serverName',
      tlsPin: pin,
      streamProtocol: SipralTransport.tls,
      clientCertificate: presents,
    );
    return (stack, account);
  }

  /// The first transport failure once [account] registers.
  Future<SipralStackEvent> refusal(SipralStack stack, SipralAccount account) {
    final failed = stack.events
        .firstWhere((event) => event.kind == SipralEventKind.transportFailed)
        .timeout(const Duration(seconds: 15));
    account.register();
    return failed;
  }

  test('presents its certificate and registers', () async {
    if (!ready) {
      markTestSkipped('no openssl command to make the certificates with');
      return;
    }
    final registrar = await requiring();
    final (_, line) = await account(registrar.address, made.files('good'));
    await line.registered();
    expect(registrar.peers.first, clientName);
    expect(registrar.registers, isNotEmpty);
  });

  test(
    'presents a certificate given as bytes, and the stack\'s by default',
    () async {
      if (!ready) {
        markTestSkipped('no openssl command to make the certificates with');
        return;
      }
      final registrar = await requiring();
      final stack = await SipralStack.open(
        bindHost: '127.0.0.1',
        clientCertificate: SipralClientCertificate.pem(
          await File(made.at('good.pem')).readAsBytes(),
          await File(made.at('good.key')).readAsBytes(),
        ),
      );
      opened.add(stack);
      final line = stack.addAccount(
        'sip:alice@$serverName',
        registrarAddress: registrar.address,
        registrar: 'sip:$serverName',
        tlsPin: pin,
        streamProtocol: SipralTransport.tls,
      );
      await line.registered();
      expect(registrar.peers.first, clientName);
    },
  );

  test(
    'accounts with certificates of their own at one server each present their own',
    () async {
      if (!ready) {
        markTestSkipped('no openssl command to make the certificates with');
        return;
      }
      // a connection presents one certificate, and the server takes all it
      // carries as from the user that one names
      final registrar = await requiring();
      final stack = await SipralStack.open(
        bindHost: '127.0.0.1',
        clientCertificate: made.files('stranger'),
      );
      opened.add(stack);
      final users = {
        'alice': ('good', clientName),
        'bob': ('bobs', otherClientName),
      };
      final lines = [
        for (final MapEntry(key: user, value: (file, _)) in users.entries)
          stack.addAccount(
            'sip:$user@$serverName',
            registrarAddress: registrar.address,
            registrar: 'sip:$serverName',
            tlsPin: pin,
            streamProtocol: SipralTransport.tls,
            clientCertificate: made.files(file),
          ),
      ];
      await Future.wait([for (final line in lines) line.registered()]);
      for (final MapEntry(key: user, value: (_, name)) in users.entries) {
        final theirs = {
          for (final (connection, message) in registrar.registers)
            if (message
                .split('\r\n')
                .any(
                  (line) =>
                      line.toLowerCase().startsWith('from:') &&
                      line.contains('sip:$user@'),
                ))
              registrar.peerOn[connection],
        };
        expect(
          theirs,
          {name},
          reason:
              "$user's REGISTER came on a connection that presented $theirs",
        );
      }
    },
  );

  test(
    'with no certificate, the server requiring one is said to require it',
    () async {
      if (!ready) {
        markTestSkipped('no openssl command to make the certificates with');
        return;
      }
      // TLS 1.3: the alert comes after this end's handshake has finished,
      // on the first read
      final (server, port) = await openSslServer(made, '-tls1_3');
      addTearDown(server.kill);
      final (stack, line) = await account('127.0.0.1:$port', null);
      final event = await refusal(stack, line);
      expect(
        event.tlsFailure,
        SipralTlsFailure.clientCertificateRequired,
        reason: event.transportDetail,
      );
      expect(event.transportError, SipralTransportError.connectionReset);
    },
  );

  test(
    'a REGISTER written at once over a slow path still hears why TLS 1.3 refused it',
    () async {
      if (!ready) {
        markTestSkipped('no openssl command to make the certificates with');
        return;
      }
      // the stack writes its REGISTER as soon as the connection is bound;
      // over this path that would reach a server that has refused already,
      // and its reset would overtake the alert saying why
      final cases = <(SipralClientCertificate?, int)>[
        (null, SipralTlsFailure.clientCertificateRequired),
        (made.files('stranger'), SipralTlsFailure.clientCertificateRefused),
      ];
      for (final (presents, expected) in cases) {
        final (server, port) = await openSslServer(made, '-tls1_3');
        addTearDown(server.kill);
        final path = await slowPath(port, const Duration(milliseconds: 150));
        addTearDown(path.close);
        final (stack, line) = await account('127.0.0.1:${path.port}', presents);
        final event = await refusal(stack, line);
        expect(event.tlsFailure, expected, reason: event.transportDetail);
      }
    },
  );

  for (final version in ['-tls1_3', '-tls1_2']) {
    test(
      'a certificate another authority signed is refused, by its alert ($version)',
      () async {
        if (!ready) {
          markTestSkipped('no openssl command to make the certificates with');
          return;
        }
        final (server, port) = await openSslServer(made, version);
        addTearDown(server.kill);
        final (stack, line) = await account(
          '127.0.0.1:$port',
          made.files('stranger'),
        );
        final event = await refusal(stack, line);
        expect(
          event.tlsFailure,
          SipralTlsFailure.clientCertificateRefused,
          reason: event.transportDetail,
        );
        expect(event.transportDetail?.toUpperCase(), contains('UNKNOWN_CA'));
      },
    );
  }

  test(
    'an expired certificate, or a key that cannot be used, reaches no server',
    () async {
      if (!ready) {
        markTestSkipped('no openssl command to make the certificates with');
        return;
      }
      // plain TCP: any connection at all is counted
      final listener = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(listener.close);
      var reached = 0;
      listener.listen((socket) {
        reached++;
        socket.destroy();
      });
      final address = '127.0.0.1:${listener.port}';
      final cases = <(SipralClientCertificate, int)>[
        (made.files('expired'), SipralTlsFailure.clientCertificateExpired),
        (
          made.files('good', key: 'stranger'),
          SipralTlsFailure.clientKeyUnavailable,
        ),
        (
          made.files('good', key: 'absent'),
          SipralTlsFailure.clientKeyUnavailable,
        ),
        (
          SipralClientCertificate.pem(
            await File(made.at('good.pem')).readAsBytes(),
            'not a key'.codeUnits,
          ),
          SipralTlsFailure.clientKeyUnavailable,
        ),
      ];
      for (final (presents, expected) in cases) {
        final (stack, line) = await account(address, presents);
        final event = await refusal(stack, line);
        expect(event.tlsFailure, expected, reason: event.transportDetail);
        expect(event.transportError, SipralTransportError.other);
      }
      expect(reached, 0);
    },
  );
}
