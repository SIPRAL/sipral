// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The printed binding against the library it loads: the ABI check passes,
// and every struct and union dart:ffi lays out here is as long as the
// library compiled it.

import 'dart:convert';
import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart';
import 'package:sipral/sipral_abi.dart';
import 'package:test/test.dart';

void main() {
  final sipral = Sipral.open();

  test('the library serves the ABI this binding was printed from', () {
    final version = calloc<SipralAbiVersion>();
    addTearDown(() => calloc.free(version));
    version.ref.size = ffi.sizeOf<SipralAbiVersion>();
    expect(sipral.abiVersion(version), SipralStatus.ok);
    expect(version.ref.major, Sipral.abiVersionMajor);
    expect(version.ref.minor, greaterThanOrEqualTo(Sipral.abiVersionMinor));
  });

  test('every record is laid out as long as the layout it runs on says', () {
    final layouts = Sipral.recordLayouts();
    expect(layouts.length, greaterThan(50));
    // 64-bit pointers, or 32-bit ones with a 64-bit integer aligned to four
    // (i386 everywhere but Windows) or to eight (ARM, Windows x86)
    final column = ffi.sizeOf<ffi.IntPtr>() == 8
        ? 1
        : ffi.Abi.current() == ffi.Abi.linuxIA32 ||
                ffi.Abi.current() == ffi.Abi.androidIA32
            ? 2
            : 3;
    using((arena) {
      final out = arena<ffi.Size>();
      for (final MapEntry(key: name, value: lengths) in layouts.entries) {
        final bytes = utf8.encode(name);
        final text = arena<ffi.Uint8>(bytes.length);
        text.asTypedList(bytes.length).setAll(0, bytes);
        expect(
          sipral.abiStructSize(text.cast(), bytes.length, out),
          SipralStatus.ok,
          reason: '$name is not a struct the library knows',
        );
        expect(lengths[0], lengths[column],
            reason: '$name as dart:ffi lays it out');
        expect(out.value, lengths[column],
            reason: '$name as the library compiled it');
      }
    });
  });

  test('a status is named by the library', () {
    final name = sipral.statusName(SipralStatus.invalidArgument);
    expect(name.cast<Utf8>().toDartString(), isNotEmpty);
  });
}
