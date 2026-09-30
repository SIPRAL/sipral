// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import {fromNative, SipralError} from '../errors';

function rejected(code: string): {code: string; message: string} {
  return Object.assign(new Error(`refused as ${code}`), {code});
}

describe('a native rejection', () => {
  it('keeps every status the library names, as the native halves spell it', () => {
    for (const code of ['notAFocus', 'clockBehind', 'conferenceRefused', 'busy', 'transportDown']) {
      const error = fromNative(rejected(code));
      expect(error).toBeInstanceOf(SipralError);
      expect(error.code).toBe(code);
    }
  });

  it('is the platform\'s when its code names no status', () => {
    expect(fromNative(rejected('notAfocus')).code).toBe('platform');
    expect(fromNative(rejected('somethingNew')).code).toBe('platform');
    expect(fromNative('no code at all').code).toBe('platform');
  });
});
