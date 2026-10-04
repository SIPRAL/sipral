// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

/// <reference types="node" />
// the shared list is a file beside the package, read the way Jest's Node
// reads one; nothing outside this test sees Node's types

import {readFileSync} from 'fs';
import {join} from 'path';

import {SipralError} from '../errors';
import {pinDigest} from '../pin';

describe('a certificate pin', () => {
  it('is read or refused as every line of pin-forms.txt says', () => {
    const listed = readFileSync(join(__dirname, '..', '..', '..', 'fixtures', 'pin-forms.txt'), 'utf8');
    let digest = '';
    let checked = 0;
    for (const line of listed.split('\n')) {
      if (line === '' || line.startsWith('#')) {
        continue;
      }
      const tab = line.indexOf('\t');
      const verdict = tab < 0 ? line : line.slice(0, tab);
      const text = tab < 0 ? '' : line.slice(tab + 1);
      if (verdict === 'digest') {
        digest = text;
      } else if (verdict === 'accept') {
        expect([text, pinDigest(text)]).toEqual([text, digest]);
        checked += 1;
      } else {
        let refused: unknown;
        try {
          pinDigest(text);
        } catch (error) {
          refused = error;
        }
        expect([text, refused instanceof SipralError && refused.code]).toEqual([text, 'invalidArgument']);
        checked += 1;
      }
    }
    expect(digest).toHaveLength(64);
    expect(checked).toBeGreaterThan(20);
  });
});
