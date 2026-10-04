// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import {TypedEmitter} from '../emitter';

interface Events {
  rang: {from: string};
  ended: {reason: string};
}

describe('the typed emitter', () => {
  it('hands each listener its own event, until it is removed', () => {
    const emitter = new TypedEmitter<Events>();
    const seen: string[] = [];
    const subscription = emitter.on('rang', (event) => seen.push(event.from));
    emitter.on('ended', (event) => seen.push(event.reason));
    emitter.emit('rang', {from: 'carol'});
    emitter.emit('ended', {reason: 'remoteHangup'});
    subscription.remove();
    emitter.emit('rang', {from: 'dave'});
    expect(seen).toEqual(['carol', 'remoteHangup']);
    expect(emitter.listenerCount('rang')).toBe(0);
  });

  it('calls a once listener once', () => {
    const emitter = new TypedEmitter<Events>();
    const seen: string[] = [];
    emitter.once('rang', (event) => seen.push(event.from));
    emitter.emit('rang', {from: 'carol'});
    emitter.emit('rang', {from: 'dave'});
    expect(seen).toEqual(['carol']);
  });

  it('keeps calling the others when one throws, and hands on what it threw', () => {
    const emitter = new TypedEmitter<Events>();
    const thrown: unknown[] = [];
    emitter.onListenerError = (failure) => thrown.push(failure);
    const seen: string[] = [];
    emitter.on('rang', () => {
      throw new Error('listener broke');
    });
    emitter.on('rang', (event) => seen.push(event.from));
    emitter.emit('rang', {from: 'carol'});
    expect(seen).toEqual(['carol']);
    expect((thrown[0] as Error).message).toBe('listener broke');
  });

  it('lets a listener remove itself while the event is being delivered', () => {
    const emitter = new TypedEmitter<Events>();
    const seen: string[] = [];
    const first = emitter.on('rang', () => {
      first.remove();
      seen.push('first');
    });
    emitter.on('rang', () => seen.push('second'));
    emitter.emit('rang', {from: 'carol'});
    emitter.emit('rang', {from: 'carol'});
    expect(seen).toEqual(['first', 'second', 'second']);
  });
});
