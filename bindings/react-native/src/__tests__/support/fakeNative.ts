// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The native module as the TypeScript layer sees it, with nothing behind
// it: every call is recorded, handles are counted out, a failure can be
// queued for the next call of a method the way a native half rejects
// (an Error carrying `code`), and `emit` raises an event as the native
// half's onEvent would.

import type {NativeEvent, Spec} from '../../NativeSipral';

type Method = Exclude<keyof Spec, 'onEvent' | 'getConstants'>;

export interface Recorded {
  method: Method;
  args: unknown[];
}

export class FakeNative implements Spec {
  readonly calls: Recorded[] = [];
  private readonly handlers = new Set<(event: NativeEvent) => void>();
  private readonly failures = new Map<Method, {code: string; message: string}>();
  private next = 1;
  /** Run inside a method before it resolves: an event raised there arrives before the promise does. */
  during: Partial<Record<Method, () => void>> = {};

  readonly onEvent = (handler: (event: NativeEvent) => void) => {
    this.handlers.add(handler);
    return {remove: () => this.handlers.delete(handler)};
  };

  get listeners(): number {
    return this.handlers.size;
  }

  failNext(method: Method, code: string, message = `${method} refused`): void {
    this.failures.set(method, {code, message});
  }

  emit(event: Partial<NativeEvent> & {kind: string}): void {
    const full: NativeEvent = {kindName: event.kind, account: '', call: '', ...event};
    for (const handler of [...this.handlers]) {
      handler(full);
    }
  }

  /** The methods called so far, in order. */
  methods(): Method[] {
    return this.calls.map((call) => call.method);
  }

  private settle<T>(method: Method, args: unknown[], value: T): Promise<T> {
    this.calls.push({method, args});
    const failure = this.failures.get(method);
    if (failure !== undefined) {
      this.failures.delete(method);
      return Promise.reject(Object.assign(new Error(failure.message), {code: failure.code}));
    }
    this.during[method]?.();
    return Promise.resolve(value);
  }

  private handle(): string {
    return String(this.next++);
  }

  open(...args: Parameters<Spec['open']>) {
    return this.settle('open', args, '192.0.2.10:5060');
  }
  close() {
    return this.settle('close', [], undefined);
  }
  addAccount(...args: Parameters<Spec['addAccount']>) {
    return this.settle('addAccount', args, this.handle());
  }
  register(...args: Parameters<Spec['register']>) {
    return this.settle('register', args, undefined);
  }
  unregister(...args: Parameters<Spec['unregister']>) {
    return this.settle('unregister', args, undefined);
  }
  removeAccount(...args: Parameters<Spec['removeAccount']>) {
    return this.settle('removeAccount', args, undefined);
  }
  placeCall(...args: Parameters<Spec['placeCall']>) {
    return this.settle('placeCall', args, this.handle());
  }
  answer(...args: Parameters<Spec['answer']>) {
    return this.settle('answer', args, undefined);
  }
  reject(...args: Parameters<Spec['reject']>) {
    return this.settle('reject', args, undefined);
  }
  hangup(...args: Parameters<Spec['hangup']>) {
    return this.settle('hangup', args, undefined);
  }
  hold(...args: Parameters<Spec['hold']>) {
    return this.settle('hold', args, undefined);
  }
  resume(...args: Parameters<Spec['resume']>) {
    return this.settle('resume', args, undefined);
  }
  transfer(...args: Parameters<Spec['transfer']>) {
    return this.settle('transfer', args, undefined);
  }
  acceptTransfer(...args: Parameters<Spec['acceptTransfer']>) {
    return this.settle('acceptTransfer', args, this.handle());
  }
  rejectTransfer(...args: Parameters<Spec['rejectTransfer']>) {
    return this.settle('rejectTransfer', args, undefined);
  }
  sendDtmf(...args: Parameters<Spec['sendDtmf']>) {
    return this.settle('sendDtmf', args, undefined);
  }
  activateAudio() {
    return this.settle('activateAudio', [], undefined);
  }
  deactivateAudio() {
    return this.settle('deactivateAudio', [], undefined);
  }
  setMuted(...args: Parameters<Spec['setMuted']>) {
    return this.settle('setMuted', args, undefined);
  }
  setDiagnosticTrace(...args: Parameters<Spec['setDiagnosticTrace']>) {
    return this.settle('setDiagnosticTrace', args, undefined);
  }
  setCallGain(...args: Parameters<Spec['setCallGain']>) {
    return this.settle('setCallGain', args, undefined);
  }
  setCallMuted(...args: Parameters<Spec['setCallMuted']>) {
    return this.settle('setCallMuted', args, undefined);
  }
  callAudio(...args: Parameters<Spec['callAudio']>) {
    return this.settle('callAudio', args, {gain: 0.5, muted: true, level: 0});
  }
  settings() {
    return this.settle('settings', [], {
      transport: 'udp',
      codecCount: 4,
      frameMs: 20,
      srtpSuites: '2,1',
      pseudonymSalted: true,
      diagnosticTrace: false,
      systemEchoCancellation: false,
    });
  }
}
