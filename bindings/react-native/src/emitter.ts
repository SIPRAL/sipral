// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

/** What `on` hands back: `remove()` stops that listener and no other. */
export interface Subscription {
  remove(): void;
}

/**
 * An emitter whose event names and payloads are one type, so that a listener
 * for "callEnded" is handed a `CallEndedEvent` and a misspelt name does not
 * compile.
 *
 * A listener that throws does not stop the others: what it threw is handed
 * to `onListenerError`, which rethrows it on a later turn by default so that
 * it still reaches the application's own error reporting.
 */
export class TypedEmitter<Events extends {[K in keyof Events]: unknown}> {
  private readonly listeners = new Map<keyof Events, Set<(payload: never) => void>>();

  onListenerError: (failure: unknown) => void = (failure) => {
    setTimeout(() => {
      throw failure;
    }, 0);
  };

  on<K extends keyof Events>(name: K, listener: (payload: Events[K]) => void): Subscription {
    let set = this.listeners.get(name);
    if (set === undefined) {
      set = new Set();
      this.listeners.set(name, set);
    }
    const held = listener as (payload: never) => void;
    set.add(held);
    return {
      remove: () => {
        this.listeners.get(name)?.delete(held);
      },
    };
  }

  /** `on`, for the next one only. */
  once<K extends keyof Events>(name: K, listener: (payload: Events[K]) => void): Subscription {
    const subscription = this.on(name, (payload) => {
      subscription.remove();
      listener(payload);
    });
    return subscription;
  }

  emit<K extends keyof Events>(name: K, payload: Events[K]): void {
    const set = this.listeners.get(name);
    if (set === undefined) {
      return;
    }
    for (const listener of [...set]) {
      try {
        (listener as (payload: Events[K]) => void)(payload);
      } catch (failure) {
        this.onListenerError(failure);
      }
    }
  }

  /** How many listeners `name` has. */
  listenerCount(name: keyof Events): number {
    return this.listeners.get(name)?.size ?? 0;
  }

  removeAllListeners(): void {
    this.listeners.clear();
  }
}
