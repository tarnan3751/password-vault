// Storage abstraction for the offline cache. NEVER store keys, passwords or
// tokens here: only ciphertext (the last SyncResponse verbatim), the SEALED
// local trust store (opaque without the account key) and node URLs. A browser
// backs this with IndexedDB, tests with memory.

export interface KeyValueStore {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<void>;
}

export class MemoryStore implements KeyValueStore {
  readonly data = new Map<string, unknown>();
  async get<T>(key: string): Promise<T | undefined> {
    const v = this.data.get(key);
    return v === undefined ? undefined : (structuredClone(v) as T);
  }
  async set(key: string, value: unknown): Promise<void> {
    this.data.set(key, structuredClone(value));
  }
  async delete(key: string): Promise<void> {
    this.data.delete(key);
  }
}

export const K = {
  sync: (username: string) => `sync:${username}`,
  trust: (userId: string) => `trust:${userId}`,
  nodes: 'nodes',
  lastUser: 'lastUser',
} as const;
