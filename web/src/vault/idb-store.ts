import type { KeyValueStore } from './storage.ts';

/** IndexedDB-backed KeyValueStore (browser only). One tiny object store. */
export class IdbStore implements KeyValueStore {
  private dbp: Promise<IDBDatabase> | null = null;
  private readonly name: string;
  constructor(name = 'family-vault') {
    this.name = name;
  }

  private db(): Promise<IDBDatabase> {
    this.dbp ??= new Promise((resolve, reject) => {
      const req = indexedDB.open(this.name, 1);
      req.onupgradeneeded = () => req.result.createObjectStore('kv');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return this.dbp;
  }

  private async tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    const db = await this.db();
    return new Promise<T>((resolve, reject) => {
      const r = fn(db.transaction('kv', mode).objectStore('kv'));
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }

  get<T>(key: string): Promise<T | undefined> {
    return this.tx<T | undefined>('readonly', (s) => s.get(key) as IDBRequest<T | undefined>);
  }
  async set(key: string, value: unknown): Promise<void> {
    await this.tx('readwrite', (s) => s.put(value, key));
  }
  async delete(key: string): Promise<void> {
    await this.tx('readwrite', (s) => s.delete(key));
  }
}
