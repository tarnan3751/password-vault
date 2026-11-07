import { render } from 'preact';
import { MemoryStore, type KeyValueStore } from './vault/index.ts';
import { IdbStore } from './vault/idb-store.ts';
import { App } from './ui/app.tsx';
import './styles.css';

// IndexedDB can be unavailable (some private modes). The app still works for
// the session; there is just no offline copy afterwards.
let store: KeyValueStore;
try {
  store = typeof indexedDB === 'undefined' ? new MemoryStore() : new IdbStore();
} catch {
  store = new MemoryStore();
}

render(<App store={store} />, document.getElementById('app')!);

if ('serviceWorker' in navigator && location.protocol.startsWith('http')) {
  navigator.serviceWorker.register('/sw.js').catch(() => {
    /* offline shell is a bonus, never a requirement */
  });
}
