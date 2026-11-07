# Family Vault: browser client

All cryptography happens here, in the browser. The servers only see ciphertext.
Normative specs: `../docs/spec/crypto.md`, `../docs/spec/api.md`; shared vectors: `../testvectors/`.

## Commands

```
npm ci               # install (exact versions pinned, package-lock.json committed)
npm test             # vectors + unit + API + session + dist/CSP tests (node --test, no DOM)
npm run typecheck    # tsc --noEmit (app) and for the service worker (separate lib set)
npm run build        # deterministic build into dist/ (COMMITTED; embedded by embed.go)
npm run smoke        # headless-Chromium run of the built bundle against scripts/stub-server.ts
                     #   (once: npx playwright-core install chromium; SHOTS_DIR=... saves screenshots)
npm run smoke -- --real
                     # same UI against a REAL three-node vaultd cluster in a temp dir (rebuilds ../bin/vaultd,
                     #   second user via invite, share + verify + accept, node kills and recovery)
npm run e2e -- --base http://127.0.0.1:8001 --bootstrap-token <t>
                     # drives a real cluster's HTTP API with src/api + src/vault (no UI)
npm run e2e -- --stub   # self-check of the script against the in-memory fake
npm run e2e -- --real   # starts a temporary real cluster (scripts/real-cluster.mjs) and runs against it
```

After changing anything in `src/`, `public/` or `scripts/build.mjs`, run `npm run build` and commit
`dist/`: a test fails if the committed `dist/` differs from what the build produces.

## Layers (each testable without a DOM)

| dir | role |
|---|---|
| `src/crypto/` | pure functions per crypto.md (revised: username-bound KDF salt, epoch-bound AADs, rosters, strict §5.3 scanner `strictjson.ts` that keeps unknown members byte for byte, raw re-encryption, 128-bit identity-bound fingerprints, key commitments, sealed local trust, master-password policy). Test-vector-only entry points (fixed nonces/ephemeral keys, unsafe KDF) live in `testonly.ts`, which the app never imports (a test greps the bundle). Previously: KDF + parameter floor, box seal/open, X25519 wrap/unwrap, fingerprints, padding, item/meta/backup encode+decode (unknown fields preserved), password generator, ids, encodings. Libraries: `@noble/*`, `hash-wasm`; nothing hand-rolled. |
| `src/api/` | typed HTTP client mirroring `internal/api/types.go`: node list + failover, `Idempotency-Key` on every mutation, linearizable reads with stale fallback, typed `ApiError`/`NetworkError`. |
| `src/vault/` | `Session`: register/login/unlock (online or from cache), sync validation (§6.2), identity checks (§4), the sealed local trust store (`trust-store.ts`: verified contacts, mismatch events, per-vault epoch+commitment+owners), vault-key acceptance incl. PENDING shares (§6.4), rosters (§6.3), add-member (§6.5), plan/execute rekey (§6.6), items with optimistic concurrency, password change, admin, backup. Storage behind `KeyValueStore` (IndexedDB in the browser, memory in tests). Keys and token live only in memory. |
| `src/ui/` | Preact components. No logic that is not trivially view-related. |
| `src/sw.ts`, `src/sw-integrity.ts` | service worker: app shell offline; never touches `/v1/`; verifies every asset against a SHA-256 manifest embedded at build time before caching and purges mismatching entries on activate. |
| `test/fake-server.ts` | in-memory fake of the HTTP API used by the session tests and the smoke test. |

## Constraints worth remembering

* CSP is `script-src 'self' 'wasm-unsafe-eval'; style-src 'self'`: no inline script/style, no `style=""`, no eval.
  Presentation lives in `src/styles.css`; `test/dist-csp.test.ts` checks the built output.
* Nothing secret in URLs, `document.title`, console output, or error messages (the dist test greps for `console.*`).
* `localStorage` holds only the auto-lock minutes and a typed server address. Everything else is IndexedDB
  (ciphertext cache, key pins, node URLs) or memory (keys).

## Restoring the servers from a backup

If an administrator restores the servers from a backup they legitimately show an older state. A device that has
seen newer data cannot tell this from a rollback, so it stops writing, keeps its saved copy readable and offers one
explicit action, "Accept the restored state" (never automatic, never for key-mismatch events or a vault at the
same key generation with a different key). See `Session.acceptRestoredState` and crypto.md §6.4.
