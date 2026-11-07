// The text people see for server refusals: plain sentences, never the developer wording of the API.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApiError, NetworkError } from '../src/api/index.ts';
import { errMsg } from '../src/ui/errors.ts';

const api = (code: string, message: string, status = 400) => errMsg(new ApiError(status, { code, message }));

test('every API error code maps to a sentence that says what happened', () => {
  const codes = ['bad_request', 'unauthorized', 'forbidden', 'not_found', 'version_conflict', 'key_epoch_mismatch', 'already_exists', 'invalid_invite', 'too_large', 'limit_exceeded', 'rate_limited', 'unavailable', 'outcome_unknown', 'internal', 'something_new'];
  for (const c of codes) {
    const m = api(c, 'dev text: base_version does not match');
    assert.match(m, /^[A-Z].*[.]$/, c);
    assert.ok(!/base_version|dev text/.test(m), `${c} leaks developer wording: ${m}`);
  }
});

test('refusals that share a code are told apart by cause', () => {
  assert.match(api('forbidden', 'the last enabled admin cannot be disabled or demoted'), /last administrator.*someone else/);
  assert.match(api('forbidden', 'the last owner cannot be removed'), /at least one owner/);
  assert.match(api('forbidden', 'viewers cannot change items'), /editor/);
  assert.match(api('limit_exceeded', 'vault storage quota of 8 MiB exceeded'), /vault is full/);
  assert.match(api('limit_exceeded', 'household storage quota of 48 MiB exceeded'), /household’s storage is full/);
  assert.match(api('limit_exceeded', 'per-user storage quota of 16 MiB exceeded (charged to the vault\'s creator)'), /created by this person are full/);
  assert.match(api('limit_exceeded', 'item limit reached for this vault'), /as many entries/);
  assert.match(api('already_exists', 'user is already a member; omit wrapped_key to change the role'), /already in this vault/);
  assert.match(errMsg(new ApiError(429, { code: 'rate_limited', message: 'x', retry_after_ms: 2500 })), /3 seconds/);
});

test('connection failures are explained, not echoed', () => {
  assert.match(errMsg(new NetworkError('could not reach any server')), /No server could be reached/);
  assert.match(errMsg(new NetworkError('could not reach any server; the change may or may not have been saved', true)), /may or may not have been saved/);
});
