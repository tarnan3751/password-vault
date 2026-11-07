import { ApiError, NetworkError } from '../api/index.ts';
import { BackupError, DecryptError, KdfParamsError, ItemFormatError } from '../crypto/index.ts';
import { VaultError } from '../vault/index.ts';

/**
 * Turns any thrown value into text for the user. Never includes secrets:
 * the underlying errors do not carry any, and unknown errors are replaced by a
 * generic message instead of echoing arbitrary text.
 */
export function errMsg(e: unknown): string {
  if (e instanceof VaultError || e instanceof BackupError || e instanceof KdfParamsError) return e.message;
  if (e instanceof NetworkError) {
    if (e.outcomeUnknown) return 'The servers did not answer in time. The change may or may not have been saved; check before trying again.';
    return e.message.includes('unreadable') ? 'The server sent an answer this app could not read. Try again; if it keeps happening, tell your administrator.' : 'No server could be reached. Check your connection and that the servers are running, then try again.';
  }
  if (e instanceof DecryptError) return 'It could not be decrypted: the password or passphrase is wrong, or the data is damaged.';
  if (e instanceof ItemFormatError) return 'This entry is in a format this version cannot read.';
  if (e instanceof ApiError) {
    switch (e.code) {
      case 'rate_limited':
        return `Too many attempts. Try again in ${Math.max(1, Math.ceil((e.retryAfterMs ?? 30_000) / 1000))} seconds.`;
      case 'unavailable':
        return 'Nothing was saved: a majority of the servers cannot be reached right now. Try again in a moment.';
      case 'outcome_unknown':
        return 'The servers did not confirm the change in time. It may or may not have been saved; check before trying again.';
      case 'unauthorized':
        return 'Please sign in again.';
      case 'forbidden':
        return pick(FORBIDDEN, e.message, 'You are not allowed to do that.');
      case 'not_found':
        return 'That no longer exists (or you do not have access to it).';
      case 'too_large':
        return 'That is too large for the server to accept. Shorten it (for an entry, trim long notes) and try again.';
      case 'limit_exceeded':
        return pick(LIMITS, e.message, 'A limit of this household was reached. Remove something you no longer need and try again.');
      case 'already_exists':
        return /already a member/.test(e.message) ? 'That person is already in this vault.' : 'That name is already taken. Choose another one.';
      case 'invalid_invite':
        return 'That invite code is not valid. It may have been used already, withdrawn or expired. Ask for a new one.';
      case 'version_conflict':
      case 'key_epoch_mismatch':
        return 'Someone else changed this at the same time. It has been reloaded; please try again.';
      case 'internal':
        return 'The server had a problem and did not finish. Try again in a moment; if it keeps happening, tell your administrator.';
      default: // bad_request and anything newer than this app
        return 'The server did not accept that request. Reload the page and try again; if it keeps happening, tell your administrator.';
    }
  }
  return 'Something went wrong. Please try again.';
}

/** The server words these refusals for developers (api.md names no stable code for the cause), so they are recognised by their text and told in plain words. */
const pick = (table: [RegExp, string][], message: string, fallback: string) => table.find(([re]) => re.test(message))?.[1] ?? fallback;

const FORBIDDEN: [RegExp, string][] = [
  [/last enabled admin/, 'You cannot do that to the last administrator. Make someone else an administrator first.'],
  [/last owner/, 'A vault must keep at least one owner. Make someone else an owner first.'],
  [/viewers cannot/, 'You can view this vault but not change it. An owner of the vault can make you an editor.'],
  [/only owners/, 'Only an owner of this vault can do that.'],
  [/only admins/, 'Only an administrator can do that.'],
  [/personal vault/, 'A personal vault is only for you: it cannot be shared or deleted.'],
];

const LIMITS: [RegExp, string][] = [
  [/vault storage quota/, 'This vault is full. Delete entries you no longer need, or keep new ones in another vault.'],
  [/per-user storage quota/, 'The vaults created by this person are full. Delete entries you no longer need, or ask the vault’s owner to make room.'],
  [/household storage quota/, 'The household’s storage is full. Delete entries or vaults you no longer need.'],
  [/item limit/, 'This vault holds as many entries as it can. Delete some or keep new ones in another vault.'],
  [/maximum number of users/, 'The household already has as many people as it can hold, so nobody else can join.'],
  [/pending invites/, 'There are too many unused invite codes. Withdraw some in Administration, then try again.'],
  [/vault limit/, 'You have created as many vaults as are allowed. Delete one you no longer use first.'],
];
