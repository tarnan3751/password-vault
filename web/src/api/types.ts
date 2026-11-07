// Wire types mirroring internal/api/types.go (the source of truth). `[]byte`
// fields are standard base64 WITH padding and appear here as `string`.
// Times are Unix milliseconds. Keep this file in sync with the Go file.

import type { WireKdf } from '../crypto/kdf.ts';

export type { WireKdf as KDFParams };

export const ErrorCodes = [
  'bad_request', 'unauthorized', 'forbidden', 'not_found', 'version_conflict', 'key_epoch_mismatch', 'already_exists',
  'invalid_invite', 'too_large', 'limit_exceeded', 'rate_limited', 'unavailable', 'outcome_unknown', 'internal',
] as const;
export type ErrorCode = (typeof ErrorCodes)[number];

export interface ErrorBody {
  error: { code: string; message: string; current_version?: number; retry_after_ms?: number };
}

export type Role = 'owner' | 'editor' | 'viewer';

export interface WrappedKey {
  sender_id: string;
  blob: string;
}

export interface HealthResponse {
  node_id: string;
  role: string;
  leader_id: string;
  term: number;
  commit_index: number;
  applied_index: number;
  initialized: boolean;
  has_users: boolean;
  version: string;
}

export interface ClusterNode {
  id: string;
  public_url: string;
}
export interface ClusterResponse {
  nodes: ClusterNode[];
  leader_id: string;
}

export interface PreloginRequest { username: string }
export interface PreloginResponse { kdf: WireKdf }

export interface CreateVaultRequest {
  vault_id: string;
  enc_meta: string;
  enc_roster: string;
  wrapped_key: WrappedKey;
}

export interface RegisterRequest {
  invite_code: string;
  user_id: string;
  username: string;
  kdf: WireKdf;
  login_key: string;
  public_key: string;
  wrapped_account_key: string;
  enc_private_key: string;
  personal_vault: CreateVaultRequest;
}

export interface LoginRequest { username: string; login_key: string }

export interface LoginResponse {
  token: string;
  expires_at: number;
  user_id: string;
  username: string;
  is_admin: boolean;
}

export interface Account {
  user_id: string;
  username: string;
  is_admin: boolean;
  kdf: WireKdf;
  public_key: string;
  wrapped_account_key: string;
  enc_private_key: string;
  created_at: number;
}

export interface DirectoryUser {
  user_id: string;
  username: string;
  public_key: string;
  is_admin: boolean;
  disabled: boolean;
}

export interface Member { user_id: string; role: Role; added_by: string }

export interface Item {
  id: string;
  version: number;
  blob: string;
  updated_at: number;
  updated_by: string;
}

export interface Vault {
  id: string;
  personal: boolean;
  key_epoch: number;
  enc_meta: string;
  meta_version: number;
  enc_roster: string;
  roster_version: number;
  rev: number;
  rekey_recommended: boolean;
  my_role: Role;
  my_key: WrappedKey;
  members: Member[];
  items: Item[];
}

export interface SyncResponse {
  rev: number;
  unchanged?: boolean;
  stale?: boolean;
  served_by?: string;
  account?: Account;
  directory?: DirectoryUser[];
  vaults?: Vault[];
}

export interface ChangePasswordRequest {
  current_login_key: string;
  new_kdf: WireKdf;
  new_login_key: string;
  new_wrapped_account_key: string;
}

export interface UpdateVaultMetaRequest { enc_meta: string; base_meta_version: number }
export interface PutMemberRequest { role: Role; wrapped_key?: WrappedKey; key_epoch: number; enc_roster: string; base_roster_version: number }
export interface RekeyItem { id: string; blob: string }
export interface RekeyRequest {
  base_rev: number;
  new_key_epoch: number;
  remove?: string[];
  enc_meta: string;
  enc_roster: string;
  wrapped_keys: Record<string, WrappedKey>;
  items: RekeyItem[];
}
export interface PutItemRequest { blob: string; base_version: number; key_epoch: number }
export interface MutationResponse { rev: number; version?: number }

export interface CreateInviteRequest { ttl_hours: number }
export interface CreateInviteResponse { invite_id: string; code: string; expires_at: number }
export interface Invite { invite_id: string; created_by: string; created_at: number; expires_at: number; used_by?: string }
export interface ListInvitesResponse { invites: Invite[] }
export interface AdminUpdateUserRequest { disabled?: boolean; is_admin?: boolean }

export interface AdminPeerStatus { id: string; match_index: number; last_contact_ms: number }
export interface AdminClusterResponse {
  node_id: string;
  role: string;
  leader_id: string;
  term: number;
  commit_index: number;
  applied_index: number;
  last_log_index: number;
  snapshot_index: number;
  rev: number;
  peers?: AdminPeerStatus[];
}
