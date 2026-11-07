// Package vaultcrypto implements the client-side cryptography of Family Vault
// exactly as specified in docs/spec/crypto.md (suite "fpv/v1").
//
// Everything here must agree byte for byte with the browser implementation;
// testvectors/crypto-v1.json proves that. Primitives come from the Go standard
// library and golang.org/x/crypto; nothing is hand-rolled.
//
// Key-holding types (SymmetricKey, PrivateKey, MasterKeys, AccountSecrets)
// redact themselves when formatted and refuse JSON encoding so that secrets
// do not leak into logs by accident.
package vaultcrypto
