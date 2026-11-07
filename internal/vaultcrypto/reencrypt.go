package vaultcrypto

// Raw re-encryption for rekeying (crypto.md §5.3, §6.6): a box that opens
// under the old key and epoch is re-sealed from its RAW plaintext bytes
// (padding included, nothing parsed) under the new key and epoch. A box that
// does not open is reported as opened == false and the caller carries the
// original blob over unchanged (it was garbage and stays garbage).

func reencrypt(oldVK, newVK *SymmetricKey, oldAAD, newAAD, blob, nonce []byte) ([]byte, bool, error) {
	pt, err := Open(oldVK, blob, oldAAD)
	if err != nil {
		return blob, false, nil
	}
	defer Zero(pt)
	var out []byte
	if nonce == nil {
		out, err = Seal(newVK, pt, newAAD)
	} else {
		out, err = SealWithNonce(newVK, nonce, pt, newAAD)
	}
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func reencryptArgs(vaultID string, oldEpoch, newEpoch uint32, itemID *string) error {
	if err := checkArgs(oldEpoch, vaultID); err != nil {
		return err
	}
	if itemID != nil {
		if err := checkIDs(*itemID); err != nil {
			return err
		}
	}
	return checkEpoch(newEpoch)
}

// ReencryptItem re-seals an item blob under newVK at newEpoch.
func ReencryptItem(oldVK, newVK *SymmetricKey, vaultID, itemID string, oldEpoch, newEpoch uint32, blob []byte) (newBlob []byte, opened bool, err error) {
	return ReencryptItemWithNonce(oldVK, newVK, vaultID, itemID, oldEpoch, newEpoch, blob, nil)
}

// ReencryptItemWithNonce is ReencryptItem with a fixed nonce (nil: a random
// one). For test vectors only.
func ReencryptItemWithNonce(oldVK, newVK *SymmetricKey, vaultID, itemID string, oldEpoch, newEpoch uint32, blob, nonce []byte) ([]byte, bool, error) {
	if err := reencryptArgs(vaultID, oldEpoch, newEpoch, &itemID); err != nil {
		return nil, false, err
	}
	return reencrypt(oldVK, newVK, ItemAAD(vaultID, itemID, oldEpoch), ItemAAD(vaultID, itemID, newEpoch), blob, nonce)
}

// ReencryptMeta re-seals an encMeta blob under newVK at newEpoch.
func ReencryptMeta(oldVK, newVK *SymmetricKey, vaultID string, oldEpoch, newEpoch uint32, blob []byte) (newBlob []byte, opened bool, err error) {
	return ReencryptMetaWithNonce(oldVK, newVK, vaultID, oldEpoch, newEpoch, blob, nil)
}

// ReencryptMetaWithNonce is ReencryptMeta with a fixed nonce (nil: a random
// one). For test vectors only.
func ReencryptMetaWithNonce(oldVK, newVK *SymmetricKey, vaultID string, oldEpoch, newEpoch uint32, blob, nonce []byte) ([]byte, bool, error) {
	if err := reencryptArgs(vaultID, oldEpoch, newEpoch, nil); err != nil {
		return nil, false, err
	}
	return reencrypt(oldVK, newVK, VaultMetaAAD(vaultID, oldEpoch), VaultMetaAAD(vaultID, newEpoch), blob, nonce)
}
