package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/fsm"
	"github.com/tarnan3751/password-vault/internal/raft"
	"github.com/tarnan3751/password-vault/internal/raft/filestore"
)

// cmdRestore seeds an empty data directory with a server backup, as a Raft
// snapshot at index rev+1, term 1.
//
// Disaster recovery procedure: stop every node, move the old data
// directories aside, run `vaultd restore` with the SAME backup file on every
// node (at the very least on a majority) and only then start them. A node
// that starts empty next to restored ones will simply receive the snapshot,
// but if a majority starts empty they can elect a leader with an empty log
// and the restored state would be discarded.
func cmdRestore(args []string) error {
	fs := newFlagSet("restore", "--config FILE --from BACKUP",
		`Load a server backup into this server's EMPTY data directory. This is for
disaster recovery only: stop every server, move the old data directories
aside, run this with the SAME backup file on every server, check that they
all print the same state digest, then start them again
(docs/OPERATIONS.md, "When things break").`)
	configPath := fs.String("config", "", "this server's config.json `file` (required)")
	from := fs.String("from", "", "server backup `file`, made by \"fvault admin backup\" or found in <data_dir>/backups (required)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *configPath == "" || *from == "" {
		return errors.New("restore: --config and --from are required")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*from)
	if err != nil {
		return err
	}
	var b api.ServerBackup
	if err := json.Unmarshal(raw, &b); err != nil {
		return fmt.Errorf("%s is not a server backup: %w", *from, err)
	}
	if b.Format != "fpv-server-backup" {
		return fmt.Errorf("%s is not a server backup (format %q). Encrypted user exports are restored with `fvault import`", *from, b.Format)
	}
	if b.Version != 1 {
		return fmt.Errorf("unsupported server backup version %d", b.Version)
	}
	if err := fsm.ValidateSnapshot(b.State); err != nil {
		return fmt.Errorf("backup state is invalid: %w", err)
	}

	store, err := filestore.Open(filepath.Join(cfg.DataDir, "raft"), filestore.Options{})
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	defer store.Close()
	hs, snap, entries, err := store.Load()
	if err != nil {
		return fmt.Errorf("load storage: %w", err)
	}
	if hs != (raft.HardState{}) || snap != nil || len(entries) != 0 {
		return fmt.Errorf("refusing to restore: %s already contains Raft state. Move it aside first", filepath.Join(cfg.DataDir, "raft"))
	}
	// The snapshot is placed at log index rev+1 rather than a constant. If
	// the operator mistakenly restores DIFFERENT backups on different nodes,
	// they then hold snapshots at different indices: Raft's up-to-date rule
	// lets only the node with the newest state win an election, and it
	// overwrites the others with its snapshot. With a constant index the
	// replicas would instead diverge silently.
	index := b.Rev + 1
	// Snapshot first, then the term: if we crash in between, the directory
	// holds a snapshot with term 0 hard state, which is still a consistent
	// (if unusual) starting point, and re-running restore is refused rather
	// than silently mixing two backups.
	if err := store.InstallSnapshot(raft.Snapshot{Meta: raft.SnapshotMeta{Index: index, Term: 1}, Data: b.State}); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	if err := store.SaveHardState(raft.HardState{Term: 1}); err != nil {
		return fmt.Errorf("write hard state: %w", err)
	}
	digest := sha256.Sum256(b.State)
	fmt.Printf("Restored backup (rev %d, taken on node %q) into %s.\n", b.Rev, b.NodeID, cfg.DataDir)
	fmt.Printf("State digest: %s\n", hex.EncodeToString(digest[:]))
	fmt.Println("Restore the same file on the other nodes BEFORE starting any of them, and check that every node prints the same digest.")
	return nil
}
