//go:build !unix

package chaos

import "errors"

// ProcsConfig configures a cluster of real vaultd processes (Unix only:
// process groups and SIGKILL/SIGSTOP/SIGCONT are the point of the mode).
type ProcsConfig struct {
	Nodes             int
	Dir               string
	VaultdBin         string
	TLS               bool
	TickMs            int
	ElectionTicks     int
	SnapshotThreshold uint64
	BootstrapToken    string
	Seed              int64
	LogLevel          string
}

// StartProcs is not available on this platform.
func StartProcs(ProcsConfig) (Cluster, error) {
	return nil, errors.New("process mode needs a Unix system (process groups, SIGKILL/SIGSTOP)")
}
