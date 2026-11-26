package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/chrisguiney/mithril2pq/internal/chunk"
)

// knownMagics names the public networks, so a dataset converted from a local
// node's database and one converted from the matching Mithril snapshot agree
// on the network and can be updated from either source.
var knownMagics = map[int64]string{
	764824073: "mainnet",
	1:         "preprod",
	2:         "preview",
}

// localNetwork is the manifest's network name for a protocol magic.
func localNetwork(magic int64) string {
	if name, ok := knownMagics[magic]; ok {
		return name
	}
	return fmt.Sprintf("magic-%d", magic)
}

// validateLocal checks the flags that go with -immutable-dir.
func validateLocal(cfg *config) error {
	for _, c := range []struct {
		flag string
		set  bool
	}{
		{"-mithril-archive", cfg.archive != ""},
		{"-snapshot", cfg.snapshot != ""},
		{"-cache-dir", cfg.cacheDir != ""},
		{"-genesis-vkey", cfg.genesisKeyArg != ""},
	} {
		if c.set {
			return fmt.Errorf("-immutable-dir reads a node's database, not a Mithril aggregator; it cannot be combined with %s", c.flag)
		}
	}
	if cfg.networkMagic < 0 || cfg.networkMagic > math.MaxUint32 {
		return errors.New("-network-magic (0 to 4294967295) is required with -immutable-dir: a node's database does not name its network, and the output directory refuses data from another network")
	}
	return nil
}

// loadLocal plans a run over a node's ImmutableDB directory. Only finished
// chunks are read. With no aggregator to certify digests, the manifest's
// last-chunk digests are computed from the files, so a later run still
// detects a directory that no longer continues the dataset's chain.
func (r *runner) loadLocal() error {
	r.network = localNetwork(r.cfg.networkMagic)
	last, err := chunk.LastFinished(r.cfg.immutableDir)
	if err != nil {
		return err
	}
	r.last = last
	r.prog.logf("local ImmutableDB %s: network %s, finished chunks 0..%d (the newest chunk is still being written and is skipped)", r.cfg.immutableDir, r.network, last)

	m := r.ds.Manifest
	r.digests = map[string]string{}
	if m == nil || m.LastChunk < 0 || m.LastChunk > last {
		return nil
	}
	f, err := chunk.ReadDir(r.cfg.immutableDir, uint64(m.LastChunk))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s has no immutable file %d, the last one in %s: %w", filepath.Base(r.cfg.immutableDir), m.LastChunk, r.cfg.out, err)
	}
	if err != nil {
		return err
	}
	r.digests = digestMap(uint64(m.LastChunk), f.Sum())
	return nil
}
