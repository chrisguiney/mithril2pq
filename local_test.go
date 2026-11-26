package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chrisguiney/mithril2pq/internal/chunk"
	"github.com/chrisguiney/mithril2pq/internal/dataset"
)

func baseConfig() config {
	return config{out: "o", fileSize: 128_000_000, concurrency: 1, buffer: 1, workers: 1, compression: "zstd", lastChunk: -1, networkMagic: -1}
}

func TestValidateLocalSource(t *testing.T) {
	ok := baseConfig()
	ok.immutableDir, ok.networkMagic = "imm", 42
	if err := validate(&ok); err != nil {
		t.Fatalf("valid local config: %v", err)
	}

	for _, c := range []struct {
		name string
		edit func(*config)
		want string
	}{
		{"exclusive with -mithril-archive", func(c *config) { c.archive = "preprod" }, "-mithril-archive"},
		{"needs -network-magic", func(c *config) { c.networkMagic = -1 }, "-network-magic"},
		{"magic out of range", func(c *config) { c.networkMagic = 1 << 32 }, "-network-magic"},
		{"exclusive with -snapshot", func(c *config) { c.snapshot = "abc" }, "-snapshot"},
		{"exclusive with -cache-dir", func(c *config) { c.cacheDir = "c" }, "-cache-dir"},
		{"exclusive with -genesis-vkey", func(c *config) { c.genesisKeyArg = "k" }, "-genesis-vkey"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := ok
			c.edit(&cfg)
			err := validate(&cfg)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want mention of %s", err, c.want)
			}
		})
	}
}

func TestNetworkMagicWithoutImmutableDir(t *testing.T) {
	cfg := baseConfig()
	cfg.archive, cfg.networkMagic = "mainnet", 1
	if err := validate(&cfg); err == nil || !strings.Contains(err.Error(), "-immutable-dir") {
		t.Errorf("err = %v", err)
	}
}

func TestArchiveDefaultsToMainnet(t *testing.T) {
	cfg := baseConfig()
	if err := validate(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.archive != "mainnet" {
		t.Errorf("archive = %q", cfg.archive)
	}
}

const devnetDir = "internal/chunk/testdata/devnet"

const devnetMagic = 42

// copyChunks copies the devnet fixture's chunk src to chunk dst in dir.
func copyChunks(t *testing.T, dir string, src, dst int) {
	t.Helper()
	for _, ext := range []string{"chunk", "primary", "secondary"} {
		b, err := os.ReadFile(filepath.Join(devnetDir, chunk.FileName(uint64(src), ext)))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, chunk.FileName(uint64(dst), ext)), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func runLocal(t *testing.T, imm, out string, magic int64) (*stats, error) {
	t.Helper()
	cfg := baseConfig()
	cfg.immutableDir, cfg.out, cfg.networkMagic = imm, out, magic
	cfg.workers, cfg.concurrency, cfg.buffer = 2, 2, 2
	if err := validate(&cfg); err != nil {
		t.Fatal(err)
	}
	st := &stats{start: time.Now()}
	prog := newProgress(st, io.Discard, false)
	err := run(context.Background(), make(chan struct{}), cfg, st, prog)
	return st, err
}

func readManifest(t *testing.T, out string) dataset.Manifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(out, dataset.ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var m dataset.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func sha(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// A growing node database: each run converts the chunks finished since the
// last one, the open chunk is never read, and the manifest's computed digests
// carry the continuity check across runs.
func TestLocalSourceGrows(t *testing.T) {
	imm, out := t.TempDir(), t.TempDir()
	copyChunks(t, imm, 0, 0)
	copyChunks(t, imm, 1, 1)
	// The open chunk: files mid-write, unreadable as blocks.
	for _, ext := range []string{"chunk", "primary", "secondary"} {
		if err := os.WriteFile(filepath.Join(imm, chunk.FileName(2, ext)), []byte("partial"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	st, err := runLocal(t, imm, out, devnetMagic)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.chunksWritten.Load(); got != 2 {
		t.Errorf("first run wrote %d chunks, want 2 (0 and 1)", got)
	}
	m := readManifest(t, out)
	if m.LastChunk != 1 || m.Network != "magic-42" || m.Aggregator != "" {
		t.Errorf("manifest: last chunk %d, network %q, aggregator %q", m.LastChunk, m.Network, m.Aggregator)
	}
	for _, ext := range []string{"chunk", "primary", "secondary"} {
		name := chunk.FileName(1, ext)
		if want := sha(t, filepath.Join(imm, name)); m.LastChunkDigests[name] != want {
			t.Errorf("%s digest %q, want computed %q", name, m.LastChunkDigests[name], want)
		}
	}

	// The node moves on: chunk 2 is finished, 3 and 4 exist, 4 is open.
	copyChunks(t, imm, 2, 2)
	copyChunks(t, imm, 3, 3)
	copyChunks(t, imm, 4, 4)
	st, err = runLocal(t, imm, out, devnetMagic)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.chunksWritten.Load(); got != 2 {
		t.Errorf("second run wrote %d chunks, want 2 (2 and 3)", got)
	}
	if m = readManifest(t, out); m.LastChunk != 3 {
		t.Errorf("last chunk %d, want 3", m.LastChunk)
	}

	st, err = runLocal(t, imm, out, devnetMagic)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.chunksWritten.Load(); got != 0 {
		t.Errorf("unchanged directory: wrote %d chunks", got)
	}
}

func TestLocalSourceRefusesOtherNetwork(t *testing.T) {
	imm, out := t.TempDir(), t.TempDir()
	copyChunks(t, imm, 0, 0)
	copyChunks(t, imm, 1, 1)
	if _, err := runLocal(t, imm, out, devnetMagic); err != nil {
		t.Fatal(err)
	}
	_, err := runLocal(t, imm, out, 764824073)
	if err == nil || !strings.Contains(err.Error(), "holds magic-42 data") {
		t.Errorf("err = %v, want a refusal naming magic-42", err)
	}
}

// The computed digests of the last chunk converted must still match the
// directory, or the dataset and the node's database are different chains.
func TestLocalSourceDetectsRewrittenChunk(t *testing.T) {
	imm, out := t.TempDir(), t.TempDir()
	for n := range 3 {
		copyChunks(t, imm, n, n)
	}
	if _, err := runLocal(t, imm, out, devnetMagic); err != nil {
		t.Fatal(err)
	}
	copyChunks(t, imm, 3, 1)
	copyChunks(t, imm, 3, 3)
	_, err := runLocal(t, imm, out, devnetMagic)
	if err == nil || !strings.Contains(err.Error(), "different chain") {
		t.Errorf("err = %v, want a different-chain refusal", err)
	}
}

// The previous-hash check on the first new block still applies: chunk 4
// does not follow chunk 1.
func TestLocalSourceChecksPreviousHash(t *testing.T) {
	imm, out := t.TempDir(), t.TempDir()
	copyChunks(t, imm, 0, 0)
	copyChunks(t, imm, 1, 1)
	if _, err := runLocal(t, imm, out, devnetMagic); err != nil {
		t.Fatal(err)
	}
	copyChunks(t, imm, 4, 2)
	copyChunks(t, imm, 3, 3)
	_, err := runLocal(t, imm, out, devnetMagic)
	if err == nil || !strings.Contains(err.Error(), "does not continue the chain") {
		t.Errorf("err = %v, want a broken-chain refusal", err)
	}
}
