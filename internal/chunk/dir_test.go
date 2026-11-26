package chunk

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func touch(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The highest-numbered chunk is still being appended to, so chunk N is
// final only once N+1 exists.
func TestLastFinished(t *testing.T) {
	for _, c := range []struct {
		name  string
		files []string
		want  int64
	}{
		{"empty", nil, -1},
		{"one chunk, still open", []string{"00000.chunk", "00000.primary", "00000.secondary"}, -1},
		{"two chunks", []string{"00000.chunk", "00001.chunk"}, 0},
		{"three chunks", []string{"00000.chunk", "00001.chunk", "00002.chunk", "00002.primary"}, 1},
		{"unrelated files ignored", []string{"00000.chunk", "00001.chunk", "clean", "lock", "00009.tmp"}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			touch(t, dir, c.files...)
			got, err := LastFinished(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("LastFinished = %d, want %d", got, c.want)
			}
		})
	}
	if _, err := LastFinished(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing directory: no error")
	}
}

func TestReadDirAndSum(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir, "00007.chunk", "00007.primary", "00007.secondary")
	f, err := ReadDir(dir, 7)
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Chunk) != "00007.chunk" || string(f.Primary) != "00007.primary" || string(f.Secondary) != "00007.secondary" {
		t.Errorf("files read wrong: %q %q %q", f.Chunk, f.Primary, f.Secondary)
	}
	want := sha256.Sum256([]byte("00007.primary"))
	if got := f.Sum().Primary; got != hex.EncodeToString(want[:]) {
		t.Errorf("Sum().Primary = %s", got)
	}
	if err := f.Verify(f.Sum()); err != nil {
		t.Errorf("computed digests do not verify: %v", err)
	}
	if _, err := ReadDir(dir, 8); err == nil {
		t.Error("absent chunk: no error")
	}
}

// A devnet whose first era is not Byron-with-EBBs still uses the chunk
// geometry of ouroboros-consensus: cardano-node sizes chunks by the first
// era's epoch (10k slots, 50 for k=5), not by the 500-slot Shelley epoch, and
// the primary index holds one entry per relative slot, the EBB slot, and the
// end. testdata/devnet is chunks 0-4 of a cardano-node 11.1.3 devnet with
// k=5, f=0.05, 500-slot epochs, from `continuum-genesis`.
func TestDevnetGeometry(t *testing.T) {
	const slots = 50
	for n := uint64(0); n < 5; n++ {
		files, err := ReadDir("testdata/devnet", n)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := len(files.Primary), 1+4*(slots+2); got != want {
			t.Errorf("chunk %d: primary is %d bytes, want %d (%d slots + EBB slot + end)", n, got, want, slots)
		}
		blocks, err := Blocks(files)
		if err != nil {
			t.Fatalf("chunk %d: %v", n, err)
		}
		if len(blocks) == 0 {
			t.Fatalf("chunk %d: no blocks", n)
		}
		filled := map[uint64]bool{}
		for i, b := range blocks {
			if b.IsEbb {
				t.Errorf("chunk %d block %d: EBB in a chain with no Byron blocks", n, i)
			}
			if rel := b.SlotOrEpoch - n*slots; b.SlotOrEpoch < n*slots || rel >= slots {
				t.Fatalf("chunk %d block %d: slot %d outside [%d, %d)", n, i, b.SlotOrEpoch, n*slots, (n+1)*slots)
			}
			filled[b.SlotOrEpoch-n*slots+1] = true
		}
		// Independent read of the primary index: relative slot r is filled
		// when entry r+1 exceeds entry r; relative slot 0 is the EBB slot.
		body := files.Primary[1:]
		entry := func(i int) uint32 { return binary.BigEndian.Uint32(body[4*i:]) }
		for r := range uint64(slots + 1) {
			if got := entry(int(r)+1) > entry(int(r)); got != filled[r] {
				t.Errorf("chunk %d relative slot %d: primary says filled=%v, secondary says %v", n, r, got, filled[r])
			}
		}
	}
}
