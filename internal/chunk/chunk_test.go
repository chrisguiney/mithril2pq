package chunk

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// preprod-00000.tar.zst is Preprod's immutable file 0 as Mithril serves it.
// It starts with an epoch boundary block. The digests are from the
// snapshot's certified digest list.
var preprod0 = Digests{
	Chunk:     "836a1ba1c349e99dbaa470029dd5cd7260013084759bc5f8df4bcbbd18c7250b",
	Primary:   "c9f5fdd0130909b44faabc6d5b052aa2434ba879fe50bbcd17d169701841f917",
	Secondary: "78712484b1036062ec5f9a571ffdb1fb9fbe96588aecf7bf662d198f5d490dfb",
}

func readFixture(t *testing.T) Files {
	t.Helper()
	f, err := os.Open("testdata/preprod-00000.tar.zst")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	files, err := ReadArchive(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestBlocks(t *testing.T) {
	files := readFixture(t)
	if err := files.Verify(preprod0); err != nil {
		t.Fatal(err)
	}
	blocks, err := Blocks(files)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) < 2 {
		t.Fatalf("%d blocks", len(blocks))
	}
	ebb := blocks[0]
	if !ebb.IsEbb || ebb.Type != 0 || ebb.SlotOrEpoch != 0 {
		t.Errorf("first block: ebb %v type %d slot/epoch %d", ebb.IsEbb, ebb.Type, ebb.SlotOrEpoch)
	}
	for _, b := range blocks[1:] {
		if b.IsEbb || b.Type != 1 {
			t.Errorf("block %d: ebb %v type %d", b.Index, b.IsEbb, b.Type)
		}
	}
	var end uint64
	for _, b := range blocks {
		if b.BlockOffset != end {
			t.Errorf("block %d at %d, previous ended at %d", b.Index, b.BlockOffset, end)
		}
		end = b.BlockOffset + b.BlockSize
	}
	if end != uint64(len(files.Chunk)) {
		t.Errorf("blocks end at %d of %d bytes", end, len(files.Chunk))
	}
}

func TestBlocksDetectsCorruption(t *testing.T) {
	files := readFixture(t)
	blocks, err := Blocks(files)
	if err != nil {
		t.Fatal(err)
	}
	files.Chunk = append([]byte(nil), files.Chunk...)
	files.Chunk[blocks[1].BlockOffset+blocks[1].BlockSize/2] ^= 0xff
	if _, err := Blocks(files); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "CRC32") {
		t.Fatalf("flipped byte: err %v", err)
	}
	if err := files.Verify(preprod0); err == nil {
		t.Fatal("flipped byte passed digest verification")
	}
}

func TestBlocksRejectsBadIndexes(t *testing.T) {
	files := readFixture(t)
	bad := files
	bad.Secondary = files.Secondary[:len(files.Secondary)-1]
	if _, err := Blocks(bad); !errors.Is(err, ErrCorrupt) {
		t.Errorf("truncated secondary: err %v", err)
	}
	bad = files
	bad.Primary = append([]byte{2}, files.Primary[1:]...)
	if _, err := Blocks(bad); !errors.Is(err, ErrCorrupt) {
		t.Errorf("primary version 2: err %v", err)
	}
	bad = files
	bad.Secondary = files.Secondary[:len(files.Secondary)-secondaryEntrySize]
	if _, err := Blocks(bad); !errors.Is(err, ErrCorrupt) {
		t.Errorf("secondary shorter than the primary says: err %v", err)
	}
}
