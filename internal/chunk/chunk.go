// Package chunk reads one ImmutableDB chunk (the NNNNN.chunk, .primary and
// .secondary triplet) from memory and yields its blocks.
//
// Layout, as written by ouroboros-consensus:
//
//   - .primary: a version byte (1), then one big-endian uint32 per relative
//     slot of the chunk, plus one final entry. Entry i is the offset in
//     .secondary of slot i's record; slot i is filled when entry i+1 is
//     greater than entry i. Relative slot 0 is reserved for an epoch
//     boundary block (EBB).
//   - .secondary: 56-byte big-endian records, one per block in chunk order:
//     block offset (u64), header offset (u16), header size (u16), CRC32 of
//     the block bytes (u32), header hash (32 bytes), and the block's slot -
//     or, for an EBB, its epoch (u64).
//   - .chunk: the blocks back to back, each wrapped as CBOR [type, block].
package chunk

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"

	"github.com/blinklabs-io/gouroboros/cbor"
)

const secondaryEntrySize = 56

// Files is one chunk's triplet.
type Files struct {
	Chunk, Primary, Secondary []byte
}

// Digests holds the expected SHA-256 of each file, hex encoded, as the
// Mithril digest list gives them.
type Digests struct {
	Chunk, Primary, Secondary string
}

// Verify checks each file against its certified SHA-256 digest.
func (f Files) Verify(d Digests) error {
	for _, c := range []struct {
		name string
		data []byte
		want string
	}{{"chunk", f.Chunk, d.Chunk}, {"primary", f.Primary, d.Primary}, {"secondary", f.Secondary, d.Secondary}} {
		if c.want == "" {
			return fmt.Errorf("no certified digest for the .%s file", c.name)
		}
		sum := sha256.Sum256(c.data)
		if got := hex.EncodeToString(sum[:]); got != c.want {
			return fmt.Errorf(".%s file SHA-256 is %s, the snapshot certifies %s", c.name, got, c.want)
		}
	}
	return nil
}

// Block is one block as stored in the chunk.
type Block struct {
	Index        int
	Hash         [32]byte
	BlockOffset  uint64
	BlockSize    uint64
	HeaderOffset uint16
	HeaderSize   uint16
	Checksum     uint32
	// SlotOrEpoch is the slot, or the epoch for an EBB.
	SlotOrEpoch uint64
	IsEbb       bool
	// Type is the block-type tag from the [type, block] wrapper.
	Type uint
	// Cbor is the block without the wrapper.
	Cbor []byte
}

// ErrCorrupt marks a structural or checksum failure in the chunk files.
var ErrCorrupt = errors.New("corrupt chunk")

// Blocks parses the triplet. Every block's CRC32 is checked against the
// secondary index, and the EBB flag from the primary index is checked
// against the block's type tag.
func Blocks(f Files) ([]Block, error) {
	if len(f.Secondary)%secondaryEntrySize != 0 {
		return nil, fmt.Errorf("%w: secondary index is %d bytes, not a multiple of %d", ErrCorrupt, len(f.Secondary), secondaryEntrySize)
	}
	n := len(f.Secondary) / secondaryEntrySize
	ebb, err := firstSlotFilled(f.Primary, len(f.Secondary))
	if err != nil {
		return nil, err
	}
	blocks := make([]Block, n)
	for i := range n {
		rec := f.Secondary[i*secondaryEntrySize : (i+1)*secondaryEntrySize]
		b := &blocks[i]
		b.Index = i
		b.BlockOffset = binary.BigEndian.Uint64(rec[0:8])
		b.HeaderOffset = binary.BigEndian.Uint16(rec[8:10])
		b.HeaderSize = binary.BigEndian.Uint16(rec[10:12])
		b.Checksum = binary.BigEndian.Uint32(rec[12:16])
		copy(b.Hash[:], rec[16:48])
		b.SlotOrEpoch = binary.BigEndian.Uint64(rec[48:56])
		b.IsEbb = i == 0 && ebb
	}
	for i := range blocks {
		b := &blocks[i]
		end := uint64(len(f.Chunk))
		if i+1 < n {
			end = blocks[i+1].BlockOffset
		}
		if b.BlockOffset >= end || end > uint64(len(f.Chunk)) {
			return nil, fmt.Errorf("%w: block %d spans [%d, %d) in a %d-byte chunk file", ErrCorrupt, i, b.BlockOffset, end, len(f.Chunk))
		}
		raw := f.Chunk[b.BlockOffset:end]
		b.BlockSize = end - b.BlockOffset
		if got := crc32.ChecksumIEEE(raw); got != b.Checksum {
			return nil, fmt.Errorf("%w: block %d (%x) CRC32 is %08x, the secondary index records %08x", ErrCorrupt, i, b.Hash, got, b.Checksum)
		}
		var wrapped struct {
			cbor.StructAsArray
			Type uint
			Cbor cbor.RawMessage
		}
		if _, err := cbor.Decode(raw, &wrapped); err != nil {
			return nil, fmt.Errorf("%w: block %d (%x) has no [type, block] wrapper: %v", ErrCorrupt, i, b.Hash, err)
		}
		b.Type = wrapped.Type
		b.Cbor = wrapped.Cbor
		if b.IsEbb != (b.Type == 0) {
			return nil, fmt.Errorf("%w: block %d (%x) has type %d but the primary index says EBB=%v", ErrCorrupt, i, b.Hash, b.Type, b.IsEbb)
		}
	}
	return blocks, nil
}

// firstSlotFilled reports whether relative slot 0 (the EBB slot) holds a
// block, after checking the primary index is well formed and agrees with
// the secondary index's size.
func firstSlotFilled(primary []byte, secondarySize int) (bool, error) {
	if len(primary) < 1 || primary[0] != 1 {
		return false, fmt.Errorf("%w: primary index has no version 1 header", ErrCorrupt)
	}
	body := primary[1:]
	if len(body)%4 != 0 || len(body) < 8 {
		return false, fmt.Errorf("%w: primary index body is %d bytes", ErrCorrupt, len(body))
	}
	var prev uint32
	for i := 0; i < len(body); i += 4 {
		off := binary.BigEndian.Uint32(body[i:])
		if off < prev || off%secondaryEntrySize != 0 {
			return false, fmt.Errorf("%w: primary index entry %d (%d) is not an aligned, non-decreasing secondary offset", ErrCorrupt, i/4, off)
		}
		prev = off
	}
	if int(prev) != secondarySize {
		return false, fmt.Errorf("%w: primary index ends at secondary offset %d, secondary index is %d bytes", ErrCorrupt, prev, secondarySize)
	}
	return binary.BigEndian.Uint32(body[4:]) > binary.BigEndian.Uint32(body[0:]), nil
}
