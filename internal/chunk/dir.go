package chunk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// LastFinished returns the number of the last chunk in a node's ImmutableDB
// directory that is safe to read, or -1 if there is none. The node appends
// to the highest-numbered chunk, so chunk N is final only once chunk N+1 has
// a file.
func LastFinished(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return -1, fmt.Errorf("listing immutable directory: %w", err)
	}
	highest := int64(-1)
	for _, e := range entries {
		num, ok := strings.CutSuffix(e.Name(), ".chunk")
		if !ok || len(num) != 5 {
			continue
		}
		n, err := strconv.ParseInt(num, 10, 64)
		if err != nil {
			continue
		}
		highest = max(highest, n)
	}
	return max(highest-1, -1), nil
}

// ReadDir reads chunk number's three files from a node's ImmutableDB
// directory.
func ReadDir(dir string, number uint64) (Files, error) {
	var f Files
	for ext, dst := range map[string]*[]byte{"chunk": &f.Chunk, "primary": &f.Primary, "secondary": &f.Secondary} {
		b, err := os.ReadFile(filepath.Join(dir, FileName(number, ext)))
		if err != nil {
			return Files{}, fmt.Errorf("reading immutable file %d: %w", number, err)
		}
		*dst = b
	}
	return f, nil
}

// Sum computes the SHA-256 digests of the files. Mithril's certified digests
// are the same hash of the same bytes, so a computed Digests can stand in for
// them when there is no aggregator.
func (f Files) Sum() Digests {
	h := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	return Digests{Chunk: h(f.Chunk), Primary: h(f.Primary), Secondary: h(f.Secondary)}
}
