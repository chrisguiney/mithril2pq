// SPDX-License-Identifier: Apache-2.0

package stm

import (
	"errors"
	"testing"
)

func testLeaves(t *testing.T, n int) []Leaf {
	t.Helper()
	rng := NewChaChaRNG([32]byte{1})
	out := make([]Leaf, n)
	for i := range out {
		sk, err := GenerateSigningKey(rng)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = Leaf{VK: sk.VerificationKey(), Stake: uint64(i + 1)}
	}
	return out
}

// TestBatchPathRoundTrip proves every subset of leaves for trees of 1 to 9
// leaves, which covers full and partial last levels.
func TestBatchPathRoundTrip(t *testing.T) {
	all := testLeaves(t, 9)
	for n := 1; n <= len(all); n++ {
		tree, err := NewMerkleTree(all[:n])
		if err != nil {
			t.Fatal(err)
		}
		for mask := 1; mask < 1<<n; mask++ {
			var idx []uint64
			var leaves []Leaf
			for i := range n {
				if mask&(1<<i) != 0 {
					idx = append(idx, uint64(i))
					leaves = append(leaves, all[i])
				}
			}
			path, err := tree.BatchPath(idx)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyBatchPath(tree.Root(), uint64(n), leaves, path); err != nil {
				t.Fatalf("n=%d mask=%b: %v", n, mask, err)
			}
			if len(path.Values) > 0 {
				bad := path
				bad.Values = append([][]byte(nil), path.Values...)
				bad.Values[len(bad.Values)-1] = append([]byte{1}, bad.Values[len(bad.Values)-1][1:]...)
				if err := VerifyBatchPath(tree.Root(), uint64(n), leaves, bad); !errors.Is(err, ErrBatchPathInvalid) {
					t.Fatalf("n=%d mask=%b: tampered value accepted", n, mask)
				}
			}
		}
	}
}

func TestBatchPathRejects(t *testing.T) {
	all := testLeaves(t, 5)
	tree, err := NewMerkleTree(all)
	if err != nil {
		t.Fatal(err)
	}
	path, err := tree.BatchPath([]uint64{1, 3})
	if err != nil {
		t.Fatal(err)
	}
	leaves := []Leaf{all[1], all[3]}
	if err := VerifyBatchPath(tree.Root(), 5, leaves, path); err != nil {
		t.Fatal(err)
	}
	// Mithril tolerates unused trailing values.
	extra := path
	extra.Values = append(append([][]byte(nil), path.Values...), []byte("unused"))
	if err := VerifyBatchPath(tree.Root(), 5, leaves, extra); err != nil {
		t.Errorf("trailing value: %v", err)
	}
	for name, tc := range map[string]struct {
		leaves []Leaf
		path   BatchPath
		n      uint64
	}{
		"swapped leaves":   {[]Leaf{all[3], all[1]}, path, 5},
		"unsorted indices": {[]Leaf{all[3], all[1]}, BatchPath{Values: path.Values, Indices: []uint64{3, 1}}, 5},
		"duplicate index":  {[]Leaf{all[1], all[1]}, BatchPath{Values: path.Values, Indices: []uint64{1, 1}}, 5},
		"wrong tree depth": {leaves, path, 9},
		"no leaves":        {nil, BatchPath{}, 5},
		"missing value":    {leaves, BatchPath{Values: path.Values[:len(path.Values)-1], Indices: path.Indices}, 5},
		"length mismatch":  {leaves[:1], path, 5},
		"index past tree":  {[]Leaf{all[1], all[3]}, BatchPath{Values: path.Values, Indices: []uint64{1, 1 << 63}}, 5},
		"zero leaves":      {leaves, path, 0},
	} {
		if err := VerifyBatchPath(tree.Root(), tc.n, tc.leaves, tc.path); !errors.Is(err, ErrBatchPathInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
