// SPDX-License-Identifier: Apache-2.0
//
// Ported from mithril-stm/src/membership_commitment/merkle_tree/ (tree.rs,
// commitment.rs, path.rs, leaf.rs, mod.rs) in IntersectMBO/mithril at
// release 2642.0 (e85df3ddc52b528c7b9ddbdddf1941fec6d5f348).
// Copyright 2022 Input Output (Hong Kong) Ltd.
// Modifications: translated from Rust to Go.

package stm

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"slices"

	"golang.org/x/crypto/blake2b"
)

// ErrBatchPathInvalid reports a batch path that does not lead to the root.
var ErrBatchPathInvalid = errors.New("stm: Merkle batch path invalid")

// Leaf is a registered party: its verification key and stake.
type Leaf struct {
	VK    *VerificationKey
	Stake uint64
}

// bytes is the leaf encoding hashed into the tree: vk (96) || stake u64 BE.
func (l Leaf) bytes() []byte {
	b := make([]byte, 0, VerificationKeySize+8)
	b = append(b, l.VK.Bytes()...)
	return binary.BigEndian.AppendUint64(b, l.Stake)
}

func merkleHash(parts ...[]byte) []byte {
	h, _ := blake2b.New256(nil)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// emptyNode fills a missing child: H(0x00).
var emptyNode = merkleHash([]byte{0})

func nextPowerOfTwo(n uint64) (uint64, bool) {
	if n <= 1 {
		return 1, true
	}
	p := uint64(1) << (64 - bits.LeadingZeros64(n-1))
	return p, p != 0
}

func parent(i uint64) uint64 { return (i - 1) / 2 }

// BatchPath proves that several leaves are in a tree.
type BatchPath struct {
	Values  [][]byte
	Indices []uint64
}

// MerkleTree is the heap-ordered tree of registered parties: leaf i sits
// at node np2-1+i, where np2 is the next power of two of the leaf count,
// and a missing right child hashes as H(0x00).
type MerkleTree struct {
	nodes  [][]byte
	leaves uint64
}

// NewMerkleTree builds the tree over leaves, in the given order.
func NewMerkleTree(leaves []Leaf) (*MerkleTree, error) {
	n := uint64(len(leaves))
	if n == 0 {
		return nil, errors.New("stm: Merkle tree needs at least one leaf")
	}
	np2, _ := nextPowerOfTwo(n)
	numNodes := n + np2 - 1
	nodes := make([][]byte, numNodes)
	for i, l := range leaves {
		nodes[np2-1+uint64(i)] = merkleHash(l.bytes())
	}
	for i := int64(np2) - 2; i >= 0; i-- {
		left, right := uint64(2*i+1), uint64(2*i+2)
		l, r := emptyNode, emptyNode
		if left < numNodes {
			l = nodes[left]
		}
		if right < numNodes {
			r = nodes[right]
		}
		nodes[i] = merkleHash(l, r)
	}
	return &MerkleTree{nodes: nodes, leaves: n}, nil
}

// Root returns the root hash.
func (t *MerkleTree) Root() []byte { return t.nodes[0] }

// Leaves returns the number of leaves.
func (t *MerkleTree) Leaves() uint64 { return t.leaves }

// BatchPath returns a proof for the leaves at the given ascending indices.
func (t *MerkleTree) BatchPath(indices []uint64) (BatchPath, error) {
	if len(indices) == 0 || !slices.IsSorted(indices) {
		return BatchPath{}, errors.New("stm: batch path needs ascending leaf indices")
	}
	np2, _ := nextPowerOfTwo(t.leaves)
	numNodes := uint64(len(t.nodes))
	oi := make([]uint64, len(indices))
	for i, x := range indices {
		if x >= t.leaves {
			return BatchPath{}, errors.New("stm: batch path index out of range")
		}
		oi[i] = np2 - 1 + x
	}
	var values [][]byte
	for oi[0] > 0 {
		var next []uint64
		for i := 0; i < len(oi); i++ {
			next = append(next, parent(oi[i]))
			if oi[i]%2 == 0 { // right child: the left sibling is needed
				values = append(values, t.nodes[oi[i]-1])
				continue
			}
			sib := oi[i] + 1
			if i < len(oi)-1 && oi[i+1] == sib {
				i++
			} else if sib < numNodes {
				values = append(values, t.nodes[sib])
			}
		}
		oi = next
	}
	return BatchPath{Values: values, Indices: append([]uint64(nil), indices...)}, nil
}

// VerifyBatchPath checks that leaves sit at path.Indices in the tree with
// the given root and leaf count. It mirrors Mithril's checks exactly,
// including what it tolerates: unused trailing values, and values of any
// length.
func VerifyBatchPath(root []byte, nrLeaves uint64, leaves []Leaf, path BatchPath) error {
	if len(leaves) != len(path.Indices) || len(path.Indices) == 0 {
		return ErrBatchPathInvalid
	}
	if !slices.IsSorted(path.Indices) {
		return ErrBatchPathInvalid
	}
	np2, ok := nextPowerOfTwo(nrLeaves)
	if !ok || nrLeaves == 0 {
		return ErrBatchPathInvalid
	}
	nrNodes := np2 + nrLeaves - 1
	oi := make([]uint64, len(path.Indices))
	for i, x := range path.Indices {
		v := np2 - 1 + x
		if v < x { // overflow
			return ErrBatchPathInvalid
		}
		oi[i] = v
	}
	hashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = merkleHash(l.bytes())
	}
	values := path.Values
	pop := func() ([]byte, bool) {
		if len(values) == 0 {
			return nil, false
		}
		v := values[0]
		values = values[1:]
		return v, true
	}
	idx := oi[0]
	for idx > 0 {
		idx = parent(idx)
		var newH [][]byte
		var newI []uint64
		for i := 0; i < len(oi); i++ {
			if oi[i] == 0 { // indices at different depths cannot occur; never panic
				return ErrBatchPathInvalid
			}
			newI = append(newI, parent(oi[i]))
			if oi[i]%2 == 0 {
				v, ok := pop()
				if !ok {
					return ErrBatchPathInvalid
				}
				newH = append(newH, merkleHash(v, hashes[i]))
				continue
			}
			sib := oi[i] + 1
			switch {
			case i < len(oi)-1 && oi[i+1] == sib:
				newH = append(newH, merkleHash(hashes[i], hashes[i+1]))
				i++
			case sib < nrNodes:
				v, ok := pop()
				if !ok {
					return ErrBatchPathInvalid
				}
				newH = append(newH, merkleHash(hashes[i], v))
			default:
				newH = append(newH, merkleHash(hashes[i], emptyNode))
			}
		}
		hashes, oi = newH, newI
	}
	if len(hashes) != 1 || string(hashes[0]) != string(root) {
		return ErrBatchPathInvalid
	}
	return nil
}
