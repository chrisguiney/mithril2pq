// SPDX-License-Identifier: Apache-2.0

package stm

import (
	"encoding/binary"

	"golang.org/x/crypto/chacha20"
)

// ChaChaRNG reproduces rand_chacha's ChaCha20Rng::from_seed output: the
// plain ChaCha20 keystream (key = seed, zero nonce, counter from 0) read
// sequentially. Mithril's tests and benchmarks seed it with 32 zero bytes,
// so the same seed gives the same keys and messages here. It is for tests
// and benchmarks only; it is not a source of secret randomness.
type ChaChaRNG struct{ c *chacha20.Cipher }

// NewChaChaRNG seeds the stream.
func NewChaChaRNG(seed [32]byte) *ChaChaRNG {
	c, err := chacha20.NewUnauthenticatedCipher(seed[:], make([]byte, chacha20.NonceSize))
	if err != nil {
		panic(err)
	}
	return &ChaChaRNG{c: c}
}

// Read fills p with the next len(p) keystream bytes. rand_chacha consumes
// whole 4-byte words; every caller here reads multiples of 4.
func (r *ChaChaRNG) Read(p []byte) (int, error) {
	clear(p)
	r.c.XORKeyStream(p, p)
	return len(p), nil
}

// Uint64 returns the next 8 bytes as a little-endian integer (next_u64).
func (r *ChaChaRNG) Uint64() uint64 {
	var b [8]byte
	r.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}
