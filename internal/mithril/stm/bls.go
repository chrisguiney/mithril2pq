// SPDX-License-Identifier: Apache-2.0
//
// Ported from mithril-stm/src/signature_scheme/bls_multi_signature/ in
// IntersectMBO/mithril at release 2642.0
// (e85df3ddc52b528c7b9ddbdddf1941fec6d5f348).
// Copyright 2022 Input Output (Hong Kong) Ltd.
// Modifications: translated from Rust (blst) to Go (gnark-crypto).

package stm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
)

// Mithril uses blst's min_sig variant: signatures in G1, verification keys
// in G2, and an empty domain separation tag for hash-to-curve. A standard
// ciphersuite DST would produce different signatures.
var dst = []byte{}

// Encoded sizes: compressed G1 signature, compressed G2 key, scalar.
const (
	SignatureSize       = bls.SizeOfG1AffineCompressed // 48
	VerificationKeySize = bls.SizeOfG2AffineCompressed // 96
	SigningKeySize      = fr.Bytes                     // 32
)

// Errors from decoding and verifying BLS values.
var (
	ErrInvalidPoint     = errors.New("stm: invalid curve point encoding")
	ErrPointAtInfinity  = errors.New("stm: point at infinity")
	ErrSignatureInvalid = errors.New("stm: BLS signature invalid")
)

var g1Gen, g2Gen = func() (bls.G1Affine, bls.G2Affine) {
	_, _, g1, g2 := bls.Generators()
	return g1, g2
}()

// SigningKey is a BLS secret scalar.
type SigningKey struct{ s big.Int }

// VerificationKey is a BLS public key in G2.
type VerificationKey struct{ p bls.G2Affine }

// Signature is a BLS signature in G1.
type Signature struct{ p bls.G1Affine }

// GenerateSigningKey draws 32 bytes of input keying material from rng and
// derives the key with the IETF BLS KeyGen (key_info empty), as blst's
// SecretKey::key_gen does.
func GenerateSigningKey(rng io.Reader) (*SigningKey, error) {
	var ikm [32]byte
	if _, err := io.ReadFull(rng, ikm[:]); err != nil {
		return nil, err
	}
	return keyGen(ikm[:], nil), nil
}

// keyGen is draft-irtf-cfrg-bls-signature KeyGen (v4 and later): the salt is
// hashed before each attempt, and IKM is extended with a zero byte.
func keyGen(ikm, keyInfo []byte) *SigningKey {
	salt := []byte("BLS-SIG-KEYGEN-SALT-")
	info := append(append([]byte(nil), keyInfo...), 0, 48)
	r := fr.Modulus()
	for {
		h := sha256.Sum256(salt)
		salt = h[:]
		okm := make([]byte, 48)
		rd := hkdf.New(func() hash.Hash { return sha256.New() }, append(append([]byte(nil), ikm...), 0), salt, info)
		if _, err := io.ReadFull(rd, okm); err != nil {
			panic(err) // 48 bytes is far below HKDF's limit
		}
		sk := new(big.Int).SetBytes(okm)
		sk.Mod(sk, r)
		if sk.Sign() != 0 {
			k := &SigningKey{}
			k.s.Set(sk)
			return k
		}
	}
}

// SigningKeyFromBytes decodes a 32-byte big-endian scalar.
func SigningKeyFromBytes(b []byte) (*SigningKey, error) {
	if len(b) != SigningKeySize {
		return nil, fmt.Errorf("stm: signing key is %d bytes, want %d", len(b), SigningKeySize)
	}
	k := &SigningKey{}
	k.s.SetBytes(b)
	if k.s.Sign() == 0 || k.s.Cmp(fr.Modulus()) >= 0 {
		return nil, errors.New("stm: signing key out of range")
	}
	return k, nil
}

// Bytes returns the 32-byte big-endian scalar.
func (k *SigningKey) Bytes() []byte {
	b := make([]byte, SigningKeySize)
	k.s.FillBytes(b)
	return b
}

// VerificationKey returns sk·G2.
func (k *SigningKey) VerificationKey() *VerificationKey {
	vk := &VerificationKey{}
	vk.p.ScalarMultiplicationBase(&k.s)
	return vk
}

func hashToG1(msg []byte) bls.G1Affine {
	h, err := bls.HashToG1(msg, dst)
	if err != nil {
		panic(err) // only for a DST over 255 bytes
	}
	return h
}

// Sign signs msg: sk·H(msg) in G1.
func (k *SigningKey) Sign(msg []byte) *Signature {
	h := hashToG1(msg)
	s := &Signature{}
	s.p.ScalarMultiplication(&h, &k.s)
	return s
}

// SignatureFromBytes decodes a compressed G1 point, rejecting the point at
// infinity and points outside the prime-order subgroup, as blst's
// Signature::sig_validate(bytes, true) does.
func SignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != SignatureSize {
		return nil, fmt.Errorf("%w: signature is %d bytes, want %d", ErrInvalidPoint, len(b), SignatureSize)
	}
	if err := checkCompressedFlags(b[0]); err != nil {
		return nil, err
	}
	s := &Signature{}
	if _, err := s.p.SetBytes(b); err != nil { // includes the subgroup check
		return nil, fmt.Errorf("%w: %v", ErrInvalidPoint, err)
	}
	return s, nil
}

// VerificationKeyFromBytes decodes a compressed G2 point, rejecting the
// point at infinity and points outside the subgroup (blst key_validate).
func VerificationKeyFromBytes(b []byte) (*VerificationKey, error) {
	if len(b) != VerificationKeySize {
		return nil, fmt.Errorf("%w: verification key is %d bytes, want %d", ErrInvalidPoint, len(b), VerificationKeySize)
	}
	if err := checkCompressedFlags(b[0]); err != nil {
		return nil, err
	}
	vk := &VerificationKey{}
	if _, err := vk.p.SetBytes(b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPoint, err)
	}
	return vk, nil
}

// checkCompressedFlags accepts only a compressed, non-infinity encoding.
// gnark-crypto would otherwise accept the infinity encoding, which blst
// rejects for signatures and keys.
func checkCompressedFlags(b0 byte) error {
	if b0&0x80 == 0 {
		return fmt.Errorf("%w: not a compressed encoding", ErrInvalidPoint)
	}
	if b0&0x40 != 0 {
		return ErrPointAtInfinity
	}
	return nil
}

// Bytes returns the 48-byte compressed encoding.
func (s *Signature) Bytes() []byte { b := s.p.Bytes(); return b[:] }

// Bytes returns the 96-byte compressed encoding.
func (vk *VerificationKey) Bytes() []byte { b := vk.p.Bytes(); return b[:] }

// Equal reports whether two keys are the same point.
func (vk *VerificationKey) Equal(o *VerificationKey) bool { return vk.p.Equal(&o.p) }

// Verify checks e(sig, g2) == e(H(msg), vk).
func (s *Signature) Verify(msg []byte, vk *VerificationKey) error {
	if vk.p.IsInfinity() {
		return ErrPointAtInfinity
	}
	h := hashToG1(msg)
	return pairingCheck([]bls.G1Affine{s.p}, []bls.G2Affine{vk.p}, []bls.G1Affine{h})
}

// pairingCheck verifies e(Σ sig, g2) == Π e(h_i, vk_i), where sigs are
// summed by the caller or listed (one G1 against g2 each).
func pairingCheck(sigs []bls.G1Affine, vks []bls.G2Affine, hs []bls.G1Affine) error {
	var sum bls.G1Jac
	for i := range sigs {
		var j bls.G1Jac
		j.FromAffine(&sigs[i])
		sum.AddAssign(&j)
	}
	var sumAff, negSum bls.G1Affine
	sumAff.FromJacobian(&sum)
	negSum.Neg(&sumAff)
	ps := append([]bls.G1Affine{negSum}, hs...)
	qs := append([]bls.G2Affine{g2Gen}, vks...)
	ok, err := bls.PairingCheck(ps, qs)
	if err != nil {
		return err
	}
	if !ok {
		return ErrSignatureInvalid
	}
	return nil
}

// aggregationScalars derives the per-signature 128-bit scalars:
// Blake2b-128(sig_0 || ... || sig_n-1 || i as u64 big-endian), read as a
// little-endian integer (blst mult with 128-bit byte scalars).
func aggregationScalars(sigs []*Signature) []fr.Element {
	h, _ := blake2b.New(16, nil)
	for _, s := range sigs {
		h.Write(s.Bytes())
	}
	state, _ := h.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	out := make([]fr.Element, len(sigs))
	for i := range sigs {
		hi, _ := blake2b.New(16, nil)
		hi.(interface{ UnmarshalBinary([]byte) error }).UnmarshalBinary(state)
		var idx [8]byte
		putU64BE(idx[:], uint64(i))
		hi.Write(idx[:])
		d := hi.Sum(nil)
		var le [16]byte
		for j := range d {
			le[15-j] = d[j]
		}
		var x big.Int
		x.SetBytes(le[:])
		out[i].SetBigInt(&x)
	}
	return out
}

// Aggregate combines keys and signatures with deterministic scalars. A
// single pair is returned unchanged, without a scalar.
func Aggregate(vks []*VerificationKey, sigs []*Signature) (*VerificationKey, *Signature, error) {
	if len(vks) != len(sigs) || len(vks) == 0 {
		return nil, nil, errors.New("stm: aggregate needs equal, non-zero numbers of keys and signatures")
	}
	if len(vks) == 1 {
		return vks[0], sigs[0], nil
	}
	scalars := aggregationScalars(sigs)
	g1s := make([]bls.G1Affine, len(sigs))
	g2s := make([]bls.G2Affine, len(vks))
	for i := range sigs {
		g1s[i], g2s[i] = sigs[i].p, vks[i].p
	}
	var aSig bls.G1Jac
	var aVK bls.G2Jac
	if _, err := aSig.MultiExp(g1s, scalars, multiExpConfig); err != nil {
		return nil, nil, err
	}
	if _, err := aVK.MultiExp(g2s, scalars, multiExpConfig); err != nil {
		return nil, nil, err
	}
	vk, s := &VerificationKey{}, &Signature{}
	vk.p.FromJacobian(&aVK)
	s.p.FromJacobian(&aSig)
	return vk, s, nil
}

// VerifyAggregate aggregates keys and signatures and verifies the result
// against msg.
func VerifyAggregate(msg []byte, vks []*VerificationKey, sigs []*Signature) error {
	vk, s, err := Aggregate(vks, sigs)
	if err != nil {
		return err
	}
	if err := s.Verify(msg, vk); err != nil {
		return fmt.Errorf("aggregate: %w", err)
	}
	return nil
}

// BatchVerifyAggregates verifies several (message, key, signature)
// triples with one multi-pairing: e(Σ sig_j, g2) == Π e(H(msg_j), vk_j).
// As in Mithril, no random scalars are applied across the batch.
func BatchVerifyAggregates(msgs [][]byte, vks []*VerificationKey, sigs []*Signature) error {
	if len(msgs) != len(vks) || len(vks) != len(sigs) || len(sigs) == 0 {
		return errors.New("stm: batch verify needs equal, non-zero numbers of messages, keys and signatures")
	}
	g1s := make([]bls.G1Affine, len(sigs))
	g2s := make([]bls.G2Affine, len(vks))
	hs := make([]bls.G1Affine, len(msgs))
	for i := range sigs {
		if vks[i].p.IsInfinity() {
			return ErrPointAtInfinity
		}
		g1s[i], g2s[i], hs[i] = sigs[i].p, vks[i].p, hashToG1(msgs[i])
	}
	return pairingCheck(g1s, g2s, hs)
}

var multiExpConfig = ecc.MultiExpConfig{}

func putU64BE(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}

// ProofOfPossession shows the holder of a verification key knows its
// signing key: k1 = sign("PoP"), k2 = sk·G1. Only key registration uses it.
type ProofOfPossession struct{ k1, k2 bls.G1Affine }

var popMessage = []byte("PoP")

// ProofOfPossession creates the key's proof of possession.
func (k *SigningKey) ProofOfPossession() *ProofOfPossession {
	p := &ProofOfPossession{k1: k.Sign(popMessage).p}
	p.k2.ScalarMultiplicationBase(&k.s)
	return p
}

// Bytes returns k1 || k2, both compressed (96 bytes).
func (p *ProofOfPossession) Bytes() []byte {
	a, b := p.k1.Bytes(), p.k2.Bytes()
	return append(a[:], b[:]...)
}

// Verify checks the proof against vk: k1 is a signature of "PoP" under vk,
// and e(g1, vk) == e(k2, g2).
func (p *ProofOfPossession) Verify(vk *VerificationKey) error {
	if vk.p.IsInfinity() || !vk.p.IsInSubGroup() {
		return ErrPointAtInfinity
	}
	if err := (&Signature{p: p.k1}).Verify(popMessage, vk); err != nil {
		return fmt.Errorf("proof of possession: %w", err)
	}
	var negK2 bls.G1Affine
	negK2.Neg(&p.k2)
	ok, err := bls.PairingCheck([]bls.G1Affine{g1Gen, negK2}, []bls.G2Affine{vk.p, g2Gen})
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("stm: proof of possession invalid")
	}
	return nil
}
