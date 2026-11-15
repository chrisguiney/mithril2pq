// SPDX-License-Identifier: Apache-2.0
//
// Ported from mithril-stm/src/proof_system/concatenation/eligibility.rs and
// mithril-stm/src/signature_scheme/bls_multi_signature/signature.rs
// (evaluate_dense_mapping) in IntersectMBO/mithril at release 2642.0
// (e85df3ddc52b528c7b9ddbdddf1941fec6d5f348).
// Copyright 2022 Input Output (Hong Kong) Ltd.
// Modifications: translated from Rust to Go.

package stm

import (
	"encoding/binary"
	"errors"
	"math"
	"math/big"

	"golang.org/x/crypto/blake2b"
)

// Errors from the lottery's inputs.
var (
	ErrZeroTotalStake = errors.New("stm: total stake is zero")
	ErrPhiFOutOfRange = errors.New("stm: phi_f must be in (0, 1]")
)

// Lottery evaluates one lottery ticket: the 64-byte value
// Blake2b-512("map" || msgp || index as u64 little-endian || sigma).
func Lottery(msgp []byte, index uint64, sigma *Signature) [64]byte {
	h, _ := blake2b.New512(nil)
	h.Write([]byte("map"))
	h.Write(msgp)
	var idx [8]byte
	binary.LittleEndian.PutUint64(idx[:], index)
	h.Write(idx[:])
	h.Write(sigma.Bytes())
	var out [64]byte
	h.Sum(out[:0])
	return out
}

var evMax = new(big.Int).Lsh(big.NewInt(1), 512)

// IsLotteryWon reports whether ticket ev wins for a party holding stake
// out of totalStake: ev/2^512 < 1 - (1 - phiF)^(stake/totalStake).
//
// This is Mithril's num-integer backend, which mithril-client builds: the
// comparison is rewritten as 2^512/(2^512 - ev) < exp(-w·ln(1 - phiF)) and
// decided by a Taylor series in exact rational arithmetic. The only
// inexact step is ln(1 - phiF), a float64 as in Rust; its exact rational
// value is used from there on.
func IsLotteryWon(phiF float64, ev [64]byte, stake, totalStake uint64) (bool, error) {
	if totalStake == 0 {
		return false, ErrZeroTotalStake
	}
	if math.Abs(phiF-1) < 2.220446049250313e-16 { // f64::EPSILON
		return true, nil
	}
	if !(phiF > 0 && phiF <= 1) {
		return false, ErrPhiFOutOfRange
	}
	var le [64]byte
	for i := range ev {
		le[63-i] = ev[i]
	}
	e := new(big.Int).SetBytes(le[:])
	q := new(big.Rat).SetFrac(evMax, new(big.Int).Sub(evMax, e))

	c := new(big.Rat)
	if c.SetFloat64(math.Log(1-phiF)) == nil {
		return false, ErrPhiFOutOfRange
	}
	w := new(big.Rat).SetFrac(new(big.Int).SetUint64(stake), new(big.Int).SetUint64(totalStake))
	x := new(big.Rat).Mul(w, c)
	x.Neg(x)
	return taylorComparison(1000, q, x), nil
}

// taylorComparison reports whether cmp < exp(x), summing the series until
// the bound 3·|next term| separates cmp from the partial sum, or giving up
// (false) after bound terms.
func taylorComparison(bound int, cmp, x *big.Rat) bool {
	newX := new(big.Rat).Set(x)
	phi := big.NewRat(1, 1)
	divisor := big.NewRat(1, 1)
	one := big.NewRat(1, 1)
	three := big.NewRat(3, 1)
	errTerm := new(big.Rat)
	hi, lo := new(big.Rat), new(big.Rat)
	for range bound {
		phi.Add(phi, newX)
		divisor.Add(divisor, one)
		newX.Mul(newX, x)
		newX.Quo(newX, divisor)
		errTerm.Abs(newX)
		errTerm.Mul(errTerm, three)
		if cmp.Cmp(hi.Add(phi, errTerm)) > 0 {
			return false
		}
		if cmp.Cmp(lo.Sub(phi, errTerm)) < 0 {
			return true
		}
	}
	return false
}
