// SPDX-License-Identifier: Apache-2.0
//
// Ported from mithril-stm/benches/stm.rs, mithril-stm/benches/multi_sig.rs
// and mithril-stm/benches/size_benches.rs
// in IntersectMBO/mithril at release 2642.0
// (e85df3ddc52b528c7b9ddbdddf1941fec6d5f348).
// Copyright 2022 Input Output (Hong Kong) Ltd.
// Modifications: translated from Rust (criterion) to Go testing.B. Each
// criterion group/id maps to a sub-benchmark; parameters, ChaCha20 seeding
// and the order the RNG is drawn from are the same, so the keys, stakes and
// messages are Mithril's.

package stm

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// parallelMap applies f to every element on all CPUs, keeping order (as
// rayon's par_iter().map().collect() does). Setup only; the measured
// closures run on one goroutine, as criterion's do.
func parallelMap[T, U any](in []T, f func(T) U) []U {
	out := make([]U, len(in))
	var wg sync.WaitGroup
	next := make(chan int)
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			for i := range next {
				out[i] = f(in[i])
			}
		})
	}
	for i := range in {
		next <- i
	}
	close(next)
	wg.Wait()
	return out
}

// stmSetup is the shared part of stm_benches and batch_benches: N stakes of
// 1 + next_u64 % 9999, then one initializer (32 bytes of key material)
// per party.
func stmInitializers(b *testing.B, rng *ChaChaRNG, n int, params Parameters) []*Initializer {
	stakes := make([]uint64, n)
	for i := range stakes {
		stakes[i] = 1 + rng.Uint64()%9999
	}
	inits := make([]*Initializer, n)
	for i, s := range stakes {
		var err error
		if inits[i], err = NewInitializer(params, s, rng); err != nil {
			b.Fatal(err)
		}
	}
	return inits
}

func register(b *testing.B, inits []*Initializer) *KeyRegistration {
	reg := NewKeyRegistration()
	for _, p := range inits {
		if err := reg.Register(p.Stake, p.VerificationKeyPoP()); err != nil {
			b.Fatal(err)
		}
	}
	return reg
}

// signAll creates every party's signer and signature; parties that win no
// lottery are dropped, as filter_map(... .ok()) does.
func signAll(b *testing.B, inits []*Initializer, closed *ClosedKeyRegistration, msg []byte) ([]*Signer, []*SingleSignature) {
	signers := parallelMap(inits, func(p *Initializer) *Signer {
		s, err := p.CreateSigner(closed)
		if err != nil {
			panic(err)
		}
		return s
	})
	all := parallelMap(signers, func(s *Signer) *SingleSignature {
		sig, err := s.Sign(msg)
		if err != nil {
			return nil
		}
		return sig
	})
	var sigs []*SingleSignature
	for _, s := range all {
		if s != nil {
			sigs = append(sigs, s)
		}
	}
	return signers, sigs
}

type stmParams struct {
	parties int
	params  Parameters
	heavy   bool // skipped with -short
}

func (p stmParams) String() string {
	return fmt.Sprintf("k=%d,m=%d,parties=%d", p.params.K, p.params.M, p.parties)
}

// BenchmarkSTM is stm_benches: key registration, one party playing all m
// lotteries, and aggregation of every party's signature.
func BenchmarkSTM(b *testing.B) {
	for _, sp := range []stmParams{
		{300, Parameters{M: 150, K: 25, PhiF: 0.2}, false},
		{2000, Parameters{M: 1523, K: 250, PhiF: 0.2}, true},
	} {
		b.Run("Blake2b/"+sp.String(), func(b *testing.B) {
			if sp.heavy && testing.Short() {
				b.Skip("2000-party setup skipped with -short")
			}
			rng := NewChaChaRNG([32]byte{})
			msg := make([]byte, 16)
			rng.Read(msg)
			inits := stmInitializers(b, rng, sp.parties, sp.params)

			b.Run("KeyRegistration", func(b *testing.B) {
				for b.Loop() {
					register(b, inits)
				}
			})

			closed, err := register(b, inits).Close()
			if err != nil {
				b.Fatal(err)
			}
			signers, sigs := signAll(b, inits, closed, msg)

			// With these seeds the first 300-party signer wins none of its
			// 150 lotteries, so Rust's unwrap() panics here at 2642.0 and
			// the group (and the 2000-party one after it) never reports.
			// The work is the same either way: one signature and m
			// lotteries.
			b.Run("PlayAllLotteries", func(b *testing.B) {
				for b.Loop() {
					if _, err := signers[0].Sign(msg); err != nil && !errors.Is(err, ErrLotteryLost) {
						b.Fatal(err)
					}
				}
			})

			clerk := &Clerk{Params: sp.params, Closed: closed}
			b.Run("Aggregation", func(b *testing.B) {
				for b.Loop() {
					if _, err := clerk.Aggregate(sigs, msg); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

// BenchmarkSTMBatchVerification is batch_benches: verifying B aggregate
// signatures, each over its own registration and message, with one
// multi-pairing. One RNG feeds every batch size in turn, as in Rust.
//
// The 2000-party sets need about 260,000 signers playing 1523 lotteries
// each (several CPU-minutes), so they run only with MITHRIL2PQ_BENCH_FULL=1.
func BenchmarkSTMBatchVerification(b *testing.B) {
	for _, sp := range []stmParams{
		{300, Parameters{M: 150, K: 25, PhiF: 0.4}, false},
		{2000, Parameters{M: 1523, K: 250, PhiF: 0.4}, true},
	} {
		b.Run("Blake2b/"+sp.String(), func(b *testing.B) {
			if sp.heavy && (testing.Short() || os.Getenv("MITHRIL2PQ_BENCH_FULL") == "") {
				b.Skip("2000-party batches need MITHRIL2PQ_BENCH_FULL=1")
			}
			rng := NewChaChaRNG([32]byte{})
			for _, n := range []int{1, 10, 20, 100} {
				msgs := make([][]byte, n)
				params := make([]Parameters, n)
				proofs := make([]*ConcatenationProof, n)
				avks := make([]*AggregateVerificationKey, n)
				for i := range n {
					msgs[i] = make([]byte, 32)
					rng.Read(msgs[i])
					params[i] = sp.params
					inits := stmInitializers(b, rng, sp.parties, sp.params)
					closed, err := register(b, inits).Close()
					if err != nil {
						b.Fatal(err)
					}
					_, sigs := signAll(b, inits, closed, msgs[i])
					clerk := &Clerk{Params: sp.params, Closed: closed}
					if proofs[i], err = clerk.Aggregate(sigs, msgs[i]); err != nil {
						b.Fatal(err)
					}
					avks[i] = clerk.AggregateVerificationKey()
				}
				b.Run(fmt.Sprintf("batch=%d", n), func(b *testing.B) {
					for b.Loop() {
						if err := BatchVerify(proofs, msgs, avks, params); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

// BenchmarkMultiSig is multi_sig.rs batch_benches: BLS batch verification
// of aggregates of 300 signatures. As in Rust, the vectors are not reset
// between batch sizes, so "batch=B" verifies the cumulative 1, 11, 31, 81
// and 181 aggregates; the names keep Rust's labels so results line up.
func BenchmarkMultiSig(b *testing.B) {
	rng := NewChaChaRNG([32]byte{})
	var msgs [][]byte
	var vks []*VerificationKey
	var sigs []*Signature
	for _, n := range []int{1, 10, 20, 50, 100} {
		for range n {
			msg := make([]byte, 32)
			rng.Read(msg)
			sks := make([]*SigningKey, 300)
			for i := range sks {
				sks[i], _ = GenerateSigningKey(rng)
			}
			mvks := parallelMap(sks, func(sk *SigningKey) *VerificationKey { return sk.VerificationKey() })
			msigs := parallelMap(sks, func(sk *SigningKey) *Signature { return sk.Sign(msg) })
			avk, asig, err := Aggregate(mvks, msigs)
			if err != nil {
				b.Fatal(err)
			}
			msgs, vks, sigs = append(msgs, msg), append(vks, avk), append(sigs, asig)
		}
		b.Run(fmt.Sprintf("BatchVerification/batch=%d", n), func(b *testing.B) {
			for b.Loop() {
				if err := BatchVerifyAggregates(msgs, vks, sigs); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkBLS is multi_sig.rs aggregate_and_verify with 1000 keys: 1000
// signatures, 1000 verifications, and "batch verification" (1000 Blake2b
// hashes of the signatures, discarded as in Rust, then one aggregate and
// one verification).
func BenchmarkBLS(b *testing.B) {
	const n = 1000
	rng := NewChaChaRNG([32]byte{})
	msg := make([]byte, 32)
	rng.Read(msg)
	sks := make([]*SigningKey, n)
	for i := range sks {
		sks[i], _ = GenerateSigningKey(rng)
	}
	vks := parallelMap(sks, func(sk *SigningKey) *VerificationKey { return sk.VerificationKey() })
	sigs := parallelMap(sks, func(sk *SigningKey) *Signature { return sk.Sign(msg) })

	b.Run(fmt.Sprintf("Signature/%d", n), func(b *testing.B) {
		for b.Loop() {
			for _, sk := range sks {
				sk.Sign(msg)
			}
		}
	})
	b.Run(fmt.Sprintf("Verification/%d", n), func(b *testing.B) {
		for b.Loop() {
			for i, sig := range sigs {
				if err := sig.Verify(msg, vks[i]); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run(fmt.Sprintf("BatchVerification/%d", n), func(b *testing.B) {
		for b.Loop() {
			for _, sig := range sigs {
				blake2b.Sum512(sig.Bytes())
			}
			avk, asig, err := Aggregate(vks, sigs)
			if err != nil {
				b.Fatal(err)
			}
			if err := asig.Verify(msg, avk); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkVerifyMainnetCertificate verifies the committed mainnet
// certificate's multi-signature (48 signers, k = 1944). It has no Rust
// counterpart; it is the cost of one step of a mainnet chain walk.
func BenchmarkVerifyMainnetCertificate(b *testing.B) {
	c := committedCert(b, mainnet48)
	p, avk := decodeLive(b, c)
	msg := []byte(c.SignedMessage)
	for b.Loop() {
		if err := p.Verify(msg, avk, c.Metadata.Parameters); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkProofSize is size_benches.rs: the byte length of
// AggregateSignature::to_bytes for 3000 parties, with Mithril's tree hash
// (BLAKE2b-256) and with BLAKE2b-512, reported as the "bytes" metric. Rust
// prints these lengths; the loop here times the encoding.
func BenchmarkProofSize(b *testing.B) {
	if testing.Short() {
		b.Skip("3000-party setups skipped with -short")
	}
	for _, kmn := range [][3]uint64{{445, 2728, 3000}, {554, 3597, 3000}} {
		for _, h := range []struct {
			name string
			hash hashFunc
		}{{"Blake2b512", blake2bHash(64)}, {"Blake2b256", merkleHash}} {
			params := Parameters{K: kmn[0], M: kmn[1], PhiF: 0.2}
			b.Run(fmt.Sprintf("%s/k=%d,m=%d,parties=%d", h.name, kmn[0], kmn[1], kmn[2]), func(b *testing.B) {
				rng := NewChaChaRNG([32]byte{})
				msg := make([]byte, 16)
				rng.Read(msg)
				stakes := make([]uint64, kmn[2])
				for i := range stakes {
					stakes[i] = 1 + rng.Uint64()%9999
				}
				reg := NewKeyRegistration()
				inits := make([]*Initializer, len(stakes))
				for i, s := range stakes {
					p, err := NewInitializer(params, s, rng)
					if err != nil {
						b.Fatal(err)
					}
					if err := reg.Register(s, p.VerificationKeyPoP()); err != nil {
						b.Fatal(err)
					}
					inits[i] = p
				}
				closed, err := reg.closeWithHash(h.hash)
				if err != nil {
					b.Fatal(err)
				}
				_, sigs := signAll(b, inits, closed, msg)
				proof, err := (&Clerk{Params: params, Closed: closed}).Aggregate(sigs, msg)
				if err != nil {
					b.Fatal(err)
				}
				var n int
				for b.Loop() {
					n = len(proof.AggregateSignatureBytes())
				}
				b.ReportMetric(float64(n), "bytes")
			})
		}
	}
}
