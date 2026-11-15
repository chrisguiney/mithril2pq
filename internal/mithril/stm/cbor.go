// SPDX-License-Identifier: Apache-2.0
//
// Ported from the to_bytes methods of AggregateSignature
// (mithril-stm/src/protocol/aggregate_signature/signature.rs),
// ConcatenationProof (proof_system/concatenation/proof.rs),
// SingleSignatureWithRegisteredParty and SingleSignature
// (protocol/single_signature/), ClosedRegistrationEntry
// (protocol/key_registration/closed_registration_entry.rs), MerkleBatchPath
// (membership_commitment/merkle_tree/path.rs) and mithril-stm/src/codec.rs
// in IntersectMBO/mithril at release 2642.0
// (e85df3ddc52b528c7b9ddbdddf1941fec6d5f348).
// Copyright 2022 Input Output (Hong Kong) Ltd.
// Modifications: translated from Rust to Go; ciborium's serde output is
// written by hand.

package stm

// Mithril's versioned byte form: a 0x01 version byte, then the value as
// ciborium serializes it through serde. Two ciborium details shape the
// bytes: a Vec<u8> without serde_bytes is an array of integers, not a byte
// string, and a struct with a flattened field (SingleSignature) is an
// indefinite-length map. Nested values are themselves versioned byte
// strings, carried as integer arrays. Nothing on the wire uses this form
// today; it is here for the proof-size benchmark, and is checked against
// Mithril's golden bytes.

const cborVersion = 1

type cborWriter []byte

func (w *cborWriter) head(major byte, n uint64) {
	switch {
	case n < 24:
		*w = append(*w, major<<5|byte(n))
	case n <= 0xff:
		*w = append(*w, major<<5|24, byte(n))
	case n <= 0xffff:
		*w = append(*w, major<<5|25, byte(n>>8), byte(n))
	case n <= 0xffffffff:
		*w = append(*w, major<<5|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	default:
		*w = append(*w, major<<5|27)
		for i := 7; i >= 0; i-- {
			*w = append(*w, byte(n>>(8*i)))
		}
	}
}

func (w *cborWriter) uint(n uint64)  { w.head(0, n) }
func (w *cborWriter) text(s string)  { w.head(3, uint64(len(s))); *w = append(*w, s...) }
func (w *cborWriter) bstr(b []byte)  { w.head(2, uint64(len(b))); *w = append(*w, b...) }
func (w *cborWriter) array(n int)    { w.head(4, uint64(n)) }
func (w *cborWriter) mapHead(n int)  { w.head(5, uint64(n)) }
func (w *cborWriter) null()          { *w = append(*w, 0xf6) }
func (w *cborWriter) indefiniteMap() { *w = append(*w, 0xbf) }
func (w *cborWriter) end()           { *w = append(*w, 0xff) }

// intArray writes bytes as serde serializes a Vec<u8> or [u8; N]: an array
// of integers.
func (w *cborWriter) intArray(b []byte) {
	w.array(len(b))
	for _, v := range b {
		w.uint(uint64(v))
	}
}

func (w *cborWriter) uints(xs []uint64) {
	w.array(len(xs))
	for _, v := range xs {
		w.uint(v)
	}
}

func versioned(f func(w *cborWriter)) []byte {
	w := cborWriter{cborVersion}
	f(&w)
	return w
}

func (s *SingleSignature) versionedBytes() []byte {
	return versioned(func(w *cborWriter) {
		w.indefiniteMap()
		w.text("sigma")
		w.intArray(s.Sigma.Bytes())
		w.text("indexes")
		w.uints(s.Indexes)
		w.text("signer_index")
		w.uint(s.SignerIndex)
		w.end()
	})
}

func (l Leaf) versionedBytes() []byte {
	return versioned(func(w *cborWriter) {
		w.mapHead(2)
		w.text("verification_key_bytes")
		w.intArray(l.VK.Bytes())
		w.text("stake")
		w.uint(l.Stake)
	})
}

func (e *SignedEntry) versionedBytes() []byte {
	return versioned(func(w *cborWriter) {
		w.mapHead(2)
		w.text("signature_bytes")
		w.intArray(e.Sig.versionedBytes())
		w.text("registration_entry_bytes")
		w.intArray(e.Party.versionedBytes())
	})
}

func (p *BatchPath) versionedBytes() []byte {
	return versioned(func(w *cborWriter) {
		w.mapHead(3)
		w.text("values")
		w.array(len(p.Values))
		for _, v := range p.Values {
			w.intArray(v)
		}
		w.text("indices")
		w.uints(p.Indices)
		w.text("hasher")
		w.null()
	})
}

func (p *ConcatenationProof) versionedBytes() []byte {
	return versioned(func(w *cborWriter) {
		w.mapHead(2)
		w.text("signature_bytes")
		w.array(len(p.Signatures))
		for i := range p.Signatures {
			w.intArray(p.Signatures[i].versionedBytes())
		}
		w.text("batch_proof_bytes")
		w.intArray(p.BatchPath.versionedBytes())
	})
}

// AggregateSignatureBytes returns the proof as Mithril's
// AggregateSignature::to_bytes encodes a concatenation aggregate signature.
func (p *ConcatenationProof) AggregateSignatureBytes() []byte {
	return versioned(func(w *cborWriter) {
		w.mapHead(2)
		w.text("signature_type")
		w.uint(0) // Concatenation
		w.text("proof_bytes")
		w.bstr(p.versionedBytes())
	})
}
