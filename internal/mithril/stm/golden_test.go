// SPDX-License-Identifier: Apache-2.0

package stm

import (
	"bytes"
	"encoding/json"
	"testing"
)

// goldenAggregateJSON is GOLDEN_JSON from
// mithril-stm/src/protocol/aggregate_signature/signature.rs (golden_json
// tests) at release 2642.0: two parties of stake 1 with the first two keys
// drawn from ChaCha20Rng::from_seed([0; 32]), m = 10, k = 5, phi_f = 0.8,
// message 16 zero bytes.
const goldenAggregateJSON = `
{
  "signatures": [
    [
      {
        "sigma": [149, 157, 201, 187, 140, 54, 0, 128, 209, 88, 16, 203, 61, 78, 77, 98,
          161, 133, 58, 152, 29, 74, 217, 113, 64, 100, 10, 161, 186, 167, 133,
          114, 211, 153, 218, 56, 223, 84, 105, 242, 41, 54, 224, 170, 208, 185,
          126, 83],
        "indexes": [1, 4, 5, 8],
        "signer_index": 0
      },
      [
        [143, 161, 255, 48, 78, 57, 204, 220, 25, 221, 164, 252, 248, 14, 56,
          126, 186, 135, 228, 188, 145, 181, 52, 200, 97, 99, 213, 46, 0, 199,
          193, 89, 187, 88, 29, 135, 173, 244, 86, 36, 83, 54, 67, 164, 6, 137,
          94, 72, 6, 105, 128, 128, 93, 48, 176, 11, 4, 246, 138, 48, 180, 133,
          90, 142, 192, 24, 193, 111, 142, 31, 76, 111, 110, 234, 153, 90, 208,
          192, 31, 124, 95, 102, 49, 158, 99, 52, 220, 165, 94, 251, 68, 69,
          121, 16, 224, 194],
        1
      ]
    ],
    [
      {
        "sigma": [149, 169, 22, 201, 216, 97, 163, 188, 115, 210, 217, 236, 233, 161,
          201, 13, 42, 132, 12, 63, 5, 31, 120, 22, 78, 177, 125, 134, 208, 205,
          73, 58, 247, 141, 59, 62, 187, 81, 213, 30, 153, 218, 41, 42, 110,
          156, 161, 205],
        "indexes": [0, 3, 6],
        "signer_index": 1
      },
      [
        [145, 56, 175, 32, 122, 187, 214, 226, 251, 148, 88, 9, 1, 103, 159,
          146, 80, 166, 107, 243, 251, 236, 41, 28, 111, 128, 207, 164, 132,
          147, 228, 83, 246, 228, 170, 68, 89, 78, 60, 28, 123, 130, 88, 234,
          38, 97, 42, 65, 1, 100, 53, 18, 78, 131, 8, 61, 122, 131, 238, 84,
          233, 223, 154, 118, 118, 73, 28, 27, 101, 78, 80, 233, 123, 206, 220,
          174, 134, 205, 71, 110, 112, 180, 97, 98, 0, 113, 69, 145, 231, 168,
          43, 173, 172, 56, 104, 208],
        1
      ]
    ]
  ],
  "batch_proof": { "values": [], "indices": [0, 1], "hasher": null }
}`

// TestGoldenAggregateSignature rebuilds Mithril's golden aggregate
// signature from the seeded RNG (key generation, registration order,
// signing, lottery, deduplication, batch path) and checks it is byte for
// byte the golden value, and that it verifies.
func TestGoldenAggregateSignature(t *testing.T) {
	var golden ConcatenationProof
	if err := json.Unmarshal([]byte(goldenAggregateJSON), &golden); err != nil {
		t.Fatal(err)
	}
	want, _ := golden.MarshalJSON()

	rng := NewChaChaRNG([32]byte{})
	params := Parameters{M: 10, K: 5, PhiF: 0.8}
	msg := make([]byte, 16)
	i1, err := NewInitializer(params, 1, rng)
	if err != nil {
		t.Fatal(err)
	}
	i2, err := NewInitializer(params, 1, rng)
	if err != nil {
		t.Fatal(err)
	}
	reg := NewKeyRegistration()
	for _, i := range []*Initializer{i1, i2} {
		if err := reg.Register(i.Stake, i.VerificationKeyPoP()); err != nil {
			t.Fatal(err)
		}
	}
	if err := reg.Register(i1.Stake, i1.VerificationKeyPoP()); err == nil {
		t.Fatal("duplicate registration accepted")
	}
	closed, err := reg.Close()
	if err != nil {
		t.Fatal(err)
	}
	var sigs []*SingleSignature
	for _, i := range []*Initializer{i1, i2} {
		s, err := i.CreateSigner(closed)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := s.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, sig)
	}
	clerk := &Clerk{Params: params, Closed: closed}
	proof, err := clerk.Aggregate(sigs, msg)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := proof.MarshalJSON()
	if !bytes.Equal(got, want) {
		t.Fatalf("aggregate signature\n got %s\nwant %s", got, want)
	}
	avk := clerk.AggregateVerificationKey()
	if err := golden.Verify(msg, avk, params); err != nil {
		t.Fatal(err)
	}
	if err := BatchVerify([]*ConcatenationProof{proof, &golden}, [][]byte{msg, msg}, []*AggregateVerificationKey{avk, avk}, []Parameters{params, params}); err != nil {
		t.Fatal(err)
	}
}
