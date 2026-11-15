// SPDX-License-Identifier: Apache-2.0

package stm

import (
	"bytes"
	"testing"
)

// Golden values from mithril-stm/src/signature_scheme/bls_multi_signature/
// (signing_key.rs, verification_key.rs, signature.rs, proof_of_possession.rs)
// at release 2642.0, all derived from ChaCha20Rng::from_seed([0; 32]).
var (
	goldenSK = []byte{64, 129, 87, 121, 27, 239, 221, 215, 2, 103, 45, 207, 207, 201, 157, 163, 81, 47, 156, 14, 168, 24, 137, 15, 203, 106, 183, 73, 88, 14, 242, 207}
	goldenVK = []byte{143, 161, 255, 48, 78, 57, 204, 220, 25, 221, 164, 252, 248, 14, 56, 126, 186, 135, 228, 188, 145, 181, 52, 200, 97, 99, 213, 46, 0, 199, 193, 89, 187, 88, 29, 135, 173, 244, 86, 36, 83, 54, 67, 164, 6, 137, 94, 72, 6, 105, 128, 128, 93, 48, 176, 11, 4, 246, 138, 48, 180, 133, 90, 142, 192, 24, 193, 111, 142, 31, 76, 111, 110, 234, 153, 90, 208, 192, 31, 124, 95, 102, 49, 158, 99, 52, 220, 165, 94, 251, 68, 69, 121, 16, 224, 194}
	// Signature of 32 zero bytes: checks hash-to-curve and the empty DST.
	goldenSig = []byte{132, 95, 124, 197, 185, 105, 193, 171, 114, 182, 52, 171, 205, 119, 202, 188, 2, 213, 61, 125, 219, 242, 10, 131, 53, 219, 53, 197, 157, 42, 152, 194, 234, 161, 244, 204, 2, 134, 47, 179, 176, 49, 200, 232, 120, 241, 180, 246}
	goldenPoP = []byte{168, 50, 233, 193, 15, 136, 65, 72, 123, 148, 129, 176, 38, 198, 209, 47, 28, 204, 176, 144, 57, 251, 42, 28, 66, 76, 89, 97, 158, 63, 54, 198, 194, 176, 135, 221, 14, 185, 197, 225, 202, 98, 243, 74, 233, 225, 143, 151, 147, 177, 170, 117, 66, 165, 66, 62, 33, 216, 232, 75, 68, 114, 195, 22, 100, 65, 44, 198, 4, 166, 102, 233, 253, 240, 59, 175, 60, 117, 142, 114, 140, 122, 17, 87, 110, 187, 1, 17, 10, 195, 154, 13, 249, 86, 54, 226}
)

func goldenKey(t testing.TB) *SigningKey {
	t.Helper()
	sk, err := GenerateSigningKey(NewChaChaRNG([32]byte{}))
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func TestBLSGolden(t *testing.T) {
	sk := goldenKey(t)
	if !bytes.Equal(sk.Bytes(), goldenSK) {
		t.Fatalf("signing key %x", sk.Bytes())
	}
	vk := sk.VerificationKey()
	if !bytes.Equal(vk.Bytes(), goldenVK) {
		t.Fatalf("verification key %x", vk.Bytes())
	}
	msg := make([]byte, 32)
	sig := sk.Sign(msg)
	if !bytes.Equal(sig.Bytes(), goldenSig) {
		t.Fatalf("signature %x", sig.Bytes())
	}
	if err := sig.Verify(msg, vk); err != nil {
		t.Fatal(err)
	}
	if err := sig.Verify([]byte("other"), vk); err == nil {
		t.Fatal("signature verified for another message")
	}
	if got := sk.ProofOfPossession().Bytes(); !bytes.Equal(got, goldenPoP) {
		t.Fatalf("proof of possession %x", got)
	}
	if err := sk.ProofOfPossession().Verify(vk); err != nil {
		t.Fatal(err)
	}
}

func TestBLSDecodeRejects(t *testing.T) {
	inf := make([]byte, SignatureSize)
	inf[0] = 0xc0
	if _, err := SignatureFromBytes(inf); err == nil {
		t.Error("infinity signature accepted")
	}
	if _, err := SignatureFromBytes(goldenSig[:47]); err == nil {
		t.Error("short signature accepted")
	}
	unc := append([]byte(nil), goldenSig...)
	unc[0] &^= 0x80
	if _, err := SignatureFromBytes(unc); err == nil {
		t.Error("uncompressed flag accepted")
	}
	vkInf := make([]byte, VerificationKeySize)
	vkInf[0] = 0xc0
	if _, err := VerificationKeyFromBytes(vkInf); err == nil {
		t.Error("infinity key accepted")
	}
	if s, err := SignatureFromBytes(goldenSig); err != nil || !bytes.Equal(s.Bytes(), goldenSig) {
		t.Errorf("golden signature round trip: %v", err)
	}
	if k, err := VerificationKeyFromBytes(goldenVK); err != nil || !bytes.Equal(k.Bytes(), goldenVK) {
		t.Errorf("golden key round trip: %v", err)
	}
}
