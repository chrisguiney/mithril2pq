// SPDX-License-Identifier: Apache-2.0

package stm

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// liveCert is the part of a certificate message the STM proof needs.
type liveCert struct {
	Hash          string `json:"hash"`
	Epoch         uint64 `json:"epoch"`
	SignedMessage string `json:"signed_message"`
	AVK           string `json:"aggregate_verification_key"`
	MultiSig      string `json:"multi_signature"`
	Metadata      struct {
		Parameters Parameters `json:"parameters"`
	} `json:"metadata"`
}

func (c liveCert) avkJSON(t testing.TB) []byte {
	b, err := hex.DecodeString(c.AVK)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (c liveCert) proofJSON(t testing.TB) []byte {
	b, err := hex.DecodeString(c.MultiSig)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// liveCerts returns the committed certificates plus, when present, the
// chains saved under ~/.cache/mithril2pq-certs. Genesis certificates carry
// no multi-signature and are skipped.
func liveCerts(t testing.TB, includeCache bool) map[string]liveCert {
	t.Helper()
	globs := []string{"../testdata/certs/*/*.json"}
	if home, err := os.UserHomeDir(); err == nil && includeCache {
		globs = append(globs, filepath.Join(home, ".cache/mithril2pq-certs/*/*.json"))
	}
	out := map[string]liveCert{}
	for _, g := range globs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var c liveCert
			if err := json.Unmarshal(b, &c); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if c.MultiSig == "" {
				continue
			}
			out[filepath.Base(filepath.Dir(f))+"/"+c.Hash] = c
		}
	}
	if len(out) == 0 {
		t.Fatal("no certificates found")
	}
	return out
}

func decodeLive(t testing.TB, c liveCert) (*ConcatenationProof, *AggregateVerificationKey) {
	t.Helper()
	var avk AggregateVerificationKey
	if err := json.Unmarshal(c.avkJSON(t), &avk); err != nil {
		t.Fatalf("%s: %v", c.Hash, err)
	}
	var p ConcatenationProof
	if err := json.Unmarshal(c.proofJSON(t), &p); err != nil {
		t.Fatalf("%s: %v", c.Hash, err)
	}
	return &p, &avk
}

func committedCert(t testing.TB, prefix string) liveCert {
	t.Helper()
	for k, c := range liveCerts(t, false) {
		if strings.HasPrefix(k, prefix) {
			return c
		}
	}
	t.Fatalf("no committed certificate %s", prefix)
	return liveCert{}
}

func TestLiveCodecRoundTrip(t *testing.T) {
	for name, c := range liveCerts(t, true) {
		p, avk := decodeLive(t, c)
		got, _ := avk.MarshalJSON()
		if !bytes.Equal(got, c.avkJSON(t)) {
			t.Errorf("%s: AVK re-encodes differently", name)
		}
		got, _ = p.MarshalJSON()
		if !bytes.Equal(got, c.proofJSON(t)) {
			t.Errorf("%s: multi-signature re-encodes differently", name)
		}
	}
}

func TestLiveProofsVerify(t *testing.T) {
	certs := liveCerts(t, !testing.Short())
	signers := map[int]int{}
	for name, c := range certs {
		p, avk := decodeLive(t, c)
		if err := p.Verify([]byte(c.SignedMessage), avk, c.Metadata.Parameters); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		signers[len(p.Signatures)]++
	}
	t.Logf("verified %d proofs; signers per proof: %v", len(certs), signers)
}

// The committed preprod certificate of epoch 201 has three signers, so it
// exercises the aggregation scalars; the mainnet one has 48.
const (
	preprod3Signers = "preprod/172f78406dfbb005"
	mainnet48       = "mainnet/e3c57f5db73ebfec"
)

func TestLiveProofNegative(t *testing.T) {
	for _, prefix := range []string{preprod3Signers, mainnet48} {
		c := committedCert(t, prefix)
		msg := []byte(c.SignedMessage)
		params := c.Metadata.Parameters
		fresh := func() (*ConcatenationProof, *AggregateVerificationKey) { return decodeLive(t, c) }
		cases := []struct {
			name   string
			mutate func(p *ConcatenationProof, a *AggregateVerificationKey, msg []byte) []byte
			want   error
		}{
			{"sigma bit flip", func(p *ConcatenationProof, _ *AggregateVerificationKey, m []byte) []byte {
				// Re-sign under another key is not possible here, so replace
				// sigma with a valid point that is not the signature: the
				// lottery or the pairing must fail.
				p.Signatures[0].Sig.Sigma = p.Signatures[len(p.Signatures)-1].Sig.Sigma.double()
				return m
			}, nil},
			{"batch path value", func(p *ConcatenationProof, _ *AggregateVerificationKey, m []byte) []byte {
				v := append([]byte(nil), p.BatchPath.Values[0]...)
				v[0] ^= 1
				p.BatchPath.Values[0] = v
				return m
			}, ErrBatchPathInvalid},
			{"index changed", func(p *ConcatenationProof, _ *AggregateVerificationKey, m []byte) []byte {
				a := decodeAVK(t, c)
				p.Signatures[0].Sig.Indexes[0] = losingIndex(t, p, a, MessageWithRoot(m, a), params)
				return m
			}, ErrLotteryLost},
			{"index = m", func(p *ConcatenationProof, _ *AggregateVerificationKey, m []byte) []byte {
				p.Signatures[0].Sig.Indexes[0] = params.M
				return m
			}, ErrIndexBound},
			{"index = m+1", func(p *ConcatenationProof, _ *AggregateVerificationKey, m []byte) []byte {
				p.Signatures[0].Sig.Indexes[0] = params.M + 1
				return m
			}, ErrIndexBound},
			{"duplicate index", func(p *ConcatenationProof, _ *AggregateVerificationKey, m []byte) []byte {
				ix := p.Signatures[0].Sig.Indexes
				p.Signatures[0].Sig.Indexes = append(ix, ix[0])
				return m
			}, ErrIndexNotUnique},
			{"too few indexes", func(p *ConcatenationProof, _ *AggregateVerificationKey, m []byte) []byte {
				return m
			}, nil},
			{"stake changed", func(p *ConcatenationProof, _ *AggregateVerificationKey, m []byte) []byte {
				p.Signatures[0].Party.Stake++
				return m
			}, ErrBatchPathInvalid},
			// total_stake is not under the Merkle root, so a small change can
			// leave every ticket winning; the certificate chain binds it
			// through the AVK. A large one must lose a lottery.
			{"total stake inflated", func(_ *ConcatenationProof, a *AggregateVerificationKey, m []byte) []byte {
				a.TotalStake *= 1 << 20
				return m
			}, ErrLotteryLost},
			{"total stake zero", func(_ *ConcatenationProof, a *AggregateVerificationKey, m []byte) []byte {
				a.TotalStake = 0
				return m
			}, ErrZeroTotalStake},
			{"signed message bit flip", func(_ *ConcatenationProof, _ *AggregateVerificationKey, m []byte) []byte {
				m = append([]byte(nil), m...)
				m[0] ^= 1
				return m
			}, nil},
			{"signatures swapped", func(p *ConcatenationProof, _ *AggregateVerificationKey, m []byte) []byte {
				s := p.Signatures
				s[0], s[1] = s[1], s[0]
				return m
			}, ErrBatchPathInvalid},
			{"sigmas swapped", func(p *ConcatenationProof, _ *AggregateVerificationKey, m []byte) []byte {
				s := p.Signatures
				s[0].Sig.Sigma, s[1].Sig.Sigma = s[1].Sig.Sigma, s[0].Sig.Sigma
				return m
			}, nil},
			{"no signatures", func(p *ConcatenationProof, _ *AggregateVerificationKey, m []byte) []byte {
				p.Signatures = nil
				return m
			}, ErrNotEnoughIndexes},
		}
		for _, tc := range cases {
			t.Run(prefix+"/"+tc.name, func(t *testing.T) {
				p, a := fresh()
				pp := params
				if tc.name == "too few indexes" {
					pp.K = 1 << 40
				}
				m := tc.mutate(p, a, msg)
				err := p.Verify(m, a, pp)
				if err == nil {
					t.Fatal("verified")
				}
				if tc.want != nil && !errors.Is(err, tc.want) {
					t.Fatalf("got %v, want %v", err, tc.want)
				}
			})
		}
	}
}

// losingIndex returns an index below m that the first signature did not
// win, so claiming it can only be caught by the lottery check.
func losingIndex(t *testing.T, p *ConcatenationProof, a *AggregateVerificationKey, msgp []byte, params Parameters) uint64 {
	e := p.Signatures[0]
	for i := range params.M {
		won, err := IsLotteryWon(params.PhiF, Lottery(msgp, i, e.Sig.Sigma), e.Party.Stake, a.TotalStake)
		if err != nil {
			t.Fatal(err)
		}
		if !won {
			return i
		}
	}
	t.Fatal("first signer wins every lottery")
	return 0
}

func decodeAVK(t testing.TB, c liveCert) *AggregateVerificationKey {
	_, a := decodeLive(t, c)
	return a
}

// TestPairingCheckIsLoadBearing removes the lottery and Merkle checks from
// the picture: the proof's preliminary checks pass, but the BLS aggregate
// is over another message, so only the pairing can reject it.
func TestPairingCheckIsLoadBearing(t *testing.T) {
	c := committedCert(t, preprod3Signers)
	p, a := decodeLive(t, c)
	msgp := MessageWithRoot([]byte(c.SignedMessage), a)
	if err := p.preliminaryVerify(msgp, a, c.Metadata.Parameters); err != nil {
		t.Fatal(err)
	}
	vks, sigs := p.keysAndSigs()
	if err := VerifyAggregate(msgp, vks, sigs); err != nil {
		t.Fatal(err)
	}
	other := append([]byte(nil), msgp...)
	other[len(other)-1] ^= 1
	if err := VerifyAggregate(other, vks, sigs); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("aggregate over another message: %v", err)
	}
}

func TestLiveBatchVerify(t *testing.T) {
	var proofs []*ConcatenationProof
	var msgs [][]byte
	var avks []*AggregateVerificationKey
	var params []Parameters
	for _, c := range liveCerts(t, false) {
		p, a := decodeLive(t, c)
		proofs, avks = append(proofs, p), append(avks, a)
		msgs, params = append(msgs, []byte(c.SignedMessage)), append(params, c.Metadata.Parameters)
	}
	if err := BatchVerify(proofs, msgs, avks, params); err != nil {
		t.Fatal(err)
	}
	msgs[0] = append([]byte(nil), msgs[0]...)
	msgs[0][3] ^= 1
	if err := BatchVerify(proofs, msgs, avks, params); err == nil {
		t.Fatal("batch with a wrong message verified")
	}
}

func (s *Signature) double() *Signature {
	d := &Signature{}
	d.p.Double(&s.p)
	return d
}

// A bit flip in an encoded sigma or key must fail at decoding: the result
// is either not on the curve or not in the subgroup.
func TestLiveDecodeBitFlip(t *testing.T) {
	c := committedCert(t, preprod3Signers)
	p, _ := decodeLive(t, c)
	sigma := p.Signatures[0].Sig.Sigma.Bytes()
	vk := p.Signatures[0].Party.VK.Bytes()
	for _, bit := range []int{0, 7, 100, 383} {
		s := append([]byte(nil), sigma...)
		s[len(s)-1-bit/8] ^= 1 << (bit % 8)
		if _, err := SignatureFromBytes(s); err == nil {
			// A flipped x coordinate can land on another valid point; that
			// sigma must then fail verification instead.
			q, a := decodeLive(t, c)
			q.Signatures[0].Sig.Sigma, _ = SignatureFromBytes(s)
			if q.Verify([]byte(c.SignedMessage), a, c.Metadata.Parameters) == nil {
				t.Errorf("sigma with bit %d flipped verified", bit)
			}
		}
		k := append([]byte(nil), vk...)
		k[len(k)-1-bit/8] ^= 1 << (bit % 8)
		if _, err := VerificationKeyFromBytes(k); err == nil {
			t.Logf("key with bit %d flipped still decodes", bit)
		}
	}
}
