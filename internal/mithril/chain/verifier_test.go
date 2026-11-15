// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"filippo.io/edwards25519"
)

func mapFetcher(certs map[string]*Certificate) Fetcher {
	return func(_ context.Context, hash string) (*Certificate, error) {
		c, ok := certs[hash]
		if !ok {
			return nil, fmt.Errorf("certificate %s not saved", hash)
		}
		cc := *c
		return &cc, nil
	}
}

// chainStart returns the certificate no other certificate points to: the
// newest one saved.
func chainStart(t testing.TB, certs map[string]*Certificate) *Certificate {
	t.Helper()
	pointed := map[string]bool{}
	for _, c := range certs {
		pointed[c.PreviousHash] = true
	}
	var start *Certificate
	for h, c := range certs {
		if !pointed[h] {
			if start != nil {
				t.Fatalf("two chain heads: %s and %s", start.Hash, h)
			}
			start = c
		}
	}
	return start
}

const preprodHead = "172f78406dfbb005f41f35333e6707e3812f32d7d3e136ee030b1bf8f6970f52"

func TestVerifyCommittedChain(t *testing.T) {
	certs := loadDir(t, "../testdata/certs/preprod")
	key, _ := NetworkGenesisKey("preprod")
	res, err := Verify(context.Background(), certs[preprodHead], key, mapFetcher(certs), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Genesis == nil || res.Genesis.Epoch != 196 || len(res.Verified) != len(certs) {
		t.Fatalf("result %+v", res)
	}
	mainnet, _ := NetworkGenesisKey("mainnet")
	if _, err := Verify(context.Background(), certs[preprodHead], mainnet, mapFetcher(certs), Options{}); !errors.Is(err, ErrGenesisSignature) {
		t.Fatalf("preprod chain under the mainnet key: %v", err)
	}
}

// TestVerifyCachedChains walks each saved chain from its newest
// certificate to genesis. The mainnet walk checks about 130 certificates of
// some 50 signers each and is skipped with -short.
func TestVerifyCachedChains(t *testing.T) {
	chains := cachedChains(t)
	if len(chains) == 0 {
		t.Skip("no chains saved under ~/.cache/mithril2pq-certs")
	}
	for net, certs := range chains {
		t.Run(net, func(t *testing.T) {
			if net == "mainnet" && testing.Short() {
				t.Skip("mainnet chain walk skipped in short mode")
			}
			key, _ := NetworkGenesisKey(net)
			start := chainStart(t, certs)
			res, err := Verify(context.Background(), start, key, mapFetcher(certs), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if res.Genesis == nil || len(res.Verified) != len(certs) {
				t.Fatalf("verified %d of %d, genesis %v", len(res.Verified), len(certs), res.Genesis != nil)
			}
			t.Logf("%s: %d certificates from epoch %d back to genesis epoch %d", net, len(res.Verified), start.Epoch, res.Genesis.Epoch)
		})
	}
}

func TestVerifyStopsAtTrusted(t *testing.T) {
	certs := loadDir(t, "../testdata/certs/preprod")
	key, _ := NetworkGenesisKey("preprod")
	full, err := Verify(context.Background(), certs[preprodHead], key, mapFetcher(certs), Options{})
	if err != nil {
		t.Fatal(err)
	}
	trusted := full.Verified[2]
	res, err := Verify(context.Background(), certs[preprodHead], key, mapFetcher(certs), Options{
		Trusted: func(h string) bool { return h == trusted },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.StoppedAt == nil || res.StoppedAt.Hash != trusted || len(res.Verified) != 3 || res.Genesis != nil {
		t.Fatalf("result %+v", res)
	}
	// A trusted hash served with other content is not trusted.
	tampered := map[string]*Certificate{}
	for h, c := range certs {
		tampered[h] = c
	}
	bad := *certs[trusted]
	bad.Metadata.Network = "mainnet"
	tampered[trusted] = &bad
	if _, err := Verify(context.Background(), certs[preprodHead], key, mapFetcher(tampered), Options{
		Trusted: func(h string) bool { return h == trusted },
	}); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("tampered trusted certificate: %v", err)
	}
}

// pair returns a standard certificate and its previous certificate from the
// committed chain, decoded, the first in a new epoch.
func pair(t *testing.T, epoch uint64) (c, p *decoded) {
	t.Helper()
	certs := loadDir(t, "../testdata/certs/preprod")
	for _, x := range certs {
		if x.Epoch == epoch && !x.IsGenesis() {
			dc, err := decode(x)
			if err != nil {
				t.Fatal(err)
			}
			dp, err := decode(certs[x.PreviousHash])
			if err != nil {
				t.Fatal(err)
			}
			return dc, dp
		}
	}
	t.Fatalf("no certificate in epoch %d", epoch)
	return nil, nil
}

// TestStandardRules breaks one link rule at a time on a valid pair and
// expects that rule's error.
func TestStandardRules(t *testing.T) {
	c, p := pair(t, 201)
	if err := verifyStandard(c, p); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(c, p *decoded)
		want   error
	}{
		{"self loop", func(c, p *decoded) { c.PreviousHash = c.Hash }, ErrInfiniteLoop},
		{"content changed", func(c, p *decoded) { c.Metadata.Signers[0].Stake++ }, ErrHashMismatch},
		{"previous hash", func(c, p *decoded) { p.Hash = c.Hash }, ErrPreviousHashMismatch},
		{"epoch gap back", func(c, p *decoded) { p.Epoch = c.Epoch - 2 }, ErrMissingEpoch},
		{"epoch gap forward", func(c, p *decoded) { p.Epoch = c.Epoch + 2 }, ErrMissingEpoch},
		{"next AVK", func(c, p *decoded) {
			p.ProtocolMessage.MessageParts = clone(p.ProtocolMessage.MessageParts)
			p.ProtocolMessage.MessageParts["next_aggregate_verification_key"] = c.ProtocolMessage.MessageParts["next_aggregate_verification_key"]
		}, ErrAVKMismatch},
		{"next AVK missing", func(c, p *decoded) {
			p.ProtocolMessage.MessageParts = clone(p.ProtocolMessage.MessageParts)
			delete(p.ProtocolMessage.MessageParts, "next_aggregate_verification_key")
		}, ErrAVKMismatch},
		{"next parameters", func(c, p *decoded) {
			p.ProtocolMessage.MessageParts = clone(p.ProtocolMessage.MessageParts)
			p.ProtocolMessage.MessageParts["next_protocol_parameters"] = "00"
		}, ErrParametersMismatch},
		{"same epoch AVK", func(c, p *decoded) {
			p.Epoch = c.Epoch
			a := *p.avk
			a.TotalStake++
			p.avk = &a
		}, ErrAVKMismatch},
		{"same epoch parameters", func(c, p *decoded) {
			p.Epoch = c.Epoch
			p.avk = c.avk
			p.Metadata.Parameters.K++
		}, ErrParametersMismatch},
		{"multi-signature", func(c, p *decoded) {
			c.multiSig.Signatures = c.multiSig.Signatures[1:]
			c.multiSig.BatchPath.Indices = c.multiSig.BatchPath.Indices[1:]
			c.Hash, _ = c.computeHash()
		}, ErrMultiSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, p := pair(t, 201)
			tc.mutate(c, p)
			if err := verifyStandard(c, p); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func clone(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestEpochAfterGenesis(t *testing.T) {
	c, g := pair(t, 197)
	if !g.IsGenesis() {
		t.Fatal("epoch 197 does not follow genesis")
	}
	if err := verifyStandard(c, g); err != nil {
		t.Fatal(err)
	}
	g.Epoch = c.Epoch
	if err := verifyStandard(c, g); !errors.Is(err, ErrEpochAfterGenesis) {
		t.Fatalf("got %v", err)
	}
}

func TestEpochPart(t *testing.T) {
	c, _ := pair(t, 201)
	c.Epoch++
	if err := c.checkEpochPart(); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("got %v", err)
	}
	delete(c.ProtocolMessage.MessageParts, "current_epoch")
	if err := c.checkEpochPart(); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("got %v", err)
	}
}

// TestGenesisRules covers what the genesis key does and does not sign: it
// signs only the signed message, so an AVK or parameters swapped into the
// certificate (with its hash recomputed) pass the signature check and must
// be caught by comparison with the signed message's next-epoch parts.
func TestGenesisRules(t *testing.T) {
	key, _ := NetworkGenesisKey("preprod")
	genesis := func() *decoded {
		_, g := pair(t, 197)
		return g
	}
	if err := verifyGenesis(genesis(), key); err != nil {
		t.Fatal(err)
	}
	other, _ := NetworkGenesisKey("mainnet")
	if err := verifyGenesis(genesis(), other); !errors.Is(err, ErrGenesisSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	c, _ := pair(t, 201)
	g := genesis()
	g.avk = c.avk
	g.Hash, _ = g.computeHash()
	if err := verifyGenesis(g, key); !errors.Is(err, ErrGenesisAVKMismatch) {
		t.Fatalf("swapped AVK: %v", err)
	}
	g = genesis()
	g.Metadata.Parameters.K++
	g.Hash, _ = g.computeHash()
	if err := verifyGenesis(g, key); !errors.Is(err, ErrGenesisParamsMismatch) {
		t.Fatalf("swapped parameters: %v", err)
	}
	g = genesis()
	g.genesis = append([]byte(nil), g.genesis...)
	g.genesis[10] ^= 1
	g.Hash, _ = g.computeHash()
	if err := verifyGenesis(g, key); !errors.Is(err, ErrGenesisSignature) {
		t.Fatalf("flipped signature bit: %v", err)
	}
}

func TestParseGenesisKey(t *testing.T) {
	// GOLDEN_ED25519_VERIFICATION_KEY in mithril-common/src/crypto_helper/ed25519.rs.
	k, err := ParseGenesisKey("5b32332c32372c3131322c362c35372c38342c3138302c342c3135302c3233322c3233372c3132362c3131392c3231342c33352c35342c38312c3230382c3231372c39392c3137302c3233312c3133392c362c3132322c39342c39322c3137322c32332c3130322c3135372c3136375d\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := k.String(); got != "171b70063954b40496e8ed7e77d6233651d0d963aae78b067a5e5cac17669da7" {
		t.Fatalf("key %s", got)
	}
	plain, err := ParseGenesisKey(k.String())
	if err != nil || plain.String() != k.String() {
		t.Fatalf("plain hex: %v", err)
	}
	m, _ := NetworkGenesisKey("mainnet")
	if m.String() != "bf428cb98a0bedcffa901b02bc1e0c519bcc0ab34b178ac4d9050e14394f27b0" {
		t.Fatalf("mainnet key %s", m)
	}
	p, _ := NetworkGenesisKey("preprod")
	if p.String() != "7f497ca1068983d5cf75c655b0c7a2f1447b77910de8f331e502f9cdcd27eb2c" {
		t.Fatalf("preprod key %s", p)
	}
	for _, bad := range []string{"", "abc", "01200000", "5b312c325d", hex.EncodeToString([]byte("[1,2,300]"))} {
		if _, err := ParseGenesisKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestVerifyStrictSmallOrderR builds a signature whose R is the identity
// point. Go's ed25519.Verify accepts it; ed25519-dalek's verify_strict, and
// so Mithril, does not.
func TestVerifyStrictSmallOrderR(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	h := sha512.Sum512(seed)
	a, err := new(edwards25519.Scalar).SetBytesWithClamping(h[:32])
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("signed message")
	r := edwards25519.NewIdentityPoint().Bytes()
	kh := sha512.New()
	kh.Write(r)
	kh.Write(pub)
	kh.Write(msg)
	k, err := new(edwards25519.Scalar).SetUniformBytes(kh.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	s := new(edwards25519.Scalar).Multiply(k, a)
	sig := append(append([]byte(nil), r...), s.Bytes()...)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("crafted signature does not pass ed25519.Verify; the test is not exercising anything")
	}
	if verifyStrict(GenesisKey(pub), msg, sig) {
		t.Fatal("small-order R accepted")
	}
	if !verifyStrict(GenesisKey(pub), msg, ed25519.Sign(priv, msg)) {
		t.Fatal("ordinary signature rejected")
	}
}
