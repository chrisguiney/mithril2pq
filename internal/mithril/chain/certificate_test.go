// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// loadDir reads every certificate saved as <hash>.json in dir.
func loadDir(t testing.TB, dir string) map[string]*Certificate {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*Certificate{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var c Certificate
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out[c.Hash] = &c
	}
	return out
}

// cachedChains returns the chains saved under ~/.cache/mithril2pq-certs, by
// network, or nil when there are none.
func cachedChains(t testing.TB) map[string]map[string]*Certificate {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	out := map[string]map[string]*Certificate{}
	for _, net := range []string{"mainnet", "preprod", "preview"} {
		if certs := loadDir(t, filepath.Join(home, ".cache/mithril2pq-certs", net)); len(certs) > 0 {
			out[net] = certs
		}
	}
	return out
}

func committed(t testing.TB) map[string]*Certificate {
	out := loadDir(t, "../testdata/certs/preprod")
	for h, c := range loadDir(t, "../testdata/certs/mainnet") {
		out[h] = c
	}
	return out
}

// ProtocolParameters::new(1000, 100, 0.123) hash, from
// mithril-common/src/entities/protocol_parameters.rs tests.
func TestProtocolParametersHashKAT(t *testing.T) {
	got, err := ProtocolParameters{K: 1000, M: 100, PhiF: 0.123}.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if want := "ace019657cd995b0dfbb1ce8721a1092715972c4ae0171cc636ab4a44e6e4279"; got != want {
		t.Fatalf("hash %s, want %s", got, want)
	}
}

// Expected values are U8F24::from_num(x).to_bits() printed by the fixed
// crate 1.31.0 (the version in Mithril's Cargo.lock): round to nearest,
// ties to even.
func TestU8F24(t *testing.T) {
	two25 := math.Ldexp(1, -25)
	for _, tc := range []struct {
		x    float64
		want uint32
	}{
		{0.123, 2063598}, {0.2, 3355443}, {0.65, 10905190}, {0.7, 11744051}, {0.8, 13421773},
		{1 * two25, 0}, {3 * two25, 2}, {5 * two25, 2}, {0.5 + two25, 8388608}, {0.5 + 3*two25, 8388610},
	} {
		got, err := U8F24(tc.x)
		if err != nil || got != tc.want {
			t.Errorf("U8F24(%v) = %d, %v; want %d", tc.x, got, err, tc.want)
		}
	}
	for _, x := range []float64{-0.1, 256, math.NaN(), math.Inf(1)} {
		if _, err := U8F24(x); err == nil {
			t.Errorf("U8F24(%v) accepted", x)
		}
	}
}

// TestCertificateHashes recomputes the hash of every saved certificate,
// standard and genesis, on every network.
func TestCertificateHashes(t *testing.T) {
	sets := map[string]map[string]*Certificate{"committed": committed(t)}
	for net, certs := range cachedChains(t) {
		sets[net] = certs
	}
	for name, certs := range sets {
		genesis := 0
		for h, c := range certs {
			got, err := c.ComputeHash()
			if err != nil {
				t.Errorf("%s %s: %v", name, h, err)
				continue
			}
			if got != h {
				t.Errorf("%s %s: computed hash %s", name, h, got)
			}
			if c.IsGenesis() {
				genesis++
			}
		}
		t.Logf("%s: %d certificate hashes match (%d genesis)", name, len(certs), genesis)
	}
}

// TestHashIgnoresWireSpacing re-encodes the AVK and multi-signature with
// whitespace: the hash is over the canonical re-encoding, so it must not
// change.
func TestHashIgnoresWireSpacing(t *testing.T) {
	for _, c := range committed(t) {
		if c.IsGenesis() {
			continue
		}
		cc := *c
		var avk, ms json.RawMessage
		if err := DecodeJSONHex(c.AggregateVerificationKey, &avk); err != nil {
			t.Fatal(err)
		}
		if err := DecodeJSONHex(c.MultiSignature, &ms); err != nil {
			t.Fatal(err)
		}
		spaced := func(b []byte) string {
			out, _ := json.MarshalIndent(json.RawMessage(b), "", "  ")
			return hexUpper(out)
		}
		cc.AggregateVerificationKey, cc.MultiSignature = spaced(avk), spaced(ms)
		if got, err := cc.ComputeHash(); err != nil || got != c.Hash {
			t.Fatalf("%s: %s %v", c.Hash, got, err)
		}
		return
	}
}

func hexUpper(b []byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, 0, 2*len(b)+2)
	out = append(out, ' ')
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&15])
	}
	return string(append(out, '\n'))
}

func TestSnarkFieldsRejected(t *testing.T) {
	for _, c := range committed(t) {
		cc := *c
		s := "00"
		cc.AncillaryVerifierData = &s
		if _, err := cc.ComputeHash(); err == nil {
			t.Fatal("certificate with ancillary data accepted")
		}
		return
	}
}
