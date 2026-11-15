// SPDX-License-Identifier: Apache-2.0

package difftest

import (
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const corpusDir = "testdata/diff"

// TestRecordedDifferential replays the recorded Rust answers against the Go
// port. It needs neither Rust nor the oracle.
func TestRecordedDifferential(t *testing.T) {
	files, err := ReadCorpus(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no recorded corpus under " + corpusDir)
	}
	for _, name := range SortedKeys(files) {
		t.Run(strings.TrimSuffix(name, ".jsonl"), func(t *testing.T) {
			for i, rec := range files[name] {
				if err := Replay(rec); err != nil {
					t.Errorf("record %d (%s): %v", i+1, rec.Note, err)
				}
			}
		})
	}
}

// RegenEnv, set to 1 together with MITHRIL2PQ_ORACLE, makes
// TestRegenerateCorpus rewrite the recorded corpus.
const RegenEnv = "MITHRIL2PQ_DIFF_REGEN"

// TestRegenerateCorpus asks the oracle about every case below and rewrites
// testdata/diff. Review the diff: a changed answer is a change in Rust or in
// the generators.
func TestRegenerateCorpus(t *testing.T) {
	if os.Getenv(RegenEnv) != "1" || !Enabled() {
		t.Skipf("set %s=1 and %s to regenerate %s", RegenEnv, OracleEnv, corpusDir)
	}
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, cases := range corpusCases() {
		var recs []Record
		for _, c := range cases {
			recs = append(recs, c.Record(t))
		}
		if err := WriteCorpus(filepath.Join(corpusDir, name+".jsonl"), recs); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %d records", name, len(recs))
	}
}

// ops returns n pseudo-random bytes from a fixed stream.
func ops(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func corpusCases() map[string][]Case {
	r := rand.New(rand.NewPCG(2642, 0))
	out := map[string][]Case{}
	add := func(file, note string, req Request) {
		out[file] = append(out[file], Case{Note: note, Req: req})
	}
	gen := func(file, note, g string, args ...any) {
		out[file] = append(out[file], Case{Note: note, Gen: g, Args: args})
	}

	// Target 1: point decoding, every encoding class.
	for mode := range byte(9) {
		for _, d := range [][]byte{[]byte("a"), {0xff, 0x01}, []byte("mithril"), {0x30}} {
			add("points", "G1 class", PointRequest(false, mode, d))
			add("points", "G2 class", PointRequest(true, mode, d))
		}
	}
	add("points", "signature one byte too long", PointRequest(false, 8, []byte{49}))
	add("points", "key one byte too long", PointRequest(true, 8, []byte{97}))

	// Target 2: AVK and proof JSON, strictness of the hand-written codec.
	for f := range byte(len(ProofFixtures())) {
		add("json", "avk", AVKJSONRequest(f, nil))
		gen("json", "proof", "proof_json", f, []byte{})
	}
	for i := range 40 {
		add("json", "avk mutation", AVKJSONRequest(byte(i), ops(r, 2+i%6)))
		gen("json", "proof mutation", "proof_json", byte(i), ops(r, 2+i%6))
	}

	// Target 3: phi_f number parsing.
	for _, s := range []string{"0.2", "0.65", "0.7", "0.8", "0.05", "1", "1.0", "1e0", "0.123", "1E-7", "-0",
		"2.2250738585072011e-308", "0.30000000000000004441", "9007199254740993", "1e400", "-1e400",
		"0.6999999999999901", "4.9406564584124654e-324", "2.4703282292062327e-324", "1.7976931348623157e308",
		"0.10000000000000000555", "0.1000000000000000055511151231257827", "0.00000000010060000100600000000", "123456789012345678901234567890"} {
		req, _ := ParseF64Request(s)
		add("numbers", "phi_f "+s, req)
	}
	for range 30 {
		s := "0." + fmt.Sprintf("%020d", r.Uint64())[:17+r.IntN(4)]
		req, _ := ParseF64Request(s)
		add("numbers", "long decimal", req)
	}

	// Target 4: ln(1 - phi_f) and the lottery.
	for _, p := range append(EdgePhis, 0.6999999999999901, 0.4, 0.1, 0.5, 0.9) {
		add("lottery", "ln1m", Ln1mRequest(math.Float64bits(p)))
	}
	for i := range 60 {
		ev := ops(r, 64)
		stake, total := r.Uint64()%1000+1, r.Uint64()%100000+1000
		if i%5 == 0 {
			stake = total
		}
		add("lottery", "near threshold", LotteryRequest(math.Float64bits([]float64{0.2, 0.65, 0.8, 0.95}[i%4]), ev, stake, total, 1, 0))
	}
	for range 40 {
		add("lottery", "ln1m, uniform phi", Ln1mRequest(math.Float64bits(r.Float64())))
	}
	for i := range len(EdgePhis) {
		add("lottery", "edge phi", LotteryRequest(uint64(i), ops(r, 64), 1, 3, 0, 1))
		add("lottery", "edge phi, zero total stake", LotteryRequest(uint64(i), nil, 1, 0, 0, 1))
	}
	for i := range 6 {
		add("lottery", "dense mapping", EVRequest(byte(i), ops(r, i*7), r.Uint64()>>uint(i*10)))
	}

	// Target 5: batch paths.
	for i := range 50 {
		var o []byte
		if i >= 10 {
			o = ops(r, 2*(1+i%4))
		}
		gen("merkle", "batch path", "batch_path", byte(r.Uint32()), r.Uint64(), o)
	}

	// Target 6: full proof verification with structure-aware mutations.
	for f := range byte(len(ProofFixtures())) {
		gen("proofs", "valid", "proof", f, []byte{})
		for _, op := range [][]byte{{2, 0, 0}, {2, 0, 16}, {9, 1, 0}, {7, 0, 1}, {12, 0, 0}, {1, 0, 0}, {16, 0, 0}, {11, 0, 2}, {10, 0, 3}, {18, 1, 5}} {
			gen("proofs", "targeted mutation", "proof", f, op)
		}
	}
	for i := range 40 {
		gen("proofs", "random mutation", "proof", byte(i), ops(r, 3*(1+i%3)))
	}

	// Target 7: aggregation.
	for i := range 20 {
		gen("aggregate", "aggregate", "aggregate", i%2 == 0, ops(r, i%5), ops(r, 2*(i%6)))
	}

	// Target 8: hashes of parameters and certificates.
	for mode := range byte(6) {
		for range 6 {
			add("hashes", "parameters", ParamsHashRequest(r.Uint64()%1000, r.Uint64()%10000, r.Uint64(), mode))
		}
	}
	for f := range byte(len(LiveCerts()) + 4) {
		gen("certs", "live or synthetic certificate hash", "cert_hash", f, []byte{}, []byte{})
	}
	for i := range len(Timestamps) {
		gen("certs", "timestamp "+Timestamps[i], "cert_hash", byte(i%3), []byte{12, byte(2 * i)}, []byte{})
	}
	snark := TimestampRequest(Timestamps[0])
	snark["cert"] = strings.Replace(snark.str("cert"), `{"hash"`, `{"aggregate_verification_key_snark":"00","hash"`, 1)
	add("certs", "SNARK-era field", snark)
	for i := range 25 {
		gen("certs", "field mutation", "cert_hash", byte(i), ops(r, 2*(1+i%3)), []byte{})
	}

	// Target 9: chain rules on live and synthetic pairs.
	for i := range LivePairCount() {
		gen("chain", "live pair", "live_verify", i)
	}
	for p := range byte(len(CertPairs)) {
		gen("chain", "synthetic pair", "cert_verify", p, []byte{})
	}
	gen("chain", "genesis AVK not its next AVK (main-branch rule)", "cert_verify", byte(0), []byte{3, 5, 0, 7})
	gen("chain", "genesis parameters not its next parameters (main-branch rule)", "cert_verify", byte(0), []byte{4, 3, 0, 7})
	gen("chain", "certificate in the genesis epoch (main-branch rule)", "cert_verify", byte(1), []byte{5, 6, 0, 0, 0, 1, 0, 7})
	gen("chain", "previous certificate with a rigid hash scheme", "cert_verify", byte(2), []byte{14, 1, 1, 0})
	gen("chain", "leap-second timestamp", "cert_verify", byte(3), []byte{12, 48, 0, 7})
	for i := range 30 {
		gen("chain", "synthetic pair mutation", "cert_verify", byte(i), ops(r, 4*(1+i%2)))
	}

	// Target 10: Ed25519 verify_strict.
	for mode := range byte(10) {
		for _, d := range [][]byte{{0}, {1, 9}, {2}, {3}, {4, 4, 4}, {5}, {6}, {7}} {
			add("ed25519", "class", Ed25519Request(mode, d))
		}
	}

	// Target 11: seeded signing parity.
	gen("gen", "Mithril's golden aggregate signature", "gen", []byte{}, []byte{1, 1}, uint8(9), uint8(5), uint8(3), make([]byte, 16))
	for i := range 8 {
		gen("gen", "seeded", "gen", ops(r, 4), ops(r, 1+i%4), uint8(r.Uint32()), uint8(r.Uint32()), uint8(i), ops(r, 8))
	}
	gen("gen", "zero total stake", "gen", []byte{9}, []byte{0, 0}, uint8(5), uint8(1), uint8(0), []byte("z"))
	gen("gen", "total stake overflow", "gen", []byte{9}, []byte{0xff, 1}, uint8(5), uint8(1), uint8(0), []byte("o"))
	return out
}
