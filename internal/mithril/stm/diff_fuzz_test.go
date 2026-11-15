// SPDX-License-Identifier: Apache-2.0

package stm_test

// Differential fuzz targets: each builds a request, answers it with the Go
// port and, when MITHRIL2PQ_ORACLE names the Rust oracle, compares with
// mithril-stm. See fuzz/oracle/README.md.

import (
	"math"
	"testing"

	"github.com/chrisguiney/mithril2pq/internal/mithril/difftest"
)

func FuzzSigDecode(f *testing.F) {
	for m := range byte(9) {
		f.Add(m, []byte("seed"))
		f.Add(m, []byte{0x01, 0xff, 0x80})
	}
	f.Fuzz(func(t *testing.T, mode byte, data []byte) {
		difftest.Check(t, difftest.PointRequest(false, mode, data))
	})
}

func FuzzVKDecode(f *testing.F) {
	for m := range byte(9) {
		f.Add(m, []byte("seed"))
		f.Add(m, []byte{0x01, 0xff, 0x81})
	}
	f.Fuzz(func(t *testing.T, mode byte, data []byte) {
		difftest.Check(t, difftest.PointRequest(true, mode, data))
	})
}

func FuzzAVKJSON(f *testing.F) {
	for i := range byte(len(difftest.ProofFixtures())) {
		f.Add(i, []byte{})
		f.Add(i, []byte{0, 3, 1, 9, 4, 0x47})
	}
	f.Fuzz(func(t *testing.T, fixture byte, ops []byte) {
		difftest.Check(t, difftest.AVKJSONRequest(fixture, ops))
	})
}

func FuzzProofJSON(f *testing.F) {
	for i := range byte(len(difftest.ProofFixtures())) {
		f.Add(i, []byte{})
		f.Add(i, []byte{1, 5, 4, 0x93, 2, 17})
	}
	f.Fuzz(func(t *testing.T, fixture byte, ops []byte) {
		difftest.Check(t, difftest.ProofJSONRequest(fixture, ops))
	})
}

func FuzzParseF64(f *testing.F) {
	for _, s := range []string{"0.2", "0.65", "0.7", "1e-7", "0.123", "2.2250738585072011e-308",
		"0.30000000000000004441", "9007199254740993", "1e400", "-0", "0.1e1", "1E+2"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if r, ok := difftest.ParseF64Request(s); ok {
			difftest.Check(t, r)
		}
	})
}

func FuzzLn1m(f *testing.F) {
	for _, p := range []float64{0.2, 0.4, 0.65, 0.7, 0.8, 1e-300, 0.999999, 0.6999999999999901} {
		f.Add(math.Float64bits(p))
	}
	f.Fuzz(func(t *testing.T, bits uint64) {
		difftest.Check(t, difftest.Ln1mRequest(bits))
	})
}

func FuzzLottery(f *testing.F) {
	f.Add(math.Float64bits(0.7), make([]byte, 64), uint64(1), uint64(2), byte(0), byte(0))
	f.Add(math.Float64bits(0.2), []byte{0xff, 0xff}, uint64(1), uint64(1), byte(1), byte(0))
	f.Add(uint64(7), []byte{}, uint64(3), uint64(10), byte(1), byte(1))
	f.Fuzz(func(t *testing.T, phiBits uint64, ev []byte, stake, total uint64, near, sel byte) {
		difftest.Check(t, difftest.LotteryRequest(phiBits, ev, stake, total, near, sel))
	})
}

func FuzzDenseMapping(f *testing.F) {
	f.Add(byte(0), []byte("message"), uint64(0))
	f.Add(byte(3), []byte{}, uint64(math.MaxUint64))
	f.Fuzz(func(t *testing.T, key byte, msgp []byte, index uint64) {
		difftest.Check(t, difftest.EVRequest(key, msgp, index))
	})
}

func FuzzBatchPath(f *testing.F) {
	f.Add(byte(0), uint64(1), []byte{})
	f.Add(byte(7), uint64(0b1011), []byte{0, 2})
	f.Add(byte(16), uint64(0xffff), []byte{1, 9, 3, 1})
	f.Add(byte(39), uint64(1<<39|1), []byte{8, 0, 6, 1})
	f.Fuzz(func(t *testing.T, n byte, sel uint64, ops []byte) {
		difftest.Check(t, difftest.BatchPathRequest(n, sel, ops))
	})
}

func FuzzProofVerify(f *testing.F) {
	for i := range byte(len(difftest.ProofFixtures())) {
		f.Add(i, []byte{})
	}
	f.Add(byte(1), []byte{2, 0, 0})  // index m
	f.Add(byte(1), []byte{2, 0, 16}) // index m+1
	f.Add(byte(2), []byte{9, 1, 0})  // duplicate entry
	f.Add(byte(2), []byte{7, 0, 1})  // swap entries
	f.Add(byte(0), []byte{12, 0, 0}) // total stake + 1
	f.Add(byte(2), []byte{10, 0, 3}) // drop a batch path value
	f.Add(byte(3), []byte{1, 0, 0})  // negated sigma
	f.Add(byte(4), []byte{11, 0, 2}) // duplicate batch path index
	f.Add(byte(5), []byte{18, 1, 5}) // corrupt sigma bytes
	f.Add(byte(2), []byte{16, 0, 0}) // m + 1
	f.Fuzz(func(t *testing.T, fixture byte, ops []byte) {
		difftest.Check(t, difftest.MutateProof(fixture, ops))
	})
}

func FuzzAggregate(f *testing.F) {
	f.Add(false, []byte("msg"), []byte{0, 3, 1, 3})
	f.Add(true, []byte("msg"), []byte{0, 3, 1, 3, 2, 3})
	f.Add(true, []byte("msg"), []byte{0, 3, 0, 3})
	f.Add(true, []byte{}, []byte{0, 1})
	f.Add(true, []byte("msg"), []byte{})
	f.Fuzz(func(t *testing.T, verify bool, msg, ops []byte) {
		difftest.Check(t, difftest.AggregateRequest(verify, msg, ops))
	})
}

func FuzzGen(f *testing.F) {
	f.Add([]byte{}, []byte{1, 1}, uint8(9), uint8(5), uint8(3), []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{7}, []byte{10, 20, 30}, uint8(19), uint8(6), uint8(2), []byte("m"))
	f.Add([]byte{9}, []byte{0, 0}, uint8(5), uint8(1), uint8(0), []byte("zero stake"))
	f.Add([]byte{9}, []byte{0xff, 1}, uint8(5), uint8(1), uint8(0), []byte("overflow"))
	f.Fuzz(func(t *testing.T, seed, stakes []byte, m, k, phi uint8, msg []byte) {
		difftest.Check(t, difftest.GenRequest(seed, stakes, m, k, phi, msg))
	})
}
