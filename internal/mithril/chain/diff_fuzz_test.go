// SPDX-License-Identifier: Apache-2.0

package chain_test

// Differential fuzz targets against mithril-common; see
// fuzz/oracle/README.md.

import (
	"math"
	"testing"

	"github.com/chrisguiney/mithril2pq/internal/mithril/difftest"
)

func FuzzParamsHash(f *testing.F) {
	for mode := range byte(6) {
		f.Add(uint64(5), uint64(100), math.Float64bits(0.65), mode)
	}
	f.Fuzz(func(t *testing.T, k, m, phiBits uint64, mode byte) {
		difftest.Check(t, difftest.ParamsHashRequest(k, m, phiBits, mode))
	})
}

func FuzzCertHash(f *testing.F) {
	for i := range byte(11) {
		f.Add(i, []byte{}, []byte{})
	}
	f.Add(byte(0), []byte{12, 6}, []byte{})
	f.Add(byte(1), []byte{12, 13}, []byte{})
	f.Add(byte(2), []byte{6, 11}, []byte{})
	f.Add(byte(8), []byte{10, 7}, []byte{})
	f.Add(byte(3), []byte{}, []byte{0, 0, 1, 2})
	f.Fuzz(func(t *testing.T, fixture byte, ops, jsonOps []byte) {
		difftest.Check(t, difftest.CertHashRequest(fixture, ops, jsonOps))
	})
}

func FuzzTimestamp(f *testing.F) {
	for _, ts := range difftest.Timestamps {
		f.Add(ts)
	}
	f.Fuzz(func(t *testing.T, ts string) {
		difftest.Check(t, difftest.TimestampRequest(ts))
	})
}

func FuzzCertVerify(f *testing.F) {
	for p := range byte(len(difftest.CertPairs)) {
		f.Add(p, []byte{})
	}
	f.Add(byte(1), []byte{0, 0, 0, 7})  // epoch + 1, resealed
	f.Add(byte(2), []byte{2, 2, 0, 7})  // phi_f + 1 ulp
	f.Add(byte(3), []byte{3, 0, 1, 15}) // previous's next AVK
	f.Add(byte(0), []byte{3, 0, 0, 7})  // genesis next AVK
	f.Add(byte(1), []byte{5, 2, 0, 7})  // current_epoch "011"
	f.Fuzz(func(t *testing.T, pair byte, ops []byte) {
		difftest.Check(t, difftest.CertVerifyRequest(pair, ops))
	})
}

func FuzzEd25519(f *testing.F) {
	for m := range byte(10) {
		f.Add(m, []byte("seed"))
		f.Add(m, []byte{1, 2, 3, 4, 5, 6, 7})
	}
	f.Fuzz(func(t *testing.T, mode byte, data []byte) {
		difftest.Check(t, difftest.Ed25519Request(mode, data))
	})
}
