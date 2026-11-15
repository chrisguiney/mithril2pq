// SPDX-License-Identifier: Apache-2.0

package stm

import (
	"errors"
	"math"
	"math/big"
	"testing"
)

// The lottery threshold uses the float64 ln(1 - phi_f). Rust's f64::ln is
// the platform libm (glibc for Mithril's Linux builds); Go's math.Log is a
// separate implementation. They must agree to the bit for the phi_f values
// Mithril networks use, or borderline tickets could be judged differently.
// Expected values are glibc's log, read as hex floats.
func TestLogMatchesGlibc(t *testing.T) {
	for _, tc := range []struct {
		phiF float64
		want float64
	}{
		{0.2, -0x1.c8ff7c79a9a20p-3},
		{0.4, -0x1.058aefa811452p-1},
		{0.65, -0x1.0cc1248b56cccp+0},
		{0.7, -0x1.34378fcbda720p+0},
		{0.8, -0x1.9c041f7ed8d34p+0},
	} {
		if got := math.Log(1 - tc.phiF); got != tc.want {
			t.Errorf("ln(1 - %v) = %x, glibc gives %x", tc.phiF, got, tc.want)
		}
	}
}

func evFromLE(x *big.Int) [64]byte {
	var ev [64]byte
	b := x.FillBytes(make([]byte, 64))
	for i := range b {
		ev[63-i] = b[i]
	}
	return ev
}

func TestIsLotteryWonEdges(t *testing.T) {
	var zero [64]byte
	if _, err := IsLotteryWon(0.2, zero, 1, 0); !errors.Is(err, ErrZeroTotalStake) {
		t.Errorf("zero total stake: %v", err)
	}
	for _, phi := range []float64{0, -0.1, 1.5, math.NaN()} {
		if _, err := IsLotteryWon(phi, zero, 1, 2); !errors.Is(err, ErrPhiFOutOfRange) {
			t.Errorf("phi_f %v: %v", phi, err)
		}
	}
	var max [64]byte
	for i := range max {
		max[i] = 0xff
	}
	if won, err := IsLotteryWon(1, max, 0, 2); err != nil || !won {
		t.Errorf("phi_f = 1 must always win: %v %v", won, err)
	}
	if won, _ := IsLotteryWon(0.2, zero, 1, 1000); !won {
		t.Error("ticket 0 must win with any stake")
	}
	if won, _ := IsLotteryWon(0.2, max, 1000, 1000); won {
		t.Error("the largest ticket must lose")
	}
	if won, _ := IsLotteryWon(0.2, zero, 0, 1000); won {
		t.Error("zero stake must lose even ticket 0: 1 < exp(0) is false")
	}
}

// TestIsLotteryWonThreshold checks the exact decision against the float
// threshold phi = 1 - (1 - phi_f)^w for tickets well clear of it.
func TestIsLotteryWonThreshold(t *testing.T) {
	two512 := new(big.Float).SetInt(evMax)
	for _, tc := range []struct {
		phiF         float64
		stake, total uint64
	}{
		{0.2, 1, 1}, {0.2, 3, 10}, {0.65, 1, 100}, {0.7, 9999, 10000}, {0.4, 1, 3_000_000},
	} {
		w := float64(tc.stake) / float64(tc.total)
		phi := 1 - math.Pow(1-tc.phiF, w)
		for _, f := range []float64{0.5, 0.99, 1.01, 1.5} {
			x := new(big.Float).Mul(two512, big.NewFloat(phi*f))
			n, _ := x.Int(nil)
			if n.Cmp(evMax) >= 0 {
				continue
			}
			won, err := IsLotteryWon(tc.phiF, evFromLE(n), tc.stake, tc.total)
			if err != nil {
				t.Fatal(err)
			}
			if won != (f < 1) {
				t.Errorf("phi_f %v w %v: ticket at %v of the threshold: won = %v", tc.phiF, w, f, won)
			}
		}
	}
}
