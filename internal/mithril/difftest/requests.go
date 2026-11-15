// SPDX-License-Identifier: Apache-2.0

package difftest

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"sync"

	"github.com/chrisguiney/mithril2pq/internal/mithril/stm"
)

// EdgePhis are phi_f values on the boundaries of the lottery's and the
// fixed-point conversion's domains.
var EdgePhis = []float64{
	0.2, 0.65, 0.7, 0.8, 0.95,
	1, math.Nextafter(1, 0), 1 - 2.220446049250313e-16, 1 - 1.1102230246251565e-16, 1 + 2.220446049250313e-16,
	0, math.Copysign(0, -1), 5e-324, 2.2250738585072014e-308, 1e-300, 1e-17,
	-0.5, 2, 255.99999994039536, 256, math.Inf(1), math.Inf(-1), math.NaN(),
	0.5 / (1 << 24), 1.5 / (1 << 24), 0.123,
}

// Ln1mRequest asks for ln(1 - phi) as the lottery computes it.
func Ln1mRequest(phiBits uint64) Request {
	return Request{"op": "ln1m", "phi": Bits(math.Float64frombits(phiBits))}
}

// LotteryRequest builds an is_lottery_won request. With near set, the
// ticket is placed near the winning threshold for (phi, stake, total) so
// the Taylor series runs long; sel picks phi from EdgePhis instead of
// phiBits when odd.
func LotteryRequest(phiBits uint64, ev []byte, stake, total uint64, near, sel byte) Request {
	phi := math.Float64frombits(phiBits)
	if sel&1 == 1 {
		phi = EdgePhis[int(phiBits%uint64(len(EdgePhis)))]
	}
	var e [64]byte
	copy(e[:], ev)
	if near&1 == 1 && phi > 0 && phi < 1 && total != 0 && stake <= total {
		w := float64(stake) / float64(total)
		pr := 1 - math.Pow(1-phi, w)
		binary.LittleEndian.PutUint64(e[56:], uint64(pr*(1<<63))<<1)
	}
	return Request{"op": "lottery", "phi": Bits(phi), "ev": hexOf(e[:]), "stake": stake, "total": total}
}

// ParseF64Request asks how a JSON number parses, or returns false for text
// that is not a JSON value (both sides would reject it for unrelated
// reasons).
func ParseF64Request(s string) (Request, bool) {
	if !json.Valid([]byte(s)) {
		return nil, false
	}
	return Request{"op": "parse_f64", "s": s}, true
}

// ParamsHashRequest builds a ProtocolParameters::compute_hash request. mode
// selects phi: raw bits, an exact U8F24 tie, a tie one ulp away, an exact
// U8F24 value, or an edge value.
func ParamsHashRequest(k, m, phiBits uint64, mode byte) Request {
	phi := math.Float64frombits(phiBits)
	n := float64(phiBits % (1 << 32))
	switch mode % 6 {
	case 1:
		phi = (n + 0.5) / (1 << 24)
	case 2:
		phi = math.Nextafter((n+0.5)/(1<<24), 0)
	case 3:
		phi = math.Nextafter((n+0.5)/(1<<24), math.Inf(1))
	case 4:
		phi = n / (1 << 24)
	case 5:
		phi = EdgePhis[int(phiBits%uint64(len(EdgePhis)))]
	}
	return Request{"op": "params_hash", "k": k, "m": m, "phi": Bits(phi)}
}

var keyPool = sync.OnceValue(func() []*stm.SigningKey {
	rng := stm.NewChaChaRNG([32]byte{'d', 'i', 'f', 'f'})
	keys := make([]*stm.SigningKey, 8)
	for i := range keys {
		k, err := stm.GenerateSigningKey(rng)
		if err != nil {
			panic(err)
		}
		keys[i] = k
	}
	return keys
})

// EVRequest asks for the lottery ticket of a signature over msgp.
func EVRequest(key byte, msgp []byte, index uint64) Request {
	sigma := keyPool()[int(key)%len(keyPool())].Sign(msgp)
	return Request{"op": "ev", "sigma": hexOf(sigma.Bytes()), "msgp": hexOf(msgp), "index": index}
}

// AggregateRequest builds an aggregate or verify_aggregate request over
// signatures by pool keys. Each pair of ops bytes adds one (key, signature)
// pair: the key's index, and how the signature is made (over msg, over
// another message, by another key, or missing to unbalance the lists).
func AggregateRequest(verify bool, msg, ops []byte) Request {
	keys := keyPool()
	var vks, sigs []string
	for i := 0; i+1 < len(ops) && len(vks) < 12; i += 2 {
		k := keys[int(ops[i])%len(keys)]
		vks = append(vks, hexOf(k.VerificationKey().Bytes()))
		switch ops[i+1] % 8 {
		case 0:
			continue // unbalanced: no signature for this key
		case 1:
			sigs = append(sigs, hexOf(k.Sign(append(msg, 1)).Bytes()))
		case 2:
			sigs = append(sigs, hexOf(keys[int(ops[i+1]/8)%len(keys)].Sign(msg).Bytes()))
		default:
			sigs = append(sigs, hexOf(k.Sign(msg).Bytes()))
		}
	}
	r := Request{"op": "aggregate", "vks": orEmpty(vks), "sigs": orEmpty(sigs)}
	if verify {
		r["op"] = "verify_aggregate"
		r["msg"] = hexOf(msg)
	}
	return r
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// GenRequest builds a seeded signing request: parties with the given
// stakes (one byte each, scaled), parameters m and k, phi from EdgePhis
// (only (0, 1] values are useful) and msg.
func GenRequest(seed []byte, stakes []byte, m, k uint8, phiSel uint8, msg []byte) Request {
	var s [32]byte
	copy(s[:], seed)
	var st []uint64
	for i, b := range clip(stakes, 6) {
		v := uint64(b)
		if i == 0 && b == 0xff {
			v = math.MaxUint64 // total stake overflow
		}
		st = append(st, v)
	}
	phis := []float64{0.2, 0.5, 0.65, 0.8, 1, 0.05}
	return Request{
		"op": "gen", "seed": hexOf(s[:]), "stakes": st,
		"m": uint64(m%40) + 1, "k": uint64(k % 12), "phi": Bits(phis[int(phiSel)%len(phis)]),
		"msg": hexOf(clip(msg, 64)),
	}
}
