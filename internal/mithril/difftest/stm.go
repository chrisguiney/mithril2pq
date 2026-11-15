// SPDX-License-Identifier: Apache-2.0

package difftest

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/chrisguiney/mithril2pq/internal/mithril/stm"
)

// stmClass names a Go error by the Rust error variant it corresponds to.
func stmClass(err error) string {
	switch {
	case errors.Is(err, stm.ErrIndexBound):
		return "IndexBoundFailed"
	case errors.Is(err, stm.ErrLotteryLost):
		return "LotteryLost"
	case errors.Is(err, stm.ErrIndexNotUnique):
		return "IndexNotUnique"
	case errors.Is(err, stm.ErrNotEnoughIndexes):
		return "NotEnoughSignatures"
	case errors.Is(err, stm.ErrBatchPathInvalid):
		return "BatchPathInvalid"
	case errors.Is(err, stm.ErrSignatureInvalid):
		return "SignatureInvalid"
	case errors.Is(err, stm.ErrPointAtInfinity):
		return "SignatureInfinity"
	case errors.Is(err, stm.ErrZeroTotalStake):
		return "ZeroTotalStake"
	case errors.Is(err, stm.ErrPhiFOutOfRange):
		return "PhiFValueOutOfRange"
	case errors.Is(err, stm.ErrAlreadyRegistered):
		return "EntryAlreadyRegistered"
	case errors.Is(err, stm.ErrKeyInvalid):
		return "ConcatenationKeyInvalid"
	case errors.Is(err, stm.ErrInvalidPoint):
		return "SerializationError"
	case strings.Contains(err.Error(), "total stake overflows"):
		return "TotalStakeOverflow"
	case strings.Contains(err.Error(), "aggregate needs"):
		return "AggregateSignatureInvalid"
	}
	return "go:" + err.Error()
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func init() {
	targets["sig_decode"] = target{
		compareErr: true,
		eval: func(r Request) Answer {
			s, err := stm.SignatureFromBytes(r.hex("b"))
			if err != nil {
				// Rust reports every decoding failure, infinity included,
				// as BlsSignatureError::SerializationError.
				return reject("SerializationError", err)
			}
			return okOut(hexOf(s.Bytes()))
		},
		rules: func(r Request, got, want Answer) string {
			return prefixDecode(r.hex("b"), stm.SignatureSize, got, want, func(b []byte) ([]byte, error) {
				s, err := stm.SignatureFromBytes(b)
				if err != nil {
					return nil, err
				}
				return s.Bytes(), nil
			})
		},
	}
	targets["vk_decode"] = target{
		compareErr: true,
		eval: func(r Request) Answer {
			vk, err := stm.VerificationKeyFromBytes(r.hex("b"))
			if err != nil {
				return reject("SerializationError", err)
			}
			return okOut(hexOf(vk.Bytes()))
		},
		rules: func(r Request, got, want Answer) string {
			return prefixDecode(r.hex("b"), stm.VerificationKeySize, got, want, func(b []byte) ([]byte, error) {
				vk, err := stm.VerificationKeyFromBytes(b)
				if err != nil {
					return nil, err
				}
				return vk.Bytes(), nil
			})
		},
	}
	targets["avk_json"] = target{
		eval: func(r Request) Answer {
			var a stm.AggregateVerificationKey
			if err := json.Unmarshal([]byte(r.str("s")), &a); err != nil {
				return reject("serde", err)
			}
			b, _ := a.MarshalJSON()
			return okOut(string(b))
		},
		rules: func(r Request, got, want Answer) string {
			if !got.OK && want.OK && avkRootLength(want.Out) {
				return "avk-root-length"
			}
			return ""
		},
	}
	targets["proof_json"] = target{
		eval: func(r Request) Answer {
			var p stm.ConcatenationProof
			if err := json.Unmarshal([]byte(r.str("s")), &p); err != nil {
				return reject("serde", err)
			}
			b, _ := p.MarshalJSON()
			return okOut(string(b))
		},
	}
	targets["parse_f64"] = target{
		eval: func(r Request) Answer {
			var f float64
			if err := json.Unmarshal([]byte(r.str("s")), &f); err != nil {
				return reject("serde", err)
			}
			return okOut(Bits(f))
		},
		rules: func(r Request, got, want Answer) string {
			// serde_json's parser without float_roundtrip is off by up to
			// a few ulps on long decimals.
			if d := ulps(got.Out, want.Out); got.OK && want.OK && d >= 1 && d <= 2 {
				return "serde-float-rounding"
			}
			return ""
		},
	}
	targets["ln1m"] = target{
		eval: func(r Request) Answer { return okOut(Bits(math.Log(1 - r.f64("phi")))) },
		rules: func(r Request, got, want Answer) string {
			if ulps(got.Out, want.Out) == 1 {
				return "libm-ln"
			}
			if isNaNBits(got.Out) && isNaNBits(want.Out) {
				// ln of a negative number: NaN on both sides, with a
				// sign or payload that is not meaningful.
				return "nan-bits"
			}
			return ""
		},
	}
	targets["lottery"] = target{
		compareErr: true,
		slow: func(r Request) bool {
			return slowLottery(r.f64("phi"), r.u64("stake"), r.u64("total"))
		},
		eval: func(r Request) Answer {
			var ev [64]byte
			copy(ev[:], r.hex("ev"))
			won, err := stm.IsLotteryWon(r.f64("phi"), ev, r.u64("stake"), r.u64("total"))
			if err != nil {
				return reject(stmClass(err), err)
			}
			return okOut(won)
		},
		rules: func(r Request, got, want Answer) string {
			if goLn := strconv.Quote(Bits(math.Log(1 - r.f64("phi")))); len(want.Aux) > 0 && string(want.Aux) != goLn {
				return "libm-ln"
			}
			return ""
		},
	}
	targets["ev"] = target{
		eval: func(r Request) Answer {
			s, err := stm.SignatureFromBytes(r.hex("sigma"))
			if err != nil {
				return reject(stmClass(err), err)
			}
			ev := stm.Lottery(r.hex("msgp"), r.u64("index"), s)
			return okOut(hexOf(ev[:]))
		},
	}
	targets["batch_path"] = target{
		eval: func(r Request) Answer {
			var leaves []stm.Leaf
			for _, l := range r.list("leaves") {
				pair := l.([]any)
				b, _ := hex.DecodeString(pair[0].(string))
				vk, err := stm.VerificationKeyFromBytes(b)
				if err != nil {
					return reject("decode", err)
				}
				leaves = append(leaves, stm.Leaf{VK: vk, Stake: Request{"s": pair[1]}.u64("s")})
			}
			path := stm.BatchPath{Values: r.hexList("values"), Indices: r.u64List("indices")}
			if err := stm.VerifyBatchPath(r.hex("root"), r.u64("nr_leaves"), leaves, path); err != nil {
				return reject(stmClass(err), err)
			}
			return okOut("")
		},
	}
	targets["proof_verify"] = target{
		compareErr: true,
		eval:       evalProofVerify,
		rules:      proofVerifyRules,
		slow:       slowProof,
	}
	targets["aggregate"] = target{
		compareErr: true,
		eval: func(r Request) Answer {
			vks, sigs, a := decodeKeysSigs(r)
			if vks == nil && sigs == nil && !a.OK && a.Err != "" {
				return a
			}
			vk, s, err := stm.Aggregate(vks, sigs)
			if err != nil {
				return reject(stmClass(err), err)
			}
			return okOut(hexOf(vk.Bytes()) + ":" + hexOf(s.Bytes()))
		},
	}
	targets["verify_aggregate"] = target{
		compareErr: true,
		eval: func(r Request) Answer {
			vks, sigs, a := decodeKeysSigs(r)
			if vks == nil && sigs == nil && !a.OK && a.Err != "" {
				return a
			}
			if err := stm.VerifyAggregate(r.hex("msg"), vks, sigs); err != nil {
				return reject(stmClass(err), err)
			}
			return okOut("")
		},
	}
	targets["gen"] = target{compareErr: true, eval: evalGen}
}

// prefixDecode is the rule for byte strings longer than a point: Rust
// decodes the first size bytes and ignores the rest
// (from_canonical_bytes takes bytes.get(..size)); Go requires the exact
// length. The rule holds only if Go decodes that prefix to Rust's answer.
func prefixDecode(b []byte, size int, got, want Answer, decode func([]byte) ([]byte, error)) string {
	if len(b) <= size || got.OK || !want.OK {
		return ""
	}
	if p, err := decode(b[:size]); err == nil && sameOut(want.Out, mustJSON(hexOf(p))) {
		return "rust-prefix-decode"
	}
	return ""
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// avkRootLength reports whether Rust's re-encoded key has a Merkle root
// that is not 32 bytes. Rust decodes the root as a Vec<u8> of any length
// and can only reject such a key when it is used; Go rejects it on decode.
func avkRootLength(out json.RawMessage) bool {
	var s string
	if json.Unmarshal(out, &s) != nil {
		return false
	}
	var a struct {
		MT struct {
			Root []json.Number `json:"root"`
		} `json:"mt_commitment"`
	}
	if json.Unmarshal([]byte(s), &a) != nil {
		return false
	}
	return len(a.MT.Root) != 32
}

// ulps returns the distance in units in the last place between two
// float-bit outputs, or -1 if they are not both finite floats.
func ulps(a, b json.RawMessage) int64 {
	var x, y string
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return -1
	}
	xb, err1 := strconv.ParseUint(x, 16, 64)
	yb, err2 := strconv.ParseUint(y, 16, 64)
	if err1 != nil || err2 != nil {
		return -1
	}
	xf, yf := math.Float64frombits(xb), math.Float64frombits(yb)
	if math.IsNaN(xf) || math.IsNaN(yf) || math.IsInf(xf, 0) || math.IsInf(yf, 0) || math.Signbit(xf) != math.Signbit(yf) {
		return -1
	}
	d := int64(xb) - int64(yb)
	if d < 0 {
		d = -d
	}
	return d
}

func isNaNBits(out json.RawMessage) bool {
	var s string
	if json.Unmarshal(out, &s) != nil {
		return false
	}
	b, err := strconv.ParseUint(s, 16, 64)
	return err == nil && math.IsNaN(math.Float64frombits(b))
}

func decodeKeysSigs(r Request) ([]*stm.VerificationKey, []*stm.Signature, Answer) {
	var vks []*stm.VerificationKey
	for _, b := range r.hexList("vks") {
		vk, err := stm.VerificationKeyFromBytes(b)
		if err != nil {
			return nil, nil, reject("decode", err)
		}
		vks = append(vks, vk)
	}
	var sigs []*stm.Signature
	for _, b := range r.hexList("sigs") {
		s, err := stm.SignatureFromBytes(b)
		if err != nil {
			return nil, nil, reject("decode", err)
		}
		sigs = append(sigs, s)
	}
	if vks == nil {
		vks = []*stm.VerificationKey{}
	}
	return vks, sigs, Answer{}
}

func params(r Request) stm.Parameters {
	return stm.Parameters{M: r.u64("m"), K: r.u64("k"), PhiF: r.f64("phi")}
}

func evalProofVerify(r Request) Answer {
	var avk stm.AggregateVerificationKey
	if err := json.Unmarshal([]byte(r.str("avk")), &avk); err != nil {
		return reject("serde_avk", err)
	}
	var p stm.ConcatenationProof
	if err := json.Unmarshal([]byte(r.str("proof")), &p); err != nil {
		return reject("serde_proof", err)
	}
	if err := p.Verify(r.hex("msg"), &avk, params(r)); err != nil {
		return reject(stmClass(err), err)
	}
	return okOut("")
}

func proofVerifyRules(r Request, got, want Answer) string {
	switch {
	case got.Err == "IndexBoundFailed" && want.Err != "IndexBoundFailed" && claimsIndex(r.str("proof"), r.u64("m")):
		// Release 2642.0 bounds indexes by idx > m; Mithril's main branch
		// and the Go port by idx >= m, the range signers draw from.
		return "index-bound-main"
	case got.Err == "serde_avk" && strings.Contains(got.Detail, "root is ") && !want.OK && want.Err != "serde_avk":
		return "avk-root-length"
	case got.Err == "BatchPathInvalid" && want.Err == "SerializationError":
		// Rust reports index arithmetic overflow in the batch path as
		// MerkleTreeError::SerializationError; Go has one error.
		return "merkle-error-class"
	}
	return ""
}

// slowLottery reports whether the lottery's Taylor series is expensive
// for these inputs, on both sides: its argument w·|ln(1 - phi_f)| is large
// when a stake far exceeds the total stake, and its rationals grow large
// when phi_f is tiny. Verification checks the lottery before the Merkle
// path, so such a proof costs seconds per claimed index before it is
// rejected.
func slowLottery(phi float64, stake, total uint64) bool {
	if total == 0 || !(phi > 0 && phi < 1) {
		return false
	}
	if phi < 1e-12 {
		return true
	}
	return float64(stake)/float64(total)*-math.Log(1-phi) > 100
}

func slowProof(r Request) bool {
	var avk stm.AggregateVerificationKey
	var p stm.ConcatenationProof
	if json.Unmarshal([]byte(r.str("avk")), &avk) != nil || json.Unmarshal([]byte(r.str("proof")), &p) != nil {
		return false
	}
	for _, e := range p.Signatures {
		if slowLottery(r.f64("phi"), e.Party.Stake, avk.TotalStake) {
			return true
		}
	}
	return false
}

// claimsIndex reports whether any signature in the proof JSON claims
// lottery index idx.
func claimsIndex(proof string, idx uint64) bool {
	var p stm.ConcatenationProof
	if json.Unmarshal([]byte(proof), &p) != nil {
		return false
	}
	for _, e := range p.Signatures {
		if slices.Contains(e.Sig.Indexes, idx) {
			return true
		}
	}
	return false
}

// GenOutput is the gen operation's output: the seeded registration's
// aggregate key, each party's single signature (or why it has none) and the
// aggregate signature (or why there is none).
type GenOutput struct {
	AVK   string      `json:"avk"`
	Sigs  []GenSig    `json:"sigs"`
	Proof GenProofOut `json:"proof"`
}

// GenSig is one party's signature in GenOutput.
type GenSig struct {
	Sigma       string   `json:"sigma,omitempty"`
	Indexes     []uint64 `json:"indexes,omitempty"`
	SignerIndex *uint64  `json:"signer_index,omitempty"`
	Err         string   `json:"err,omitempty"`
}

// GenProofOut is the aggregate signature in GenOutput.
type GenProofOut struct {
	JSON string `json:"json,omitempty"`
	Err  string `json:"err,omitempty"`
}

func evalGen(r Request) Answer {
	var seed [32]byte
	copy(seed[:], r.hex("seed"))
	p := params(r)
	msg := r.hex("msg")
	rng := stm.NewChaChaRNG(seed)
	var inits []*stm.Initializer
	for _, s := range r.u64List("stakes") {
		i, err := stm.NewInitializer(p, s, rng)
		if err != nil {
			return reject(stmClass(err), err)
		}
		inits = append(inits, i)
	}
	reg := stm.NewKeyRegistration()
	for _, i := range inits {
		if err := reg.Register(i.Stake, i.VerificationKeyPoP()); err != nil {
			return reject(stmClass(err), err)
		}
	}
	closed, err := reg.Close()
	if err != nil {
		return reject(stmClass(err), err)
	}
	var out GenOutput
	var sigs []*stm.SingleSignature
	for _, i := range inits {
		s, err := i.CreateSigner(closed)
		if err != nil {
			return reject(stmClass(err), err)
		}
		sig, err := s.Sign(msg)
		if err != nil {
			out.Sigs = append(out.Sigs, GenSig{Err: stmClass(err)})
			continue
		}
		idx := sig.SignerIndex
		out.Sigs = append(out.Sigs, GenSig{Sigma: hexOf(sig.Sigma.Bytes()), Indexes: sig.Indexes, SignerIndex: &idx})
		sigs = append(sigs, sig)
	}
	clerk := &stm.Clerk{Params: p, Closed: closed}
	avk, _ := clerk.AggregateVerificationKey().MarshalJSON()
	out.AVK = string(avk)
	proof, err := clerk.Aggregate(sigs, msg)
	if err != nil {
		out.Proof.Err = stmClass(err)
	} else {
		b, _ := proof.MarshalJSON()
		out.Proof.JSON = string(b)
	}
	return okOut(out)
}
