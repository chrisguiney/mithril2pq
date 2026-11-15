// SPDX-License-Identifier: Apache-2.0

package difftest

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"

	"github.com/chrisguiney/mithril2pq/internal/mithril/stm"
)

// ProofFixture is a valid concatenation proof with everything needed to
// verify it.
type ProofFixture struct {
	Name   string
	AVK    *stm.AggregateVerificationKey
	Proof  *stm.ConcatenationProof
	Msg    []byte
	Params stm.Parameters
}

// signedProof runs the seeded signing flow and returns its proof.
func signedProof(seed byte, stakes []uint64, params stm.Parameters, msg []byte) (ProofFixture, error) {
	rng := stm.NewChaChaRNG([32]byte{seed})
	reg := stm.NewKeyRegistration()
	var inits []*stm.Initializer
	for _, s := range stakes {
		i, err := stm.NewInitializer(params, s, rng)
		if err != nil {
			return ProofFixture{}, err
		}
		if err := reg.Register(s, i.VerificationKeyPoP()); err != nil {
			return ProofFixture{}, err
		}
		inits = append(inits, i)
	}
	closed, err := reg.Close()
	if err != nil {
		return ProofFixture{}, err
	}
	var sigs []*stm.SingleSignature
	for _, i := range inits {
		s, err := i.CreateSigner(closed)
		if err != nil {
			return ProofFixture{}, err
		}
		if sig, err := s.Sign(msg); err == nil {
			sigs = append(sigs, sig)
		}
	}
	clerk := &stm.Clerk{Params: params, Closed: closed}
	p, err := clerk.Aggregate(sigs, msg)
	if err != nil {
		return ProofFixture{}, err
	}
	return ProofFixture{Name: fmt.Sprintf("seed%d", seed), AVK: clerk.AggregateVerificationKey(), Proof: p, Msg: msg, Params: params}, nil
}

// liveDir is where the committed live certificates are, relative to any
// package directory under internal/mithril.
const liveDir = "../testdata/certs"

// ProofFixtures returns small generated proofs (fast to verify, so mutated
// inputs reach the pairing check often) followed by the committed live
// preprod proofs.
var ProofFixtures = sync.OnceValue(func() []ProofFixture {
	var out []ProofFixture
	for _, f := range []struct {
		seed   byte
		stakes []uint64
		params stm.Parameters
	}{
		{1, []uint64{1, 1}, stm.Parameters{M: 10, K: 5, PhiF: 0.8}},
		{2, []uint64{10, 20, 30}, stm.Parameters{M: 20, K: 6, PhiF: 0.65}},
		{3, []uint64{1, 1000, 5, 70, 3}, stm.Parameters{M: 30, K: 4, PhiF: 0.4}},
		{4, []uint64{7}, stm.Parameters{M: 12, K: 3, PhiF: 0.9}},
	} {
		p, err := signedProof(f.seed, f.stakes, f.params, []byte(fmt.Sprintf("message %d", f.seed)))
		if err != nil {
			panic(err)
		}
		out = append(out, p)
	}
	files, _ := filepath.Glob(filepath.Join(liveDir, "preprod", "*.json"))
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			panic(err)
		}
		var c struct {
			Hash, SignedMessage, MultiSig, AVK string
			Metadata                           struct{ Parameters stm.Parameters }
		}
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(b, &raw)
		_ = json.Unmarshal(raw["hash"], &c.Hash)
		_ = json.Unmarshal(raw["signed_message"], &c.SignedMessage)
		_ = json.Unmarshal(raw["multi_signature"], &c.MultiSig)
		_ = json.Unmarshal(raw["aggregate_verification_key"], &c.AVK)
		_ = json.Unmarshal(raw["metadata"], &c.Metadata)
		if c.MultiSig == "" {
			continue
		}
		var avk stm.AggregateVerificationKey
		var p stm.ConcatenationProof
		ab, _ := hex.DecodeString(c.AVK)
		pb, _ := hex.DecodeString(c.MultiSig)
		if err := json.Unmarshal(ab, &avk); err != nil {
			panic(err)
		}
		if err := json.Unmarshal(pb, &p); err != nil {
			panic(err)
		}
		out = append(out, ProofFixture{Name: "preprod/" + c.Hash[:8], AVK: &avk, Proof: &p, Msg: []byte(c.SignedMessage), Params: c.Metadata.Parameters})
	}
	return out
})

// ProofRequest builds a proof_verify request for a fixture.
func (f ProofFixture) Request() Request {
	a, _ := f.AVK.MarshalJSON()
	p, _ := f.Proof.MarshalJSON()
	return Request{
		"op": "proof_verify", "avk": string(a), "proof": string(p), "msg": hexOf(f.Msg),
		"m": f.Params.M, "k": f.Params.K, "phi": Bits(f.Params.PhiF),
	}
}

// clone deep-copies the parts of a fixture that mutations change.
func (f ProofFixture) clone() ProofFixture {
	avk := *f.AVK
	avk.Root = slices.Clone(avk.Root)
	p := &stm.ConcatenationProof{}
	for _, e := range f.Proof.Signatures {
		e.Sig.Indexes = slices.Clone(e.Sig.Indexes)
		p.Signatures = append(p.Signatures, e)
	}
	for _, v := range f.Proof.BatchPath.Values {
		p.BatchPath.Values = append(p.BatchPath.Values, slices.Clone(v))
	}
	p.BatchPath.Indices = slices.Clone(f.Proof.BatchPath.Indices)
	f.AVK, f.Proof, f.Msg = &avk, p, slices.Clone(f.Msg)
	return f
}

func negSig(s *stm.Signature) *stm.Signature {
	b := s.Bytes()
	b[0] ^= 0x20
	n, err := stm.SignatureFromBytes(b)
	if err != nil {
		return s
	}
	return n
}

func negVK(v *stm.VerificationKey) *stm.VerificationKey {
	b := v.Bytes()
	b[0] ^= 0x20
	n, err := stm.VerificationKeyFromBytes(b)
	if err != nil {
		return v
	}
	return n
}

// interesting64 are integer values at the boundaries the verifier's
// arithmetic and comparisons care about.
func interesting64(base uint64, sel byte) uint64 {
	switch sel % 10 {
	case 0:
		return base + 1
	case 1:
		return base - 1
	case 2:
		return 0
	case 3:
		return 1
	case 4:
		return math.MaxUint64
	case 5:
		return 1 << 63
	case 6:
		return base * 2
	case 7:
		return base / 2
	case 8:
		return uint64(sel)
	default:
		return math.MaxUint64 - uint64(sel)
	}
}

// MutateProof applies structure-aware mutations to a copy of fixture
// fixture%len, driven by ops three bytes at a time (operation, target,
// argument), and returns the proof_verify request. Points stay valid
// unless an operation corrupts them on purpose, so most mutated proofs
// still decode and reach the lottery, Merkle and pairing checks.
func MutateProof(fixture byte, ops []byte) Request {
	fs := ProofFixtures()
	f := fs[int(fixture)%len(fs)].clone()
	p, avk := f.Proof, f.AVK
	var corrupt []func(Request)
	for i := 0; i+2 < len(ops) && i < 3*12; i += 3 {
		op, t, a := ops[i], int(ops[i+1]), ops[i+2]
		n := len(p.Signatures)
		var e *stm.SignedEntry
		if n > 0 {
			e = &p.Signatures[t%n]
		}
		switch op % 20 {
		case 0: // another entry's sigma
			if n > 1 {
				e.Sig.Sigma = p.Signatures[int(a)%n].Sig.Sigma
			}
		case 1:
			if e != nil {
				e.Sig.Sigma = negSig(e.Sig.Sigma)
			}
		case 2: // index at a boundary of m
			if e != nil && len(e.Sig.Indexes) > 0 {
				j := int(a) % len(e.Sig.Indexes)
				e.Sig.Indexes[j] = []uint64{f.Params.M, f.Params.M + 1, f.Params.M - 1, 0, math.MaxUint64, e.Sig.Indexes[j] + 1}[int(a/16)%6]
			}
		case 3: // claim an extra index
			if e != nil {
				idx := uint64(a) % (f.Params.M + 2)
				if len(e.Sig.Indexes) > 0 && a&1 == 0 {
					idx = e.Sig.Indexes[0]
				}
				e.Sig.Indexes = append(e.Sig.Indexes, idx)
			}
		case 4:
			if e != nil && len(e.Sig.Indexes) > 0 {
				j := int(a) % len(e.Sig.Indexes)
				e.Sig.Indexes = slices.Delete(e.Sig.Indexes, j, j+1)
			}
		case 5:
			if e != nil {
				e.Party.Stake = interesting64(e.Party.Stake, a)
			}
		case 6:
			if e != nil && n > 1 {
				e.Party.VK = p.Signatures[int(a)%n].Party.VK
			} else if e != nil {
				e.Party.VK = negVK(e.Party.VK)
			}
		case 7:
			if n > 1 {
				j := int(a) % n
				p.Signatures[t%n], p.Signatures[j] = p.Signatures[j], p.Signatures[t%n]
			}
		case 8:
			if n > 0 {
				p.Signatures = slices.Delete(p.Signatures, t%n, t%n+1)
			}
		case 9:
			if n > 0 {
				p.Signatures = slices.Insert(p.Signatures, t%n, p.Signatures[t%n])
			}
		case 10: // batch path value
			if vs := p.BatchPath.Values; len(vs) > 0 {
				j := t % len(vs)
				switch a % 5 {
				case 0:
					if len(vs[j]) > 0 {
						vs[j][int(a)%len(vs[j])] ^= 1 << (a % 8)
					}
				case 1:
					vs[j] = vs[j][:min(int(a)%32, len(vs[j]))]
				case 2:
					vs[j] = append(vs[j], a)
				case 3:
					p.BatchPath.Values = slices.Delete(vs, j, j+1)
				default:
					p.BatchPath.Values = append(vs, vs[j])
				}
			} else {
				p.BatchPath.Values = append(p.BatchPath.Values, make([]byte, int(a)%40))
			}
		case 11: // batch path index
			if is := p.BatchPath.Indices; len(is) > 0 {
				j := t % len(is)
				switch a % 4 {
				case 0:
					is[j] = interesting64(is[j], a/4)
				case 1:
					if len(is) > 1 {
						k := int(a/4) % len(is)
						is[j], is[k] = is[k], is[j]
					}
				case 2:
					p.BatchPath.Indices = slices.Insert(is, j, is[j])
				default:
					p.BatchPath.Indices = slices.Delete(is, j, j+1)
				}
			}
		case 12:
			avk.TotalStake = interesting64(avk.TotalStake, a)
		case 13:
			avk.NrLeaves = interesting64(avk.NrLeaves, a)
		case 14:
			avk.Root[t%len(avk.Root)] ^= 1 << (a % 8)
		case 15:
			if len(f.Msg) > 0 && a&1 == 0 {
				f.Msg[t%len(f.Msg)] ^= 1 << (a % 8)
			} else {
				f.Msg = append(f.Msg, a)
			}
		case 16:
			switch a % 3 {
			case 0:
				f.Params.M = interesting64(f.Params.M, a/3)
			case 1:
				f.Params.K = interesting64(f.Params.K, a/3)
			default:
				f.Params.PhiF = EdgePhis[int(a/3)%len(EdgePhis)]
			}
		case 17: // signer_index is not part of verification
			if e != nil {
				e.Sig.SignerIndex = interesting64(e.Sig.SignerIndex, a)
			}
		case 18: // corrupt a point's bytes after encoding
			j, bit := t, a
			corrupt = append(corrupt, func(r Request) { r["proof"] = flipPointBit(r.str("proof"), j, bit) })
		default:
			if e != nil {
				slices.Reverse(e.Sig.Indexes)
			}
		}
	}
	r := f.Request()
	for _, c := range corrupt {
		c(r)
	}
	return r
}

// flipPointBit flips one bit of entry j's sigma (or key) in a proof's JSON.
func flipPointBit(proof string, j int, bit byte) string {
	n, err := parseJSON([]byte(proof))
	if err != nil {
		return proof
	}
	sigs := n.get("signatures")
	if sigs == nil || len(sigs.items) == 0 {
		return proof
	}
	pair := sigs.items[j%len(sigs.items)]
	var arr *jnode
	if bit&0x80 == 0 {
		arr = pair.items[0].get("sigma")
	} else {
		arr = pair.items[1].items[0]
	}
	if arr == nil || len(arr.items) == 0 {
		return proof
	}
	k := int(bit) % len(arr.items)
	var v int
	fmt.Sscan(arr.items[k].raw, &v)
	arr.items[k].raw = fmt.Sprint(v ^ (1 << (bit % 8)))
	return string(n.encode())
}

// BatchPathRequest builds a batch_path request from a valid tree of
// n%40+1 pool-key leaves and a path for the leaves sel selects, then
// mutates it with ops (pairs of operation and argument).
func BatchPathRequest(n byte, sel uint64, ops []byte) Request {
	keys := keyPool()
	nl := int(n)%40 + 1
	leaves := make([]stm.Leaf, nl)
	for i := range leaves {
		leaves[i] = stm.Leaf{VK: keys[i%len(keys)].VerificationKey(), Stake: uint64(i/len(keys) + 1)}
	}
	tree, err := stm.NewMerkleTree(leaves)
	if err != nil {
		panic(err)
	}
	var idx []uint64
	for i := range nl {
		if sel>>(uint(i)%64)&1 == 1 {
			idx = append(idx, uint64(i))
		}
	}
	if len(idx) == 0 {
		idx = []uint64{uint64(sel % uint64(nl))}
	}
	path, err := tree.BatchPath(idx)
	if err != nil {
		panic(err)
	}
	root := slices.Clone(tree.Root())
	nr := uint64(nl)
	var chosen []stm.Leaf
	for _, i := range idx {
		chosen = append(chosen, leaves[i])
	}
	for i := 0; i+1 < len(ops) && i < 2*10; i += 2 {
		op, a := ops[i], ops[i+1]
		switch op % 9 {
		case 0:
			nr = interesting64(nr, a)
		case 1:
			if len(path.Indices) > 0 {
				j := int(a) % len(path.Indices)
				path.Indices[j] = interesting64(path.Indices[j], a/8)
			}
		case 2:
			if len(path.Indices) > 1 {
				j := int(a) % len(path.Indices)
				path.Indices[0], path.Indices[j] = path.Indices[j], path.Indices[0]
			}
		case 3:
			if len(path.Values) > 0 {
				j := int(a) % len(path.Values)
				path.Values[j] = slices.Clone(path.Values[j])
				switch a % 4 {
				case 0:
					if len(path.Values[j]) > 0 {
						path.Values[j][0] ^= 1
					}
				case 1:
					path.Values[j] = path.Values[j][:min(int(a)%32, len(path.Values[j]))]
				case 2:
					path.Values[j] = append(path.Values[j], a)
				default:
					path.Values = slices.Delete(path.Values, j, j+1)
				}
			}
		case 4:
			path.Values = append(path.Values, make([]byte, int(a)%33))
		case 5:
			if len(chosen) > 0 {
				j := int(a) % len(chosen)
				chosen[j].Stake = interesting64(chosen[j].Stake, a/8)
			}
		case 6:
			if len(chosen) > 0 {
				j := int(a) % len(chosen)
				chosen = slices.Delete(chosen, j, j+1)
			}
		case 7:
			root = root[:min(int(a)%33, len(root))]
		default:
			if len(path.Indices) > 0 {
				j := int(a) % len(path.Indices)
				path.Indices = slices.Insert(path.Indices, j, path.Indices[j])
				if j < len(chosen) {
					chosen = slices.Insert(chosen, j, chosen[j])
				}
			}
		}
	}
	var ls [][]any
	for _, l := range chosen {
		ls = append(ls, []any{hexOf(l.VK.Bytes()), l.Stake})
	}
	var vals []string
	for _, v := range path.Values {
		vals = append(vals, hexOf(v))
	}
	if ls == nil {
		ls = [][]any{}
	}
	idxOut := path.Indices
	if idxOut == nil {
		idxOut = []uint64{}
	}
	return Request{"op": "batch_path", "root": hexOf(root), "nr_leaves": nr, "leaves": ls, "values": orEmpty(vals), "indices": idxOut}
}

// ProofJSONRequest builds a proof_json request: a fixture's proof JSON
// with token-level mutations.
func ProofJSONRequest(fixture byte, ops []byte) Request {
	fs := ProofFixtures()
	b, _ := fs[int(fixture)%len(fs)].Proof.MarshalJSON()
	return Request{"op": "proof_json", "s": MutateJSON(string(b), ops)}
}

// AVKJSONRequest builds an avk_json request: a fixture's aggregate key JSON
// with token-level mutations.
func AVKJSONRequest(fixture byte, ops []byte) Request {
	fs := ProofFixtures()
	b, _ := fs[int(fixture)%len(fs)].AVK.MarshalJSON()
	return Request{"op": "avk_json", "s": MutateJSON(string(b), ops)}
}
