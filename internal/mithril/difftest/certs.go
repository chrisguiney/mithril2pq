// SPDX-License-Identifier: Apache-2.0

package difftest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/chrisguiney/mithril2pq/internal/mithril/chain"
	"github.com/chrisguiney/mithril2pq/internal/mithril/stm"
)

// A synthetic chain lets mutated certificates be re-signed (STM
// multi-signature and genesis signature) and re-hashed, so mutations reach
// every chain rule instead of stopping at the content hash. Its genesis
// key is a fixed test key passed to both sides.

type epochReg struct {
	params stm.Parameters
	inits  []*stm.Initializer
	closed *stm.ClosedKeyRegistration
	avk    *stm.AggregateVerificationKey
	avkHex string
}

type synthChain struct {
	genesisPriv ed25519.PrivateKey
	genesisKey  string // genesis.vkey form: JSON-hex of a byte array
	regs        map[uint64]*epochReg
	certs       []*chain.Certificate // genesis (10), c1 (11), c2 (11), c3 (12)
}

// CertPairs are the (certificate, previous) index pairs of the synthetic
// chain that verify; previous -1 means a genesis verification.
var CertPairs = [][2]int{{0, -1}, {1, 0}, {2, 1}, {3, 1}, {3, 2}}

func jsonHexOf(v json.Marshaler) string {
	b, err := v.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func genesisKeyHex(pub ed25519.PublicKey) string {
	ints := make([]int, len(pub))
	for i, b := range pub {
		ints[i] = int(b)
	}
	j, _ := json.Marshal(ints)
	return hex.EncodeToString(j)
}

func paramsHash(p stm.Parameters) string {
	h, err := chain.ProtocolParameters{K: p.K, M: p.M, PhiF: p.PhiF}.Hash()
	if err != nil {
		panic(err)
	}
	return h
}

func cloneCert(c *chain.Certificate) *chain.Certificate {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	var out chain.Certificate
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return &out
}

var synth = sync.OnceValue(func() *synthChain {
	seed := sha256.Sum256([]byte("mithril2pq difftest genesis key"))
	s := &synthChain{genesisPriv: ed25519.NewKeyFromSeed(seed[:]), regs: map[uint64]*epochReg{}}
	s.genesisKey = genesisKeyHex(s.genesisPriv.Public().(ed25519.PublicKey))
	params := map[uint64]stm.Parameters{
		11: {K: 5, M: 20, PhiF: 0.65},
		12: {K: 4, M: 25, PhiF: 0.7},
		13: {K: 3, M: 15, PhiF: 0.8},
	}
	for e := uint64(11); e <= 13; e++ {
		rng := stm.NewChaChaRNG([32]byte{byte(e)})
		reg := stm.NewKeyRegistration()
		r := &epochReg{params: params[e]}
		for _, st := range []uint64{10, 20, 30} {
			i, err := stm.NewInitializer(r.params, st+e, rng)
			if err != nil {
				panic(err)
			}
			if err := reg.Register(i.Stake, i.VerificationKeyPoP()); err != nil {
				panic(err)
			}
			r.inits = append(r.inits, i)
		}
		closed, err := reg.Close()
		if err != nil {
			panic(err)
		}
		r.closed, r.avk = closed, closed.AggregateVerificationKey()
		r.avkHex = jsonHexOf(r.avk)
		s.regs[e] = r
	}
	mk := func(epoch uint64, prev *chain.Certificate, genesis bool) *chain.Certificate {
		signing := epoch
		if genesis {
			signing = epoch + 1
		}
		r, next := s.regs[signing], s.regs[signing+1]
		c := &chain.Certificate{
			Epoch:            epoch,
			SignedEntityType: json.RawMessage(fmt.Sprintf(`{"MithrilStakeDistribution":%d}`, epoch)),
			Metadata: chain.Metadata{
				Network: "devnet", Version: "0.1.0",
				Parameters:  chain.ProtocolParameters{K: r.params.K, M: r.params.M, PhiF: r.params.PhiF},
				InitiatedAt: fmt.Sprintf("2025-02-%02dT00:03:21.810944690Z", epoch), SealedAt: fmt.Sprintf("2025-02-%02dT00:04:01.5Z", epoch),
			},
			ProtocolMessage: chain.ProtocolMessage{MessageParts: map[string]string{
				"next_aggregate_verification_key": next.avkHex,
				"next_protocol_parameters":        paramsHash(next.params),
				"current_epoch":                   strconv.FormatUint(epoch, 10),
			}},
			AggregateVerificationKey: r.avkHex,
		}
		if genesis {
			// Mithril's main branch requires a genesis certificate's key
			// and parameters to be those it names for the next epoch.
			c.ProtocolMessage.MessageParts["next_aggregate_verification_key"] = r.avkHex
			c.ProtocolMessage.MessageParts["next_protocol_parameters"] = paramsHash(r.params)
			c.GenesisSignature = "00"
		} else {
			for i, in := range r.inits {
				c.Metadata.Signers = append(c.Metadata.Signers, chain.Party{PartyID: fmt.Sprintf("pool%d", i), Stake: in.Stake})
			}
			c.PreviousHash = prev.Hash
		}
		if c.Metadata.Signers == nil {
			c.Metadata.Signers = []chain.Party{}
		}
		s.seal(c, 7)
		return c
	}
	g := mk(10, nil, true)
	c1 := mk(11, g, false)
	c2 := mk(11, c1, false)
	c3 := mk(12, c1, false)
	s.certs = []*chain.Certificate{g, c1, c2, c3}
	return s
})

// seal recomputes what mutations invalidate: the signed message (flags
// bit 0), the signature (bit 1: the genesis signature, or a fresh STM
// multi-signature by the registration whose key the certificate carries)
// and the content hash (bit 2).
func (s *synthChain) seal(c *chain.Certificate, flags byte) {
	if flags&1 != 0 {
		if h, err := c.ProtocolMessage.Hash(); err == nil {
			c.SignedMessage = h
		}
	}
	if flags&2 != 0 {
		if c.IsGenesis() {
			c.GenesisSignature = hex.EncodeToString(ed25519.Sign(s.genesisPriv, []byte(c.SignedMessage)))
		} else if ms, ok := s.multiSign(c); ok {
			c.MultiSignature = ms
		}
	}
	if flags&4 != 0 {
		if h, err := c.ComputeHash(); err == nil {
			c.Hash = h
		}
	}
}

func (s *synthChain) multiSign(c *chain.Certificate) (string, bool) {
	var r *epochReg
	for _, e := range s.regs {
		if strings.EqualFold(strings.TrimSpace(c.AggregateVerificationKey), e.avkHex) {
			r = e
		}
	}
	if r == nil {
		return "", false
	}
	params := c.Metadata.Parameters.STM()
	if params.M > 200 || params.M == 0 || !(params.PhiF > 0 && params.PhiF <= 1) {
		return "", false // signing would be slow or impossible
	}
	msg := []byte(c.SignedMessage)
	var sigs []*stm.SingleSignature
	for _, in := range r.inits {
		sg, err := in.CreateSigner(r.closed)
		if err != nil {
			return "", false
		}
		sg.Params = params
		if sig, err := sg.Sign(msg); err == nil {
			sigs = append(sigs, sig)
		}
	}
	p, err := (&stm.Clerk{Params: params, Closed: r.closed}).Aggregate(sigs, msg)
	if err != nil {
		return "", false
	}
	return jsonHexOf(p), true
}

func certJSON(c *chain.Certificate) string {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Timestamps are RFC 3339 spellings and boundaries that chrono and Go's
// time package might read differently, including the edges of an i64 of
// nanoseconds, where Mithril hashes zero.
var Timestamps = []string{
	"2025-02-20T00:03:21.810944690Z", "2025-02-20T00:03:21Z", "2025-02-20T00:03:21.8109446901234Z",
	"2025-02-20T00:03:21+01:00", "2025-02-20t00:03:21z", "2025-02-20 00:03:21Z",
	"1677-09-21T00:12:43.145224191Z", "1677-09-21T00:12:43.145224192Z",
	"2262-04-11T23:47:16.854775807Z", "2262-04-11T23:47:16.854775808Z",
	"9999-12-31T23:59:59Z", "0000-01-01T00:00:00Z", "2025-02-20T00:03:60Z",
	"2025-02-20T24:00:00Z", "2025-02-30T00:00:00Z", "+12345-01-01T00:00:00Z",
	"2025-02-20T00:03:21.Z", "2025-02-20T00:03:21,5Z", "2025-02-20T00:03:21-00:00",
	"2025-02-20T00:03:21+23:59", "2025-02-20T00:03:21+24:00", "2025-02-20T00:03:21.000000000000000000001Z",
	"1970-01-01T00:00:00Z", "1969-12-31T23:59:59.999999999Z", "2016-12-31T23:59:60.5Z",
}

var partKeys = []string{
	"snapshot_digest", "cardano_transactions_merkle_root", "cardano_blocks_transactions_merkle_root",
	"next_aggregate_verification_key", "next_protocol_parameters", "current_epoch", "latest_block_number",
	"cardano_blocks_transactions_block_number_offset", "cardano_stake_distribution_epoch",
	"cardano_stake_distribution_merkle_root", "cardano_database_merkle_root",
	"next_aggregate_verification_key_snark", "unknown_part", "Current_epoch",
}

var entityTypes = []string{
	`{"MithrilStakeDistribution":%d}`, `{"CardanoStakeDistribution":%d}`,
	`{"CardanoDatabase":{"epoch":%d,"immutable_file_number":7}}`, `{"CardanoTransactions":[%d,100]}`,
	`{"CardanoBlocksTransactions":[%d,100,5]}`, `{"CardanoImmutableFilesFull":{"network":"devnet","epoch":%d,"immutable_file_number":7}}`,
	`{"MithrilStakeDistribution":%d,"CardanoStakeDistribution":1}`, `"MithrilStakeDistribution"`,
	`{"MithrilStakeDistribution":"%d"}`, `{"CardanoDatabase":{"epoch":%d}}`, `{"CardanoTransactions":[%d,100,1]}`,
}

// mutateCert applies one certificate edit (op, argument) to c; others are
// the synthetic chain's certificates and registrations to borrow from.
func mutateCert(s *synthChain, c *chain.Certificate, op, a byte) {
	parts := c.ProtocolMessage.MessageParts
	if parts == nil {
		parts = map[string]string{}
		c.ProtocolMessage.MessageParts = parts
	}
	other := s.certs[int(a)%len(s.certs)]
	regs := []*epochReg{s.regs[11], s.regs[12], s.regs[13]}
	switch op % 17 {
	case 0:
		c.Epoch = []uint64{c.Epoch + 1, c.Epoch - 1, c.Epoch + 2, c.Epoch - 2, 0, math.MaxUint64, 1 << 63}[int(a)%7]
	case 1:
		c.PreviousHash = []string{other.Hash, "", strings.ToUpper(c.PreviousHash), c.Hash, c.PreviousHash + " "}[int(a/8)%5]
	case 2:
		p := &c.Metadata.Parameters
		switch a % 4 {
		case 0:
			p.K = interesting64(p.K, a/4)
		case 1:
			p.M = []uint64{p.M + 1, p.M - 1, 0, 1, math.MaxUint64, 1000}[int(a/4)%6]
		case 2:
			p.PhiF = []float64{math.Nextafter(p.PhiF, 2), math.Nextafter(p.PhiF, 0), p.PhiF + 1.0/(1<<25), p.PhiF + 1.0/(1<<24)}[int(a/4)%4]
		default:
			if v := EdgePhis[int(a/4)%len(EdgePhis)]; !math.IsInf(v, 0) && !math.IsNaN(v) {
				p.PhiF = v // JSON has no infinities or NaN
			}
		}
	case 3:
		switch a % 5 {
		case 0:
			parts["next_aggregate_verification_key"] = regs[int(a/5)%3].avkHex
		case 1:
			delete(parts, "next_aggregate_verification_key")
		case 2:
			parts["next_aggregate_verification_key"] = strings.ToUpper(parts["next_aggregate_verification_key"])
		case 3:
			parts["next_aggregate_verification_key"] = " " + parts["next_aggregate_verification_key"] + "\n"
		default:
			parts["next_aggregate_verification_key"] = "7b7d"
		}
	case 4:
		switch a % 3 {
		case 0:
			parts["next_protocol_parameters"] = paramsHash(regs[int(a/3)%3].params)
		case 1:
			delete(parts, "next_protocol_parameters")
		default:
			parts["next_protocol_parameters"] = strings.ToUpper(parts["next_protocol_parameters"])
		}
	case 5:
		e := c.Epoch
		v := []string{strconv.FormatUint(e+1, 10), "", "0" + strconv.FormatUint(e, 10), " " + strconv.FormatUint(e, 10),
			"+" + strconv.FormatUint(e, 10), strconv.FormatUint(e, 10) + ".0", strconv.FormatUint(e-1, 10)}[int(a)%8%7]
		if a%8 == 7 {
			delete(parts, "current_epoch")
		} else {
			parts["current_epoch"] = v
		}
	case 6:
		parts[partKeys[int(a)%len(partKeys)]] = fmt.Sprintf("%x", a)
	case 7:
		r := regs[int(a)%3]
		c.AggregateVerificationKey = []string{r.avkHex, strings.ToUpper(r.avkHex), " " + r.avkHex + " ",
			hex.EncodeToString([]byte(" " + mustHexDecode(r.avkHex) + " ")), r.avkHex[:len(r.avkHex)-2]}[int(a/3)%5]
	case 8:
		c.MultiSignature = []string{other.MultiSignature, "", strings.ToUpper(c.MultiSignature), "7b7d"}[int(a/8)%4]
	case 9:
		switch a % 5 {
		case 0:
			c.GenesisSignature = s.certs[0].GenesisSignature
		case 1:
			c.GenesisSignature = ""
		case 2: // the same signature as JSON-hex of a byte array
			if b, err := hex.DecodeString(c.GenesisSignature); err == nil && len(b) == 64 {
				ints := make([]int, 64)
				for i := range b {
					ints[i] = int(b[i])
				}
				j, _ := json.Marshal(ints)
				c.GenesisSignature = hex.EncodeToString(j)
			}
		case 3:
			c.GenesisSignature = strings.ToUpper(c.GenesisSignature)
		default:
			if b, err := hex.DecodeString(c.GenesisSignature); err == nil && len(b) > 0 {
				b[int(a/5)%len(b)] ^= 1
				c.GenesisSignature = hex.EncodeToString(b)
			}
		}
	case 10:
		e := c.Epoch
		if a&1 == 1 {
			e += uint64(a / 64)
		}
		c.SignedEntityType = json.RawMessage(strings.ReplaceAll(entityTypes[int(a/2)%len(entityTypes)], "%d", strconv.FormatUint(e, 10)))
	case 11:
		sg := c.Metadata.Signers
		switch {
		case len(sg) == 0 || a%4 == 0:
			c.Metadata.Signers = append(sg, chain.Party{PartyID: fmt.Sprintf("pool%d", a), Stake: uint64(a)})
		case a%4 == 1:
			c.Metadata.Signers = sg[1:]
		case a%4 == 2:
			sg[int(a/4)%len(sg)].Stake = interesting64(sg[int(a/4)%len(sg)].Stake, a/16)
		default:
			sg[0], sg[len(sg)-1] = sg[len(sg)-1], sg[0]
		}
	case 12:
		ts := Timestamps[int(a/2)%len(Timestamps)]
		if a&1 == 0 {
			c.Metadata.InitiatedAt = ts
		} else {
			c.Metadata.SealedAt = ts
		}
	case 13:
		v := []string{"", "mainnet", "devnet\u0000", "é"}[int(a/2)%4]
		if a&1 == 0 {
			c.Metadata.Network = v
		} else {
			c.Metadata.Version = v
		}
	case 14:
		c.ProtocolMessage.HashScheme = []string{"legacy", "rigid", "Legacy", ""}[int(a)%4]
	case 15:
		c.SignedMessage = []string{strings.ToUpper(c.SignedMessage), other.SignedMessage, c.SignedMessage + "0"}[int(a)%3]
	default:
		c.Hash = []string{other.Hash, strings.ToUpper(c.Hash), ""}[int(a)%3]
	}
}

func mustHexDecode(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// CertVerifyRequest builds a cert_verify request from synthetic pair
// pair%len(CertPairs). ops are read four bytes at a time: operation,
// argument, which certificate to edit (even: the certificate, odd: its
// previous one) and the seal flags to apply after the edit (bit 3 also
// re-links the certificate to its edited previous one).
func CertVerifyRequest(pair byte, ops []byte) Request {
	s := synth()
	pr := CertPairs[int(pair)%len(CertPairs)]
	c := cloneCert(s.certs[pr[0]])
	var p *chain.Certificate
	if pr[1] >= 0 {
		p = cloneCert(s.certs[pr[1]])
	}
	for i := 0; i+3 < len(ops) && i < 4*6; i += 4 {
		op, a, which, flags := ops[i], ops[i+1], ops[i+2], ops[i+3]
		if which&1 == 1 && p != nil {
			mutateCert(s, p, op, a)
			s.seal(p, flags)
			if flags&8 != 0 {
				c.PreviousHash = p.Hash
				s.seal(c, 7)
			}
		} else {
			mutateCert(s, c, op, a)
			s.seal(c, flags)
		}
	}
	r := Request{"op": "cert_verify", "cert": certJSON(c)}
	if p != nil {
		r["prev"] = certJSON(p)
	} else {
		r["genesis_key"] = s.genesisKey
	}
	return r
}

// LiveCerts returns the committed live certificates in a fixed order.
var LiveCerts = sync.OnceValue(func() []string {
	files, _ := filepath.Glob(filepath.Join(liveDir, "*", "*.json"))
	sort.Strings(files)
	var out []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			panic(err)
		}
		out = append(out, string(b))
	}
	return out
})

// CertHashRequest builds a cert_hash request from a live certificate (or,
// for fixture values past the live ones, a synthetic one), with field
// edits from ops (pairs of operation and argument) and, when jsonOps is
// not empty, token-level JSON mutations on top.
func CertHashRequest(fixture byte, ops, jsonOps []byte) Request {
	s := synth()
	live := LiveCerts()
	var c *chain.Certificate
	if i := int(fixture) % (len(live) + len(s.certs)); i < len(live) {
		var lc chain.Certificate
		if err := json.Unmarshal([]byte(live[i]), &lc); err != nil {
			panic(err)
		}
		c = &lc
	} else {
		c = cloneCert(s.certs[i-len(live)])
	}
	for i := 0; i+1 < len(ops) && i < 2*6; i += 2 {
		mutateCert(s, c, ops[i], ops[i+1])
	}
	doc := certJSON(c)
	if len(jsonOps) > 0 {
		doc = MutateJSON(doc, jsonOps)
	}
	return Request{"op": "cert_hash", "cert": doc}
}

// Ed25519 encodings of small-order points (the eight torsion points) and
// non-canonical encodings of some of them.
var smallOrder = []string{
	"0100000000000000000000000000000000000000000000000000000000000000",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

// groupOrder is L, the order of the Ed25519 prime subgroup, little-endian.
var groupOrder, _ = hex.DecodeString("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")

func addLE(a, b []byte) []byte {
	out := make([]byte, len(a))
	carry := 0
	for i := range a {
		v := int(a[i]) + int(b[i]) + carry
		out[i], carry = byte(v), v>>8
	}
	return out
}

// Ed25519Request builds an ed25519_verify request of the class mode
// selects: a valid signature, small-order R or key, non-canonical S (S+L)
// or S with high bits, non-canonical R or key encodings, a negated R, or
// raw bytes.
func Ed25519Request(mode byte, data []byte) Request {
	seed := sha256.Sum256(append([]byte("ed25519 key"), data...))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := []byte(priv.Public().(ed25519.PublicKey))
	msg := clip(data, 64)
	sig := ed25519.Sign(priv, msg)
	pick := func() []byte {
		k := 0
		if len(data) > 0 {
			k = int(data[0])
		}
		b, _ := hex.DecodeString(smallOrder[k%len(smallOrder)])
		return b
	}
	switch mode % 10 {
	case 1:
		copy(sig[:32], pick())
	case 2:
		pub = pick()
	case 3:
		copy(sig[32:], addLE(sig[32:], groupOrder))
	case 4:
		sig[63] |= 0xe0
	case 5: // R with y + p when y is small enough: R becomes a non-canonical identity
		copy(sig[:32], pick())
		sig[31] |= 0x80
	case 6:
		pub = slices.Clone(pick())
		pub[0] ^= 0x02
	case 7:
		sig[31] ^= 0x80
	case 8:
		r := resize(data, 128, data)
		pub, sig, msg = r[:32], r[32:96], r[96:]
	case 9: // small-order key with a small-order R and S = 0
		pub = pick()
		copy(sig[:32], pick())
		clear(sig[32:])
	}
	return Request{"op": "ed25519_verify", "vk": hexOf(pub), "msg": hexOf(msg), "sig": hexOf(sig[:64])}
}

// livePairs lists the committed live certificates that can be verified
// offline: each standard certificate whose previous certificate is also
// committed, and each genesis certificate with its network's pinned key.
var livePairs = sync.OnceValue(func() []Request {
	byHash := map[string]string{}
	var certs []chain.Certificate
	network := map[string]string{}
	files, _ := filepath.Glob(filepath.Join(liveDir, "*", "*.json"))
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			panic(err)
		}
		var c chain.Certificate
		if err := json.Unmarshal(b, &c); err != nil {
			panic(err)
		}
		byHash[c.Hash] = string(b)
		network[c.Hash] = filepath.Base(filepath.Dir(f))
		certs = append(certs, c)
	}
	var out []Request
	for _, c := range certs {
		switch {
		case c.IsGenesis():
			out = append(out, Request{"op": "cert_verify", "cert": byHash[c.Hash], "genesis_key": chain.GenesisKeys[network[c.Hash]]})
		case byHash[c.PreviousHash] != "":
			out = append(out, Request{"op": "cert_verify", "cert": byHash[c.Hash], "prev": byHash[c.PreviousHash]})
		}
	}
	return out
})

// LiveVerifyRequest returns the i-th verifiable live certificate request.
func LiveVerifyRequest(i int) (Request, error) {
	ps := livePairs()
	if i < 0 || i >= len(ps) {
		return nil, fmt.Errorf("live pair %d of %d", i, len(ps))
	}
	return ps[i], nil
}

// LivePairCount is the number of LiveVerifyRequest requests.
func LivePairCount() int { return len(livePairs()) }

// TimestampRequest builds a cert_hash request for a synthetic certificate
// whose initiated_at is ts.
func TimestampRequest(ts string) Request {
	c := cloneCert(synth().certs[1])
	c.Metadata.InitiatedAt = ts
	return Request{"op": "cert_hash", "cert": certJSON(c)}
}
