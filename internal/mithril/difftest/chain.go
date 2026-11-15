// SPDX-License-Identifier: Apache-2.0

package difftest

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/chrisguiney/mithril2pq/internal/mithril/chain"
)

// chainClass names a chain verification error by the CertificateVerifierError
// variant it corresponds to. The rules Mithril's main branch added after
// release 2642.0 have no 2642.0 variant and are named with a "main:" prefix.
func chainClass(err error) string {
	for _, m := range []struct {
		err   error
		class string
	}{
		{chain.ErrInfiniteLoop, "CertificateChainInfiniteLoop"},
		{chain.ErrHashMismatch, "CertificateHashUnmatch"},
		{chain.ErrProtocolMessageMismatch, "CertificateProtocolMessageUnmatch"},
		{chain.ErrMultiSignature, "VerifyMultiSignature"},
		{chain.ErrEpochMismatch, "CertificateEpochUnmatch"},
		{chain.ErrMissingEpoch, "CertificateChainMissingEpoch"},
		{chain.ErrPreviousHashMismatch, "CertificateChainPreviousHashUnmatch"},
		{chain.ErrAVKMismatch, "CertificateChainAVKUnmatch"},
		{chain.ErrParametersMismatch, "CertificateChainProtocolParametersUnmatch"},
		{chain.ErrGenesisSignature, "GenesisSignature"},
		{chain.ErrStandardIsGenesis, "InvalidStandardCertificateProvided"},
		{chain.ErrNotGenesisWhereExpected, "InvalidGenesisCertificateProvided"},
		{chain.ErrGenesisAVKMismatch, "main:GenesisAVKMismatch"},
		{chain.ErrGenesisParamsMismatch, "main:GenesisParamsMismatch"},
		{chain.ErrEpochAfterGenesis, "main:EpochAfterGenesis"},
	} {
		if errors.Is(err, m.err) {
			return m.class
		}
	}
	return "decode"
}

func parseCert(s string) (*chain.Certificate, error) {
	var c chain.Certificate
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// rustCertClass maps the oracle's error classes onto chainClass's
// vocabulary: certificate parsing and conversion failures are both
// "decode", and an Ed25519 failure under a genesis verification is
// GenesisSignature.
func rustCertClass(a Answer) Answer {
	switch {
	case a.OK:
	case a.Err == "serde" || a.Err == "convert":
		a.Err = "decode"
	case a.Err == "prev_serde" || a.Err == "prev_convert":
		a.Err = "prev_decode"
	case strings.Contains(a.Detail, "Ed25519 signature verification error"):
		a.Err = "GenesisSignature"
	}
	return a
}

func init() {
	targets["params_hash"] = target{
		eval: func(r Request) Answer {
			h, err := chain.ProtocolParameters{K: r.u64("k"), M: r.u64("m"), PhiF: r.f64("phi")}.Hash()
			if err != nil {
				return reject("u8f24", err)
			}
			return okOut(h)
		},
		rules: func(r Request, got, want Answer) string {
			if got.Err == "u8f24" && want.OK {
				// Outside U8F24's range fixed's from_num wraps in
				// release builds (and panics in debug builds); the Go
				// port rejects.
				return "u8f24-out-of-range"
			}
			return ""
		},
	}
	targets["cert_hash"] = target{
		eval: func(r Request) Answer {
			c, err := parseCert(r.str("cert"))
			if err != nil {
				return reject("decode", err)
			}
			h, err := c.ComputeHash()
			if err != nil {
				return reject("decode", err)
			}
			mh, err := c.Metadata.Hash()
			if err != nil {
				return reject("decode", err)
			}
			pm, err := c.ProtocolMessage.Hash()
			if err != nil {
				return reject("decode", err)
			}
			ph, err := c.Metadata.Parameters.Hash()
			if err != nil {
				return reject("decode", err)
			}
			return okOut(map[string]string{"hash": h, "metadata": mh, "protocol_message": pm, "parameters": ph})
		},
		rules: certRules,
	}
	targets["cert_verify"] = target{
		compareErr: true,
		norm:       rustCertClass,
		eval: func(r Request) Answer {
			c, err := parseCert(r.str("cert"))
			if err != nil {
				return reject("decode", err)
			}
			if prev, ok := r["prev"].(string); ok {
				p, err := parseCert(prev)
				if err != nil {
					return reject("prev_decode", err)
				}
				if err := chain.VerifyStandard(c, p); err != nil {
					var ce *chain.CertificateError
					if errors.As(err, &ce) && ce.Hash == p.Hash && ce.Hash != c.Hash && chainClass(err) == "decode" {
						return reject("prev_decode", err)
					}
					return reject(chainClass(err), err)
				}
				return okOut("")
			}
			key, err := chain.ParseGenesisKey(r.str("genesis_key"))
			if err != nil {
				return reject("genesis_key", err)
			}
			if err := chain.VerifyGenesis(c, key); err != nil {
				return reject(chainClass(err), err)
			}
			return okOut("")
		},
		rules: func(r Request, got, want Answer) string {
			if strings.HasPrefix(got.Err, "main:") {
				// Rules from Mithril's main branch that release 2642.0
				// lacks: the Go port is stricter by design, and checks
				// them before the rules that follow in Mithril's order.
				return got.Err
			}
			if m := indexAtM.FindStringSubmatch(got.Detail); got.Err == "VerifyMultiSignature" && want.Err != got.Err && m != nil && m[1] == m[2] {
				return "index-bound-main"
			}
			if decodes := []string{"decode", "prev_decode"}; slices.Contains(decodes, got.Err) && slices.Contains(decodes, want.Err) {
				// Both reject while reading the two certificates; the
				// harness reads both messages before converting either,
				// so it can name the other one first.
				return "parse-order"
			}
			return certRules(r, got, want)
		},
	}
	targets["ed25519_verify"] = target{
		eval: func(r Request) Answer {
			if chain.VerifyEd25519Strict(r.hex("vk"), r.hex("msg"), r.hex("sig")) {
				return okOut("")
			}
			return reject("signature", nil)
		},
	}
}

// indexAtM matches the Go port's error for a lottery index equal to m,
// which release 2642.0 accepts.
var indexAtM = regexp.MustCompile(`lottery index out of bounds: index (\d+), m = (\d+)`)

// certRules are the divergences shared by the certificate operations.
func certRules(r Request, got, want Answer) string {
	if !got.OK && (want.OK || got.Err != want.Err) && strings.Contains(got.Detail, "8.24 fixed-point") {
		return "u8f24-out-of-range"
	}
	if !got.OK && want.OK && strings.Contains(got.Detail, "SNARK fields") {
		// The Go port rejects certificates carrying SNARK-era fields
		// rather than verify them without those fields.
		return "go-rejects-snark-fields"
	}
	if (got.Err == "decode" || got.Err == "prev_decode") && want.Err != got.Err && (strings.Contains(got.Detail, "aggregate verification key:") ||
		strings.Contains(got.Detail, "multi-signature is not a concatenation proof")) {
		// Mithril decodes keys and multi-signatures as JSON-hex and falls
		// back to its binary bytes-hex codec, which the Go port does not
		// implement; aggregators emit JSON-hex.
		return "go-no-bytes-hex"
	}
	return ""
}
