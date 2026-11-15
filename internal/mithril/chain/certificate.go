// SPDX-License-Identifier: Apache-2.0
//
// Ported from mithril-common/src/entities/ (certificate.rs,
// certificate_metadata.rs, protocol_parameters.rs, protocol_message.rs,
// signed_entity_type.rs), mithril-common/src/messages/certificate.rs and
// mithril-common/src/crypto_helper/codec/json_hex.rs in
// IntersectMBO/mithril at release 2642.0
// (e85df3ddc52b528c7b9ddbdddf1941fec6d5f348).
// Copyright 2022 Input Output (Hong Kong) Ltd.
// Modifications: translated from Rust to Go.

// Package chain verifies Mithril certificates and the certificate chain
// back to a genesis certificate signed by a pinned genesis key.
package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/chrisguiney/mithril2pq/internal/mithril/stm"
)

// Certificate is a certificate as the aggregator's API serves it
// (mithril-common's CertificateMessage).
type Certificate struct {
	Hash             string          `json:"hash"`
	PreviousHash     string          `json:"previous_hash"`
	Epoch            uint64          `json:"epoch"`
	SignedEntityType json.RawMessage `json:"signed_entity_type"`
	Metadata         Metadata        `json:"metadata"`
	ProtocolMessage  ProtocolMessage `json:"protocol_message"`
	SignedMessage    string          `json:"signed_message"`
	// AggregateVerificationKey and MultiSignature are JSON-hex: the hex of
	// the value's compact serde_json encoding.
	AggregateVerificationKey string `json:"aggregate_verification_key"`
	MultiSignature           string `json:"multi_signature"`
	// GenesisSignature is the hex Ed25519 signature of a genesis
	// certificate, and empty on every other certificate.
	GenesisSignature string `json:"genesis_signature"`

	// Fields of SNARK-era certificates. Their hashing and verification
	// are not implemented, so a certificate carrying any of them is
	// rejected rather than verified without them.
	AggregateVerificationKeySnark *string `json:"aggregate_verification_key_snark,omitempty"`
	AncillaryProverData           *string `json:"ancillary_prover_data,omitempty"`
	AncillaryVerifierData         *string `json:"ancillary_verifier_data,omitempty"`
	GenesisSchnorrSignature       *string `json:"genesis_schnorr_signature,omitempty"`
}

// Metadata is the certificate's metadata message part.
type Metadata struct {
	Network     string             `json:"network"`
	Version     string             `json:"version"`
	Parameters  ProtocolParameters `json:"parameters"`
	InitiatedAt string             `json:"initiated_at"`
	SealedAt    string             `json:"sealed_at"`
	Signers     []Party            `json:"signers"`
}

// Party is a signer and its stake.
type Party struct {
	PartyID string `json:"party_id"`
	Stake   uint64 `json:"stake"`
}

// ProtocolParameters are the STM parameters a certificate was signed with.
type ProtocolParameters struct {
	K    uint64  `json:"k"`
	M    uint64  `json:"m"`
	PhiF float64 `json:"phi_f"`
}

// ProtocolMessage is the set of message parts the signed message hashes.
type ProtocolMessage struct {
	MessageParts map[string]string `json:"message_parts"`
	HashScheme   string            `json:"hash_scheme,omitempty"`
}

// IsGenesis reports whether this is a genesis certificate. Mithril
// decides on the genesis signature alone.
func (c *Certificate) IsGenesis() bool { return c.GenesisSignature != "" }

// protocolMessagePartOrder is the declaration order of mithril-common's
// ProtocolMessagePartKey. The legacy message hash walks a BTreeMap keyed by
// that enum, so parts are hashed in this order, not alphabetically.
var protocolMessagePartOrder = []string{
	"snapshot_digest",
	"cardano_transactions_merkle_root",
	"cardano_blocks_transactions_merkle_root",
	"next_aggregate_verification_key",
	"next_protocol_parameters",
	"current_epoch",
	"latest_block_number",
	"cardano_blocks_transactions_block_number_offset",
	"cardano_stake_distribution_epoch",
	"cardano_stake_distribution_merkle_root",
	"cardano_database_merkle_root",
	"next_aggregate_verification_key_snark",
}

// ProtocolMessageHash computes the legacy-scheme hash of the message parts:
// SHA-256 over key then value for each part, in enum order. Unknown parts
// are an error, as they are when Mithril deserializes the message.
func ProtocolMessageHash(parts map[string]string) (string, error) {
	known := map[string]bool{}
	h := sha256.New()
	for _, k := range protocolMessagePartOrder {
		known[k] = true
		if v, ok := parts[k]; ok {
			h.Write([]byte(k))
			h.Write([]byte(v))
		}
	}
	for k := range parts {
		if !known[k] {
			return "", fmt.Errorf("protocol message has part %q that this version of mithril2pq does not know how to hash", k)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Hash returns the protocol message's hash. Only the legacy scheme exists
// outside SNARK builds; any other scheme is rejected.
func (m *ProtocolMessage) Hash() (string, error) {
	if m.HashScheme != "" && m.HashScheme != "legacy" {
		return "", fmt.Errorf("protocol message uses hash scheme %q, which this version of mithril2pq cannot check", m.HashScheme)
	}
	return ProtocolMessageHash(m.MessageParts)
}

// U8F24 converts phi_f to the 8.24 unsigned fixed-point value Mithril
// hashes and compares, rounding to nearest with ties to even as the fixed
// crate's from_num does. Values the type cannot hold are an error (Rust
// panics on them).
func U8F24(phiF float64) (uint32, error) {
	// Scaling by 2^24 is exact in float64, so RoundToEven sees the true
	// value.
	v := math.RoundToEven(phiF * (1 << 24))
	if math.IsNaN(v) || v < 0 || v > math.MaxUint32 {
		return 0, fmt.Errorf("phi_f %v does not fit Mithril's 8.24 fixed-point form", phiF)
	}
	return uint32(v), nil
}

// Hash is SHA-256 of k, m (u64 big-endian) and phi_f as 8.24 fixed point
// (u32 big-endian).
func (p ProtocolParameters) Hash() (string, error) {
	phi, err := U8F24(p.PhiF)
	if err != nil {
		return "", err
	}
	var b [20]byte
	binary.BigEndian.PutUint64(b[0:], p.K)
	binary.BigEndian.PutUint64(b[8:], p.M)
	binary.BigEndian.PutUint32(b[16:], phi)
	sum := sha256.Sum256(b[:])
	return hex.EncodeToString(sum[:]), nil
}

// Equal compares parameters as Mithril does: phi_f in fixed point.
func (p ProtocolParameters) Equal(o ProtocolParameters) bool {
	a, errA := U8F24(p.PhiF)
	b, errB := U8F24(o.PhiF)
	return errA == nil && errB == nil && p.K == o.K && p.M == o.M && a == b
}

// STM returns the parameters in mithril-stm's form.
func (p ProtocolParameters) STM() stm.Parameters {
	return stm.Parameters{M: p.M, K: p.K, PhiF: p.PhiF}
}

// Hash is SHA-256 of the network, version, parameter hash (hex text), both
// timestamps (i64 nanoseconds big-endian) and, per signer in order, the hex
// text of SHA-256(party id || stake big-endian).
func (m *Metadata) Hash() (string, error) {
	ph, err := m.Parameters.Hash()
	if err != nil {
		return "", err
	}
	initiated, err := unixNanos(m.InitiatedAt)
	if err != nil {
		return "", err
	}
	sealed, err := unixNanos(m.SealedAt)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(m.Network))
	h.Write([]byte(m.Version))
	h.Write([]byte(ph))
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(initiated)))
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(sealed)))
	for _, p := range m.Signers {
		ps := sha256.New()
		ps.Write([]byte(p.PartyID))
		ps.Write(binary.BigEndian.AppendUint64(nil, p.Stake))
		h.Write([]byte(hex.EncodeToString(ps.Sum(nil))))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// signedEntityFeed returns the bytes the certificate hash takes from the
// signed entity type: its beacon fields as u64 big-endian, preceded for
// CardanoBlocksTransactions by its type id as u16 big-endian. It accepts
// exactly what serde reads as a known SignedEntityType: one variant key,
// tuple variants as arrays of their exact length, and the CardanoDatabase
// beacon as an object or a two-element array.
func signedEntityFeed(raw json.RawMessage) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	n, err := parseNode(d)
	if err != nil || n.kind != '{' || len(n.keys) != 1 {
		return nil, fmt.Errorf("signed entity type %s is not a single-variant object", raw)
	}
	k, v := n.keys[0], n.items[0]
	u64s := func(want int) ([]uint64, error) {
		items := []*node{v}
		if want != 1 || v.kind == '[' {
			if v.kind != '[' || len(v.items) != want {
				return nil, fmt.Errorf("signed entity type %s: want %d values", k, want)
			}
			items = v.items
		}
		out := make([]uint64, len(items))
		for i, it := range items {
			x, err := strconv.ParseUint(it.text, 10, 64)
			if it.kind != 'n' || err != nil {
				return nil, fmt.Errorf("signed entity type %s: %q is not a u64", k, it.text)
			}
			out[i] = x
		}
		return out, nil
	}
	var vals []uint64
	var out []byte
	switch k {
	case "MithrilStakeDistribution", "CardanoStakeDistribution":
		if v.kind == '[' {
			return nil, fmt.Errorf("signed entity type %s: want a number", k)
		}
		vals, err = u64s(1)
	case "CardanoDatabase":
		if v.kind == '{' {
			if err = checkObject(v, beaconFields); err == nil {
				v = &node{kind: '[', items: []*node{v.items[slices.Index(v.keys, "epoch")], v.items[slices.Index(v.keys, "immutable_file_number")]}}
			}
		}
		if err == nil {
			vals, err = u64s(2)
		}
	case "CardanoTransactions":
		vals, err = u64s(2)
	case "CardanoBlocksTransactions":
		vals, err = u64s(3)
		out = binary.BigEndian.AppendUint16(out, 5) // ENTITY_TYPE_CARDANO_BLOCKS_TRANSACTIONS
	default:
		return nil, fmt.Errorf("unknown signed entity type %q", k)
	}
	if err != nil {
		return nil, err
	}
	for _, x := range vals {
		out = binary.BigEndian.AppendUint64(out, x)
	}
	return out, nil
}

// DecodeJSONHex decodes Mithril's JSON-hex: hex (either case, surrounding
// whitespace ignored) of a JSON value.
func DecodeJSONHex(s string, v any) error {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("not JSON-hex: %w", err)
	}
	return json.Unmarshal(b, v)
}

// DecodeAVK decodes a JSON-hex aggregate verification key.
func DecodeAVK(s string) (*stm.AggregateVerificationKey, error) {
	var a stm.AggregateVerificationKey
	if err := DecodeJSONHex(s, &a); err != nil {
		return nil, fmt.Errorf("aggregate verification key: %w", err)
	}
	return &a, nil
}

// decodeGenesisSignature reads the 64-byte Ed25519 signature: bytes-hex,
// or JSON-hex of an array of 64 bytes as Mithril's fallback.
func decodeGenesisSignature(s string) ([]byte, error) {
	if b, err := hex.DecodeString(strings.TrimSpace(s)); err == nil && len(b) == 64 {
		return b, nil
	}
	var ints []uint8
	var raw []json.Number
	if err := DecodeJSONHex(s, &raw); err == nil && len(raw) == 64 {
		for _, n := range raw {
			v, err := strconv.ParseUint(string(n), 10, 8)
			if err != nil {
				return nil, errors.New("genesis signature: byte out of range")
			}
			ints = append(ints, uint8(v))
		}
		return ints, nil
	}
	return nil, errors.New("genesis signature is not a 64-byte Ed25519 signature")
}

// decoded is a certificate with its cryptographic fields parsed.
type decoded struct {
	*Certificate
	avk      *stm.AggregateVerificationKey
	multiSig *stm.ConcatenationProof // nil for genesis
	genesis  []byte                  // nil for standard
}

func decode(c *Certificate) (*decoded, error) {
	if c.AggregateVerificationKeySnark != nil || c.AncillaryProverData != nil || c.AncillaryVerifierData != nil || c.GenesisSchnorrSignature != nil {
		return nil, fmt.Errorf("certificate %s carries SNARK fields, which this version of mithril2pq cannot verify", c.Hash)
	}
	d := &decoded{Certificate: c}
	var err error
	if d.avk, err = DecodeAVK(c.AggregateVerificationKey); err != nil {
		return nil, fmt.Errorf("certificate %s: %w", c.Hash, err)
	}
	if c.IsGenesis() {
		if d.genesis, err = decodeGenesisSignature(c.GenesisSignature); err != nil {
			return nil, fmt.Errorf("certificate %s: %w", c.Hash, err)
		}
		return d, nil
	}
	if _, err := signedEntityFeed(c.SignedEntityType); err != nil {
		return nil, fmt.Errorf("certificate %s: %w", c.Hash, err)
	}
	var p stm.ConcatenationProof
	if err := DecodeJSONHex(c.MultiSignature, &p); err != nil {
		return nil, fmt.Errorf("certificate %s: multi-signature is not a concatenation proof this version of mithril2pq can read: %w", c.Hash, err)
	}
	d.multiSig = &p
	return d, nil
}

func jsonHex(v json.Marshaler) (string, error) {
	b, err := v.MarshalJSON()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// computeHash is Certificate::try_compute_hash. The AVK and multi-signature
// enter as the hex of their re-encoded canonical JSON, not the wire text.
func (d *decoded) computeHash() (string, error) {
	mh, err := d.Metadata.Hash()
	if err != nil {
		return "", err
	}
	pm, err := d.ProtocolMessage.Hash()
	if err != nil {
		return "", err
	}
	avk, err := jsonHex(d.avk)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(d.PreviousHash))
	h.Write(binary.BigEndian.AppendUint64(nil, d.Epoch))
	h.Write([]byte(mh))
	h.Write([]byte(pm))
	h.Write([]byte(d.SignedMessage))
	h.Write([]byte(avk))
	if d.genesis != nil {
		h.Write([]byte(hex.EncodeToString(d.genesis)))
	} else {
		feed, err := signedEntityFeed(d.SignedEntityType)
		if err != nil {
			return "", err
		}
		h.Write(feed)
		ms, err := jsonHex(d.multiSig)
		if err != nil {
			return "", err
		}
		h.Write([]byte(ms))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ComputeHash returns the hash Mithril computes over the certificate's
// content, for comparison with its Hash field.
func (c *Certificate) ComputeHash() (string, error) {
	d, err := decode(c)
	if err != nil {
		return "", err
	}
	return d.computeHash()
}
