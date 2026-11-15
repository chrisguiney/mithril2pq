// SPDX-License-Identifier: Apache-2.0
//
// Ported from the serde encodings of mithril-stm's AggregateVerificationKey,
// ConcatenationProof, SingleSignature, ClosedRegistrationEntry and
// MerkleBatchPath (mithril-stm/src/proof_system/concatenation/,
// mithril-stm/src/protocol/, mithril-stm/src/membership_commitment/) in
// IntersectMBO/mithril at release 2642.0
// (e85df3ddc52b528c7b9ddbdddf1941fec6d5f348).
// Copyright 2022 Input Output (Hong Kong) Ltd.
// Modifications: translated from Rust to Go; the JSON is written by hand to
// reproduce serde_json's compact output byte for byte, because certificate
// hashes are computed over it. Byte arrays are JSON arrays of integers,
// structs keep their field order and PhantomData is "hasher":null.

package stm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// byteArray decodes a JSON array of integers 0..255.
type byteArray []byte

func (b *byteArray) UnmarshalJSON(data []byte) error {
	var ints []json.Number
	if err := json.Unmarshal(data, &ints); err != nil {
		return fmt.Errorf("stm: want an array of bytes: %w", err)
	}
	out := make([]byte, len(ints))
	for i, n := range ints {
		v, err := strconv.ParseUint(string(n), 10, 8)
		if err != nil {
			return fmt.Errorf("stm: byte %d is %s", i, n)
		}
		out[i] = byte(v)
	}
	*b = out
	return nil
}

func appendBytes(w *bytes.Buffer, b []byte) {
	w.WriteByte('[')
	for i, v := range b {
		if i > 0 {
			w.WriteByte(',')
		}
		w.WriteString(strconv.Itoa(int(v)))
	}
	w.WriteByte(']')
}

func appendU64s(w *bytes.Buffer, xs []uint64) {
	w.WriteByte('[')
	for i, v := range xs {
		if i > 0 {
			w.WriteByte(',')
		}
		w.WriteString(strconv.FormatUint(v, 10))
	}
	w.WriteByte(']')
}

func decodeStrict(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("stm: trailing data after JSON value")
	}
	return nil
}

type avkJSON struct {
	MTCommitment struct {
		Root     byteArray       `json:"root"`
		NrLeaves uint64          `json:"nr_leaves"`
		Hasher   json.RawMessage `json:"hasher"`
	} `json:"mt_commitment"`
	TotalStake uint64 `json:"total_stake"`
}

// UnmarshalJSON decodes {"mt_commitment":{"root":[..],"nr_leaves":n,"hasher":null},"total_stake":n}.
func (a *AggregateVerificationKey) UnmarshalJSON(data []byte) error {
	var j avkJSON
	if err := decodeStrict(data, &j); err != nil {
		return fmt.Errorf("stm: aggregate verification key: %w", err)
	}
	if string(j.MTCommitment.Hasher) != "null" {
		return errors.New(`stm: aggregate verification key: "hasher" must be null`)
	}
	if len(j.MTCommitment.Root) != 32 {
		return fmt.Errorf("stm: aggregate verification key root is %d bytes", len(j.MTCommitment.Root))
	}
	*a = AggregateVerificationKey{Root: j.MTCommitment.Root, NrLeaves: j.MTCommitment.NrLeaves, TotalStake: j.TotalStake}
	return nil
}

// MarshalJSON writes the key as serde_json does.
func (a *AggregateVerificationKey) MarshalJSON() ([]byte, error) {
	var w bytes.Buffer
	w.WriteString(`{"mt_commitment":{"root":`)
	appendBytes(&w, a.Root)
	w.WriteString(`,"nr_leaves":`)
	w.WriteString(strconv.FormatUint(a.NrLeaves, 10))
	w.WriteString(`,"hasher":null},"total_stake":`)
	w.WriteString(strconv.FormatUint(a.TotalStake, 10))
	w.WriteByte('}')
	return w.Bytes(), nil
}

type singleSigJSON struct {
	Sigma       byteArray `json:"sigma"`
	Indexes     []uint64  `json:"indexes"`
	SignerIndex uint64    `json:"signer_index"`
}

type proofJSON struct {
	Signatures []json.RawMessage `json:"signatures"`
	BatchProof struct {
		Values  []byteArray     `json:"values"`
		Indices []uint64        `json:"indices"`
		Hasher  json.RawMessage `json:"hasher"`
	} `json:"batch_proof"`
}

// UnmarshalJSON decodes the concatenation proof in its serde form:
// {"signatures":[[sig, [vk, stake]], ...], "batch_proof":{...}}. Every
// curve point is validated as it is decoded.
func (p *ConcatenationProof) UnmarshalJSON(data []byte) error {
	var j proofJSON
	if err := decodeStrict(data, &j); err != nil {
		return fmt.Errorf("stm: multi-signature: %w", err)
	}
	if string(j.BatchProof.Hasher) != "null" {
		return errors.New(`stm: multi-signature: batch proof "hasher" must be null`)
	}
	out := ConcatenationProof{BatchPath: BatchPath{Indices: j.BatchProof.Indices}}
	for _, v := range j.BatchProof.Values {
		out.BatchPath.Values = append(out.BatchPath.Values, v)
	}
	for i, raw := range j.Signatures {
		var pair []json.RawMessage
		if err := decodeStrict(raw, &pair); err != nil || len(pair) != 2 {
			return fmt.Errorf("stm: multi-signature entry %d: want [signature, registration]", i)
		}
		var s singleSigJSON
		if err := decodeStrict(pair[0], &s); err != nil {
			return fmt.Errorf("stm: multi-signature entry %d signature: %w", i, err)
		}
		var reg []json.RawMessage
		if err := decodeStrict(pair[1], &reg); err != nil || len(reg) != 2 {
			return fmt.Errorf("stm: multi-signature entry %d: want registration [vk, stake]", i)
		}
		var vkb byteArray
		var stake uint64
		if err := decodeStrict(reg[0], &vkb); err != nil {
			return fmt.Errorf("stm: multi-signature entry %d key: %w", i, err)
		}
		if err := decodeStrict(reg[1], &stake); err != nil {
			return fmt.Errorf("stm: multi-signature entry %d stake: %w", i, err)
		}
		sigma, err := SignatureFromBytes(s.Sigma)
		if err != nil {
			return fmt.Errorf("stm: multi-signature entry %d: %w", i, err)
		}
		vk, err := VerificationKeyFromBytes(vkb)
		if err != nil {
			return fmt.Errorf("stm: multi-signature entry %d: %w", i, err)
		}
		out.Signatures = append(out.Signatures, SignedEntry{
			Sig:   SingleSignature{Sigma: sigma, Indexes: s.Indexes, SignerIndex: s.SignerIndex},
			Party: Leaf{VK: vk, Stake: stake},
		})
	}
	*p = out
	return nil
}

// MarshalJSON writes the proof as serde_json does.
func (p *ConcatenationProof) MarshalJSON() ([]byte, error) {
	var w bytes.Buffer
	w.WriteString(`{"signatures":[`)
	for i, e := range p.Signatures {
		if i > 0 {
			w.WriteByte(',')
		}
		w.WriteString(`[{"sigma":`)
		appendBytes(&w, e.Sig.Sigma.Bytes())
		w.WriteString(`,"indexes":`)
		appendU64s(&w, e.Sig.Indexes)
		w.WriteString(`,"signer_index":`)
		w.WriteString(strconv.FormatUint(e.Sig.SignerIndex, 10))
		w.WriteString(`},[`)
		appendBytes(&w, e.Party.VK.Bytes())
		w.WriteByte(',')
		w.WriteString(strconv.FormatUint(e.Party.Stake, 10))
		w.WriteString(`]]`)
	}
	w.WriteString(`],"batch_proof":{"values":[`)
	for i, v := range p.BatchPath.Values {
		if i > 0 {
			w.WriteByte(',')
		}
		appendBytes(&w, v)
	}
	w.WriteString(`],"indices":`)
	appendU64s(&w, p.BatchPath.Indices)
	w.WriteString(`,"hasher":null}}`)
	return w.Bytes(), nil
}
