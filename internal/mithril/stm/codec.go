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
	"io"
	"strconv"
)

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

// The decoders below mirror serde_json's derived Deserialize for these
// types, which encoding/json does not: keys match exactly (no case
// folding), a repeated field is an error, every field is required, and
// unknown keys are skipped, repeated or not. Arrays must be arrays, not null.

// decodeObject reads one JSON object, passing each known key's raw value to
// its handler, and fails unless every known key appeared exactly once.
func decodeObject(data []byte, fields map[string]func(json.RawMessage) error) error {
	d := json.NewDecoder(bytes.NewReader(data))
	if tok, err := d.Token(); err != nil || tok != json.Delim('{') {
		return errors.New("want a JSON object")
	}
	seen := map[string]bool{}
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		key := tok.(string)
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return err
		}
		f, ok := fields[key]
		if !ok {
			// serde skips unknown keys without tracking them, so a
			// repeated unknown key is not an error.
			continue
		}
		if seen[key] {
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		if err := f(raw); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	if _, err := d.Token(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing data after JSON value")
	}
	for k := range fields {
		if !seen[k] {
			return fmt.Errorf("missing key %q", k)
		}
	}
	return nil
}

// decodeArray reads a JSON array (not null) of raw elements.
func decodeArray(data []byte) ([]json.RawMessage, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, errors.New("want an array, got null")
	}
	var out []json.RawMessage
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []json.RawMessage{}
	}
	return out, nil
}

func decodeU64(data []byte) (uint64, error) {
	return strconv.ParseUint(string(bytes.TrimSpace(data)), 10, 64)
}

func decodeU64s(data []byte) ([]uint64, error) {
	elems, err := decodeArray(data)
	if err != nil {
		return nil, err
	}
	out := make([]uint64, len(elems))
	for i, e := range elems {
		if out[i], err = decodeU64(e); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// decodeBytes reads a JSON array of integers 0..255.
func decodeBytes(data []byte) ([]byte, error) {
	elems, err := decodeArray(data)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(elems))
	for i, e := range elems {
		v, err := strconv.ParseUint(string(bytes.TrimSpace(e)), 10, 8)
		if err != nil {
			return nil, fmt.Errorf("byte %d is %s", i, e)
		}
		out[i] = byte(v)
	}
	return out, nil
}

func decodeNull(data json.RawMessage) error {
	if !bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("must be null")
	}
	return nil
}

// decodeTuple reads a fixed-length JSON array.
func decodeTuple(data []byte, n int) ([]json.RawMessage, error) {
	elems, err := decodeArray(data)
	if err != nil {
		return nil, err
	}
	if len(elems) != n {
		return nil, fmt.Errorf("want %d elements, got %d", n, len(elems))
	}
	return elems, nil
}

// UnmarshalJSON decodes {"mt_commitment":{"root":[..],"nr_leaves":n,"hasher":null},"total_stake":n}.
func (a *AggregateVerificationKey) UnmarshalJSON(data []byte) error {
	var out AggregateVerificationKey
	err := decodeObject(data, map[string]func(json.RawMessage) error{
		"mt_commitment": func(raw json.RawMessage) error {
			return decodeObject(raw, map[string]func(json.RawMessage) error{
				"root": func(raw json.RawMessage) (err error) {
					if out.Root, err = decodeBytes(raw); err == nil && len(out.Root) != 32 {
						err = fmt.Errorf("root is %d bytes", len(out.Root))
					}
					return err
				},
				"nr_leaves": func(raw json.RawMessage) (err error) { out.NrLeaves, err = decodeU64(raw); return err },
				"hasher":    decodeNull,
			})
		},
		"total_stake": func(raw json.RawMessage) (err error) { out.TotalStake, err = decodeU64(raw); return err },
	})
	if err != nil {
		return fmt.Errorf("stm: aggregate verification key: %w", err)
	}
	*a = out
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

func decodeSingleSignature(data []byte) (SingleSignature, error) {
	var s SingleSignature
	err := decodeObject(data, map[string]func(json.RawMessage) error{
		"sigma": func(raw json.RawMessage) error {
			b, err := decodeBytes(raw)
			if err != nil {
				return err
			}
			s.Sigma, err = SignatureFromBytes(b)
			return err
		},
		"indexes":      func(raw json.RawMessage) (err error) { s.Indexes, err = decodeU64s(raw); return err },
		"signer_index": func(raw json.RawMessage) (err error) { s.SignerIndex, err = decodeU64(raw); return err },
	})
	return s, err
}

func decodeRegistration(data []byte) (Leaf, error) {
	t, err := decodeTuple(data, 2)
	if err != nil {
		return Leaf{}, err
	}
	b, err := decodeBytes(t[0])
	if err != nil {
		return Leaf{}, err
	}
	vk, err := VerificationKeyFromBytes(b)
	if err != nil {
		return Leaf{}, err
	}
	stake, err := decodeU64(t[1])
	return Leaf{VK: vk, Stake: stake}, err
}

// UnmarshalJSON decodes the concatenation proof in its serde form:
// {"signatures":[[sig, [vk, stake]], ...], "batch_proof":{...}}. Every
// curve point is validated as it is decoded.
func (p *ConcatenationProof) UnmarshalJSON(data []byte) error {
	var out ConcatenationProof
	err := decodeObject(data, map[string]func(json.RawMessage) error{
		"signatures": func(raw json.RawMessage) error {
			elems, err := decodeArray(raw)
			if err != nil {
				return err
			}
			for i, e := range elems {
				pair, err := decodeTuple(e, 2)
				if err != nil {
					return fmt.Errorf("entry %d: %w", i, err)
				}
				sig, err := decodeSingleSignature(pair[0])
				if err != nil {
					return fmt.Errorf("entry %d signature: %w", i, err)
				}
				party, err := decodeRegistration(pair[1])
				if err != nil {
					return fmt.Errorf("entry %d registration: %w", i, err)
				}
				out.Signatures = append(out.Signatures, SignedEntry{Sig: sig, Party: party})
			}
			return nil
		},
		"batch_proof": func(raw json.RawMessage) error {
			return decodeObject(raw, map[string]func(json.RawMessage) error{
				"values": func(raw json.RawMessage) error {
					elems, err := decodeArray(raw)
					if err != nil {
						return err
					}
					out.BatchPath.Values = make([][]byte, len(elems))
					for i, e := range elems {
						if out.BatchPath.Values[i], err = decodeBytes(e); err != nil {
							return err
						}
					}
					return nil
				},
				"indices": func(raw json.RawMessage) (err error) { out.BatchPath.Indices, err = decodeU64s(raw); return err },
				"hasher":  decodeNull,
			})
		},
	})
	if err != nil {
		return fmt.Errorf("stm: multi-signature: %w", err)
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
