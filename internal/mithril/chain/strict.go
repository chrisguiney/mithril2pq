// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// UnmarshalJSON decodes a certificate message as mithril-client does:
// exact keys, no repeated fields, every field present and non-null unless
// Mithril makes it optional, a known protocol message hash scheme and part
// keys, and timestamps that parse.
func (c *Certificate) UnmarshalJSON(data []byte) error {
	clean, err := strictJSON(data, certificateFields)
	if err != nil {
		return fmt.Errorf("certificate message: %w", err)
	}
	type plain Certificate
	var out plain
	if err := json.Unmarshal(clean, &out); err != nil {
		return fmt.Errorf("certificate message: %w", err)
	}
	if s := out.ProtocolMessage.HashScheme; s != "" && s != "legacy" {
		return fmt.Errorf("certificate message: protocol message uses hash scheme %q, which this version of mithril2pq cannot check", s)
	}
	for k := range out.ProtocolMessage.MessageParts {
		if !slices.Contains(protocolMessagePartOrder, k) {
			return fmt.Errorf("certificate message: protocol message has unknown part %q", k)
		}
	}
	for _, ts := range []string{out.Metadata.InitiatedAt, out.Metadata.SealedAt} {
		if _, err := unixNanos(ts); err != nil {
			return fmt.Errorf("certificate message: %w", err)
		}
	}
	*c = Certificate(out)
	return nil
}

// Certificate messages are decoded by serde's derived Deserialize in
// Mithril and by encoding/json here, and the two disagree on malformed
// input: encoding/json matches keys case-insensitively, lets a repeated key
// overwrite the earlier one, reads null and absent fields as zero values
// and ignores array elements past a fixed-length array. strictJSON checks
// a message against the shape serde expects and removes keys serde would
// ignore but encoding/json would not, so both read the same values or both
// reject.

type jsonKind int

const (
	kindString jsonKind = iota
	kindU64
	kindF64
	kindObject
	kindArray
	kindStringMap
	kindAny
)

// jsonField is a field of a serde struct. A field may be absent if it is
// an Option or has serde(default), and null only if it is an Option.
type jsonField struct {
	name   string
	kind   jsonKind
	absent bool
	null   bool
	fields []jsonField // kindObject, and the element of kindArray
	values []string    // the allowed values of a kindString enum
}

var beaconFields = []jsonField{{name: "epoch", kind: kindU64}, {name: "immutable_file_number", kind: kindU64}}

var partyFields = []jsonField{{name: "party_id", kind: kindString}, {name: "stake", kind: kindU64}}

var certificateFields = []jsonField{
	{name: "hash", kind: kindString},
	{name: "previous_hash", kind: kindString},
	{name: "epoch", kind: kindU64},
	// Mithril reads any value here (unknown types become Unknown) and
	// rejects an unusable one only when converting a standard
	// certificate; decode does the same.
	{name: "signed_entity_type", kind: kindAny, null: true},
	{name: "metadata", kind: kindObject, fields: []jsonField{
		{name: "network", kind: kindString},
		{name: "version", kind: kindString},
		{name: "parameters", kind: kindObject, fields: []jsonField{
			{name: "k", kind: kindU64}, {name: "m", kind: kindU64}, {name: "phi_f", kind: kindF64},
		}},
		{name: "initiated_at", kind: kindString},
		{name: "sealed_at", kind: kindString},
		{name: "signers", kind: kindArray, fields: partyFields},
	}},
	{name: "protocol_message", kind: kindObject, fields: []jsonField{
		{name: "message_parts", kind: kindStringMap},
		// serde(default): may be absent, but not null.
		{name: "hash_scheme", kind: kindString, absent: true, values: []string{"legacy"}},
	}},
	{name: "signed_message", kind: kindString},
	{name: "aggregate_verification_key", kind: kindString},
	{name: "multi_signature", kind: kindString},
	{name: "genesis_signature", kind: kindString},
	{name: "ancillary_prover_data", kind: kindString, absent: true, null: true},
	{name: "ancillary_verifier_data", kind: kindString, absent: true, null: true},
	// SNARK-build fields: unknown to the release's default build, which
	// ignores them; decode rejects a certificate that has them.
	{name: "aggregate_verification_key_snark", kind: kindAny, absent: true, null: true},
	{name: "genesis_schnorr_signature", kind: kindAny, absent: true, null: true},
}

// node is a parsed JSON value that keeps duplicate keys and number text.
type node struct {
	kind  byte // '{', '[', 's' string, 'n' number, 'b' bool, '0' null
	keys  []string
	items []*node
	text  string // string value, or number/bool literal
}

func parseNode(d *json.Decoder) (*node, error) {
	tok, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := tok.(type) {
	case json.Delim:
		n := &node{kind: byte(v)}
		for d.More() {
			if n.kind == '{' {
				k, err := d.Token()
				if err != nil {
					return nil, err
				}
				n.keys = append(n.keys, k.(string))
			}
			c, err := parseNode(d)
			if err != nil {
				return nil, err
			}
			n.items = append(n.items, c)
		}
		_, err := d.Token()
		return n, err
	case string:
		return &node{kind: 's', text: v}, nil
	case json.Number:
		return &node{kind: 'n', text: string(v)}, nil
	case bool:
		return &node{kind: 'b', text: strconv.FormatBool(v)}, nil
	default:
		return &node{kind: '0'}, nil
	}
}

func (n *node) write(w *bytes.Buffer) {
	switch n.kind {
	case 's':
		b, _ := json.Marshal(n.text)
		w.Write(b)
	case 'n', 'b':
		w.WriteString(n.text)
	case '0':
		w.WriteString("null")
	default:
		closer := byte(']')
		if n.kind == '{' {
			closer = '}'
		}
		w.WriteByte(n.kind)
		for i, c := range n.items {
			if i > 0 {
				w.WriteByte(',')
			}
			if n.kind == '{' {
				b, _ := json.Marshal(n.keys[i])
				w.Write(b)
				w.WriteByte(':')
			}
			c.write(w)
		}
		w.WriteByte(closer)
	}
}

func strictJSON(data []byte, fields []jsonField) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	n, err := parseNode(d)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	if err := checkObject(n, fields); err != nil {
		return nil, err
	}
	var w bytes.Buffer
	n.write(&w)
	return w.Bytes(), nil
}

// checkObject checks n against fields and drops keys that differ from a
// field name only in case: serde ignores them as unknown, encoding/json
// would assign them to the field.
func checkObject(n *node, fields []jsonField) error {
	if n.kind != '{' {
		return errors.New("want a JSON object")
	}
	seen := map[string]bool{}
	var keys []string
	var items []*node
	for i, k := range n.keys {
		var f *jsonField
		folded := false
		for j := range fields {
			if fields[j].name == k {
				f = &fields[j]
			} else if strings.EqualFold(fields[j].name, k) {
				folded = true
			}
		}
		if f == nil && folded {
			continue
		}
		if f != nil {
			if seen[k] {
				return fmt.Errorf("duplicate field %q", k)
			}
			seen[k] = true
			if err := checkValue(n.items[i], f); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
		keys, items = append(keys, k), append(items, n.items[i])
	}
	for _, f := range fields {
		if !seen[f.name] && !f.absent {
			return fmt.Errorf("missing field %q", f.name)
		}
	}
	n.keys, n.items = keys, items
	return nil
}

func checkValue(n *node, f *jsonField) error {
	if n.kind == '0' {
		if f.null {
			return nil
		}
		return errors.New("null")
	}
	if f.kind == kindAny {
		return nil
	}
	want := map[jsonKind]byte{kindString: 's', kindU64: 'n', kindF64: 'n', kindObject: '{', kindArray: '[', kindStringMap: '{'}[f.kind]
	if n.kind != want {
		return fmt.Errorf("want %q, got %q", want, n.kind)
	}
	switch f.kind {
	case kindString:
		if f.values != nil && !slices.Contains(f.values, n.text) {
			return fmt.Errorf("unknown variant %q", n.text)
		}
	case kindU64:
		if _, err := strconv.ParseUint(n.text, 10, 64); err != nil {
			return err
		}
	case kindObject:
		return checkObject(n, f.fields)
	case kindArray:
		for _, c := range n.items {
			if err := checkObject(c, f.fields); err != nil {
				return err
			}
		}
	case kindStringMap:
		for i, c := range n.items {
			if c.kind != 's' {
				return fmt.Errorf("%s: want a string", n.keys[i])
			}
		}
	}
	return nil
}
