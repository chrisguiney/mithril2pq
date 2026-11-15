// SPDX-License-Identifier: Apache-2.0

package difftest

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// jnode is a JSON value that keeps object key order and duplicate keys and
// the exact text of scalars, so that mutations change only what they mean
// to change.
type jnode struct {
	kind  byte // 'o' object, 'a' array, 's' scalar
	keys  []string
	items []*jnode // object values (parallel to keys) or array elements
	raw   string   // scalar text exactly as written
}

func parseJSON(b []byte) (*jnode, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	n, err := parseNode(d)
	if err != nil {
		return nil, err
	}
	if d.More() {
		return nil, errors.New("trailing data")
	}
	return n, nil
}

func parseNode(d *json.Decoder) (*jnode, error) {
	tok, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := tok.(type) {
	case json.Delim:
		n := &jnode{kind: 'a'}
		if v == '{' {
			n.kind = 'o'
		}
		for d.More() {
			if n.kind == 'o' {
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
		if _, err := d.Token(); err != nil {
			return nil, err
		}
		return n, nil
	case json.Number:
		return &jnode{kind: 's', raw: string(v)}, nil
	case nil:
		return &jnode{kind: 's', raw: "null"}, nil
	default:
		b, _ := json.Marshal(v)
		return &jnode{kind: 's', raw: string(b)}, nil
	}
}

func (n *jnode) encode() []byte {
	var w bytes.Buffer
	n.write(&w)
	return w.Bytes()
}

func (n *jnode) write(w *bytes.Buffer) {
	switch n.kind {
	case 's':
		w.WriteString(n.raw)
	case 'a':
		w.WriteByte('[')
		for i, c := range n.items {
			if i > 0 {
				w.WriteByte(',')
			}
			c.write(w)
		}
		w.WriteByte(']')
	case 'o':
		w.WriteByte('{')
		for i, c := range n.items {
			if i > 0 {
				w.WriteByte(',')
			}
			k, _ := json.Marshal(n.keys[i])
			w.Write(k)
			w.WriteByte(':')
			c.write(w)
		}
		w.WriteByte('}')
	}
}

// get returns the first value of key k in an object.
func (n *jnode) get(k string) *jnode {
	if n == nil || n.kind != 'o' {
		return nil
	}
	for i, key := range n.keys {
		if key == k {
			return n.items[i]
		}
	}
	return nil
}

func (n *jnode) set(k string, v *jnode) {
	for i, key := range n.keys {
		if key == k {
			n.items[i] = v
			return
		}
	}
	n.keys = append(n.keys, k)
	n.items = append(n.items, v)
}

func scalar(raw string) *jnode { return &jnode{kind: 's', raw: raw} }

func str(s string) *jnode { b, _ := json.Marshal(s); return scalar(string(b)) }

// walk lists every node in document order.
func (n *jnode) walk(f func(parent *jnode, i int, c *jnode)) {
	for i, c := range n.items {
		f(n, i, c)
		c.walk(f)
	}
}

func (n *jnode) clone() *jnode {
	c := &jnode{kind: n.kind, raw: n.raw, keys: append([]string(nil), n.keys...)}
	for _, it := range n.items {
		c.items = append(c.items, it.clone())
	}
	return c
}

// numberSpellings are other ways to write an integer n that a JSON
// decoder might, or might not, accept as the same number.
func numberSpellings(raw string, sel byte) string {
	switch sel % 14 {
	case 0:
		return raw + ".0"
	case 1:
		return raw + "e0"
	case 2:
		return "0" + raw
	case 3:
		return "-" + raw
	case 4:
		return raw + "E+00"
	case 5:
		return "-0"
	case 6:
		return "1e2"
	case 7:
		return "18446744073709551616"
	case 8:
		return "18446744073709551615"
	case 9:
		return "256"
	case 10:
		return strconv.Quote(raw)
	case 11:
		return "null"
	case 12:
		return raw + ".5"
	default:
		return "-1"
	}
}

// MutateJSON applies token-aware mutations to a JSON document, driven by
// ops two bytes at a time (operation, argument): change the case of a key,
// duplicate, drop or add a key, respell a number, replace a value with
// null, an empty array or an object, add whitespace, or wrap the document.
// It returns the document unchanged if it is not JSON.
func MutateJSON(doc string, ops []byte) string {
	n, err := parseJSON([]byte(doc))
	if err != nil {
		return doc
	}
	pre, post := "", ""
	for i := 0; i+1 < len(ops) && i < 2*8; i += 2 {
		op, a := ops[i], ops[i+1]
		var objs, nums []*jnode
		var parents []*jnode
		var idxs []int
		if n.kind == 'o' {
			objs = append(objs, n)
		}
		n.walk(func(p *jnode, j int, c *jnode) {
			parents, idxs = append(parents, p), append(idxs, j)
			if c.kind == 'o' {
				objs = append(objs, c)
			}
			if c.kind == 's' && c.raw != "" && (c.raw[0] == '-' || (c.raw[0] >= '0' && c.raw[0] <= '9')) {
				nums = append(nums, c)
			}
		})
		pickObj := func() *jnode {
			if len(objs) == 0 {
				return nil
			}
			return objs[int(a)%len(objs)]
		}
		switch op % 10 {
		case 0: // key case
			if o := pickObj(); o != nil && len(o.keys) > 0 {
				if k := int(a/7) % len(o.keys); o.keys[k] != "" {
					o.keys[k] = strings.ToUpper(o.keys[k][:1]) + o.keys[k][1:]
				}
			}
		case 1: // duplicate key
			if o := pickObj(); o != nil && len(o.keys) > 0 {
				k := int(a/7) % len(o.keys)
				o.keys = append(o.keys, o.keys[k])
				o.items = append(o.items, o.items[k].clone())
			}
		case 2: // drop key
			if o := pickObj(); o != nil && len(o.keys) > 0 {
				k := int(a/7) % len(o.keys)
				o.keys = append(o.keys[:k], o.keys[k+1:]...)
				o.items = append(o.items[:k], o.items[k+1:]...)
			}
		case 3: // unknown key
			if o := pickObj(); o != nil {
				o.keys = append(o.keys, []string{"extra", "Hasher", "hasher\u0000", "signer_Index", ""}[int(a/7)%5])
				o.items = append(o.items, scalar("1"))
			}
		case 4:
			if len(nums) > 0 {
				c := nums[int(a)%len(nums)]
				c.raw = numberSpellings(c.raw, a/16)
			}
		case 5:
			if len(parents) > 0 {
				j := int(a) % len(parents)
				parents[j].items[idxs[j]] = scalar([]string{"null", "[]", "{}", "true", `""`}[int(a/32)%5])
			}
		case 6: // a key that differs by an invisible character
			if o := pickObj(); o != nil && len(o.keys) > 0 {
				k := int(a/7) % len(o.keys)
				o.keys[k] = o.keys[k] + "​"
			}
		case 7:
			pre, post = []string{" ", "\n", "\ufeff", ""}[a%4], []string{" ", "\n", "x", ""}[(a/4)%4]
		case 8: // wrap in the tagged enum form
			n = &jnode{kind: 'o', keys: []string{[]string{"Concatenation", "concatenation", "Snark"}[int(a)%3]}, items: []*jnode{n}}
		default: // reorder object keys
			if o := pickObj(); o != nil && len(o.keys) > 1 {
				o.keys[0], o.keys[len(o.keys)-1] = o.keys[len(o.keys)-1], o.keys[0]
				o.items[0], o.items[len(o.items)-1] = o.items[len(o.items)-1], o.items[0]
			}
		}
	}
	return pre + string(n.encode()) + post
}
