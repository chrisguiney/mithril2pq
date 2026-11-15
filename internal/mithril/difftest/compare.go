// SPDX-License-Identifier: Apache-2.0

package difftest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
)

// Accessors read request fields whether the request was built in Go or
// decoded from a corpus file with json.Decoder.UseNumber.

func (r Request) op() string { s, _ := r["op"].(string); return s }

func (r Request) str(k string) string { s, _ := r[k].(string); return s }

func (r Request) hex(k string) []byte {
	b, err := hex.DecodeString(r.str(k))
	if err != nil {
		panic(fmt.Sprintf("difftest: request field %q is not hex", k))
	}
	return b
}

func (r Request) u64(k string) uint64 {
	switch v := r[k].(type) {
	case uint64:
		return v
	case int:
		return uint64(v)
	case json.Number:
		n, err := strconv.ParseUint(string(v), 10, 64)
		if err != nil {
			panic(fmt.Sprintf("difftest: request field %q: %v", k, err))
		}
		return n
	}
	panic(fmt.Sprintf("difftest: request field %q is %T", k, r[k]))
}

func (r Request) f64(k string) float64 {
	n, err := strconv.ParseUint(r.str(k), 16, 64)
	if err != nil {
		panic(fmt.Sprintf("difftest: request field %q is not float bits", k))
	}
	return math.Float64frombits(n)
}

func (r Request) list(k string) []any {
	switch v := r[k].(type) {
	case []any:
		return v
	case []string:
		out := make([]any, len(v))
		for i := range v {
			out[i] = v[i]
		}
		return out
	case [][]any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = v[i]
		}
		return out
	case []uint64:
		out := make([]any, len(v))
		for i := range v {
			out[i] = v[i]
		}
		return out
	case nil:
		return nil
	}
	panic(fmt.Sprintf("difftest: request field %q is %T", k, r[k]))
}

func (r Request) hexList(k string) [][]byte {
	var out [][]byte
	for _, v := range r.list(k) {
		b, err := hex.DecodeString(v.(string))
		if err != nil {
			panic(fmt.Sprintf("difftest: request field %q has a non-hex element", k))
		}
		out = append(out, b)
	}
	return out
}

func (r Request) u64List(k string) []uint64 {
	var out []uint64
	for _, v := range r.list(k) {
		out = append(out, Request{"x": v}.u64("x"))
	}
	return out
}

// Bits encodes a float for a request.
func Bits(f float64) string { return fmt.Sprintf("%016x", math.Float64bits(f)) }

func okOut(v any) Answer {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return Answer{OK: true, Out: b}
}

func reject(class string, err error) Answer {
	a := Answer{Err: class}
	if err != nil {
		a.Detail = err.Error()
	}
	return a
}

// sameOut compares outputs as JSON values, so key order and spacing in
// object outputs do not matter but every number and string does.
func sameOut(a, b json.RawMessage) bool {
	norm := func(m json.RawMessage) string {
		d := json.NewDecoder(bytes.NewReader(m))
		d.UseNumber()
		var v any
		if err := d.Decode(&v); err != nil {
			return "invalid:" + string(m)
		}
		out, _ := json.Marshal(v)
		return string(out)
	}
	return norm(a) == norm(b)
}

// errDiverge is wrapped by every unexplained difference.
var errDiverge = errors.New("Go and Rust disagree")

func diverge(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errDiverge, fmt.Sprintf(format, args...))
}

// Compare decides whether the Go answer got and the Rust answer want to
// req agree. It returns the name of the divergence rule that explains a
// difference, "" when they are equal, or an error for an unexplained
// difference.
func Compare(req Request, got, want Answer) (string, error) {
	t, ok := targets[req.op()]
	if !ok {
		return "", fmt.Errorf("difftest: unknown op %q", req.op())
	}
	if t.norm != nil {
		want = t.norm(want)
	}
	err := plainCompare(t, got, want)
	if err == nil {
		return "", nil
	}
	if rule := t.rule(req, got, want); rule != "" {
		return rule, nil
	}
	if want.Panic && !got.OK {
		// Go fails closed where Rust panics, for example on the U8F24
		// conversion of an out-of-range phi_f.
		return "rust-panics-go-rejects", nil
	}
	return "", err
}

func plainCompare(t target, got, want Answer) error {
	switch {
	case want.Panic:
		return diverge("Rust panicked (%s); Go ok=%v", want.Detail, got.OK)
	case got.OK != want.OK:
		return diverge("accept/reject: Go ok=%v (%s), Rust ok=%v (%s)", got.OK, got.Err, want.OK, want.Err)
	case got.OK && !sameOut(got.Out, want.Out):
		return diverge("outputs differ")
	case !got.OK && t.compareErr && got.Err != want.Err:
		return diverge("error class: Go %s, Rust %s", got.Err, want.Err)
	}
	return nil
}

// Eval answers req with the Go port.
func Eval(req Request) Answer {
	t, ok := targets[req.op()]
	if !ok {
		panic(fmt.Sprintf("difftest: unknown op %q", req.op()))
	}
	return t.eval(req)
}

// target is one operation: its Go evaluator, whether error classes are
// comparable (both sides check in the same order and the vocabularies map
// one to one), and the divergence rules that apply to it.
type target struct {
	eval       func(Request) Answer
	compareErr bool
	// norm, if set, maps the oracle's answer onto the Go vocabulary
	// before comparison.
	norm func(Answer) Answer
	// slow, if set, flags requests both sides would take seconds or
	// more to answer; fuzzing skips them so it is not stalled.
	slow func(Request) bool
	// rules is consulted only when the answers differ. It returns the
	// name of the accepted divergence that explains the difference, or "".
	rules func(req Request, got, want Answer) string
}

func (t target) rule(req Request, got, want Answer) string {
	if t.rules == nil {
		return ""
	}
	return t.rules(req, got, want)
}

var targets = map[string]target{}
