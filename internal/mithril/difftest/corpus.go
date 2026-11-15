// SPDX-License-Identifier: Apache-2.0

package difftest

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
)

// Record is one recorded comparison: a request and Rust's answer to it. A
// small request is stored as is (Req); a large one (certificates, proofs)
// as the generator call that rebuilds it (Gen and Args) with the SHA-256 of
// the request it built when recorded, so a generator change cannot
// silently replay a different question against an old answer.
type Record struct {
	Note string          `json:"note,omitempty"`
	Req  Request         `json:"req,omitempty"`
	Gen  string          `json:"gen,omitempty"`
	Args json.RawMessage `json:"args,omitempty"`
	Sum  string          `json:"sha256,omitempty"`
	Want Answer          `json:"want"`
	// Rule is the accepted divergence the pair was classified under when
	// recorded, or "" if Go and Rust agreed.
	Rule string `json:"rule,omitempty"`
}

// generators rebuild large requests from their arguments.
var generators = map[string]func(args []json.RawMessage) (Request, error){
	"proof": func(a []json.RawMessage) (Request, error) {
		var f byte
		var ops []byte
		if err := unpack(a, &f, &ops); err != nil {
			return nil, err
		}
		return MutateProof(f, ops), nil
	},
	"proof_json": func(a []json.RawMessage) (Request, error) {
		var f byte
		var ops []byte
		if err := unpack(a, &f, &ops); err != nil {
			return nil, err
		}
		return ProofJSONRequest(f, ops), nil
	},
	"batch_path": func(a []json.RawMessage) (Request, error) {
		var n byte
		var sel uint64
		var ops []byte
		if err := unpack(a, &n, &sel, &ops); err != nil {
			return nil, err
		}
		return BatchPathRequest(n, sel, ops), nil
	},
	"aggregate": func(a []json.RawMessage) (Request, error) {
		var verify bool
		var msg, ops []byte
		if err := unpack(a, &verify, &msg, &ops); err != nil {
			return nil, err
		}
		return AggregateRequest(verify, msg, ops), nil
	},
	"gen": func(a []json.RawMessage) (Request, error) {
		var seed, stakes, msg []byte
		var m, k, phi uint8
		if err := unpack(a, &seed, &stakes, &m, &k, &phi, &msg); err != nil {
			return nil, err
		}
		return GenRequest(seed, stakes, m, k, phi, msg), nil
	},
	"cert_hash": func(a []json.RawMessage) (Request, error) {
		var f byte
		var ops, jops []byte
		if err := unpack(a, &f, &ops, &jops); err != nil {
			return nil, err
		}
		return CertHashRequest(f, ops, jops), nil
	},
	"cert_verify": func(a []json.RawMessage) (Request, error) {
		var p byte
		var ops []byte
		if err := unpack(a, &p, &ops); err != nil {
			return nil, err
		}
		return CertVerifyRequest(p, ops), nil
	},
	"live_verify": func(a []json.RawMessage) (Request, error) {
		var i int
		if err := unpack(a, &i); err != nil {
			return nil, err
		}
		return LiveVerifyRequest(i)
	},
}

func unpack(args []json.RawMessage, dst ...any) error {
	if len(args) != len(dst) {
		return fmt.Errorf("want %d arguments, got %d", len(dst), len(args))
	}
	for i := range dst {
		if err := json.Unmarshal(args[i], dst[i]); err != nil {
			return fmt.Errorf("argument %d: %w", i, err)
		}
	}
	return nil
}

func requestSum(r Request) string {
	b, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Request returns the record's request, rebuilding it if it was recorded
// as a generator call.
func (rec *Record) Request() (Request, error) {
	if rec.Gen == "" {
		return rec.Req, nil
	}
	g, ok := generators[rec.Gen]
	if !ok {
		return nil, fmt.Errorf("unknown generator %q", rec.Gen)
	}
	var args []json.RawMessage
	if err := json.Unmarshal(rec.Args, &args); err != nil {
		return nil, err
	}
	r, err := g(args)
	if err != nil {
		return nil, err
	}
	// Round-trip through JSON so the request has the types a recorded
	// one has.
	b, _ := json.Marshal(r)
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var out Request
	if err := d.Decode(&out); err != nil {
		return nil, err
	}
	if got := requestSum(out); got != rec.Sum {
		return nil, fmt.Errorf("generator %s%s now builds a different request (sha256 %s, recorded %s): regenerate the corpus", rec.Gen, rec.Args, got, rec.Sum)
	}
	return out, nil
}

// ReadCorpus reads every *.jsonl file in dir.
func ReadCorpus(dir string) (map[string][]Record, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	out := map[string][]Record{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(nil, 16<<20)
		for n := 1; sc.Scan(); n++ {
			d := json.NewDecoder(bytes.NewReader(sc.Bytes()))
			d.UseNumber()
			var r Record
			if err := d.Decode(&r); err != nil {
				return nil, fmt.Errorf("%s:%d: %w", f, n, err)
			}
			out[filepath.Base(f)] = append(out[filepath.Base(f)], r)
		}
	}
	return out, nil
}

// platformRules may or may not appear on replay depending on the machine:
// Go's math.Log can match or differ from the libm the oracle used.
var platformRules = []string{"libm-ln"}

// Replay checks one record against the Go port.
func Replay(rec Record) error {
	req, err := rec.Request()
	if err != nil {
		return err
	}
	got := Eval(req)
	rule, err := Compare(req, got, rec.Want)
	if err != nil {
		b, _ := json.Marshal(req)
		return fmt.Errorf("%w\nrequest: %s\n     go: %s\n   rust: %s", err, truncate(b), show(got), show(rec.Want))
	}
	if rule != rec.Rule && !slices.Contains(platformRules, rule) && !slices.Contains(platformRules, rec.Rule) {
		return fmt.Errorf("classification changed: recorded %q, now %q", rec.Rule, rule)
	}
	return nil
}

// Case is one request to record, with how to store it.
type Case struct {
	Note string
	Req  Request // stored inline when Gen is ""
	Gen  string
	Args []any
}

// Record asks the oracle about c and returns the record, failing tb on an
// unexplained divergence: those must be fixed or classified first.
func (c Case) Record(tb testing.TB) Record {
	tb.Helper()
	rec := Record{Note: c.Note, Req: c.Req}
	if c.Gen != "" {
		args, err := json.Marshal(c.Args)
		if err != nil {
			tb.Fatal(err)
		}
		rec = Record{Note: c.Note, Gen: c.Gen, Args: args, Sum: "pending"}
		raw, err := generators[c.Gen](mustRaw(args))
		if err != nil {
			tb.Fatal(err)
		}
		b, _ := json.Marshal(raw)
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		var r Request
		_ = d.Decode(&r)
		rec.Sum = requestSum(r)
	}
	req, err := rec.Request()
	if err != nil {
		tb.Fatal(err)
	}
	want := Ask(tb, req)
	if len(want.Detail) > 160 {
		want.Detail = want.Detail[:160]
	}
	rule, err := Compare(req, Eval(req), want)
	if err != nil {
		b, _ := json.Marshal(req)
		tb.Fatalf("unexplained divergence, fix or classify before recording: %v\n%s", err, truncate(b))
	}
	rec.Want, rec.Rule = want, rule
	return rec
}

func mustRaw(b []byte) []json.RawMessage {
	var out []json.RawMessage
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

// WriteCorpus writes records as JSON lines, sorted by file name.
func WriteCorpus(path string, recs []Record) error {
	var w bytes.Buffer
	for _, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		w.Write(b)
		w.WriteByte('\n')
	}
	return os.WriteFile(path, w.Bytes(), 0o644)
}

// SortedKeys returns m's keys in order.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
