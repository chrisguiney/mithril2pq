// SPDX-License-Identifier: Apache-2.0

// Package difftest compares the Go port of Mithril (packages stm and chain)
// with Mithril's own Rust crates, mithril-stm 0.13.0 and mithril-common
// 0.8.3, through the oracle program in fuzz/oracle. It is imported only by
// tests: the mithril2pq binary never links it, and it never runs anything
// unless MITHRIL2PQ_ORACLE names the oracle.
//
// Every comparison is a Request (an operation and its inputs, exactly as
// the oracle receives it) answered twice: by Eval, with the Go port, and by
// the oracle. Compare decides whether the two answers agree, agree under a
// named, documented divergence rule, or diverge.
package difftest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// OracleEnv names the oracle command: a path to the binary, or a command
// line such as "docker run -i --rm -v DIR:/o IMAGE /o/mithril-oracle".
const OracleEnv = "MITHRIL2PQ_ORACLE"

// Request is one question: "op" names the operation and the other keys
// are its inputs. Byte strings are lower-case hex, floats are 16 hex digits
// of their IEEE-754 bits, integers are JSON numbers.
type Request map[string]any

// Answer is a normalised result. Out is the operation's output when OK; Err
// is the error class when not. Aux carries intermediate values that
// divergence rules use to classify a difference, and Detail is diagnostic
// text; neither is compared.
type Answer struct {
	OK     bool            `json:"ok"`
	Err    string          `json:"err,omitempty"`
	Out    json.RawMessage `json:"out,omitempty"`
	Aux    json.RawMessage `json:"aux,omitempty"`
	Panic  bool            `json:"panic,omitempty"`
	Detail string          `json:"detail,omitempty"`
}

type client struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
	id  int
}

var (
	oracleMu sync.Mutex
	oracleC  *client
)

// Enabled reports whether an oracle is configured.
func Enabled() bool { return os.Getenv(OracleEnv) != "" }

func start() (*client, error) {
	argv := strings.Fields(os.Getenv(OracleEnv))
	cmd := exec.Command(argv[0], argv[1:]...)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting oracle %q: %w", argv, err)
	}
	return &client{cmd: cmd, in: in, out: bufio.NewReaderSize(out, 1<<20)}, nil
}

// Ask sends req to the oracle and returns its answer. A malformed request
// or an oracle that dies fails the test: the first is a harness bug, the
// second (an abort, not a panic) a finding the fuzzer should keep.
func Ask(tb testing.TB, req Request) Answer {
	tb.Helper()
	oracleMu.Lock()
	defer oracleMu.Unlock()
	if oracleC == nil {
		c, err := start()
		if err != nil {
			tb.Fatal(err)
		}
		oracleC = c
	}
	c := oracleC
	c.id++
	msg := Request{"id": c.id}
	for k, v := range req {
		msg[k] = v
	}
	line, err := json.Marshal(msg)
	if err != nil {
		tb.Fatalf("encoding request: %v", err)
	}
	reply, err := c.roundTrip(line)
	if err != nil {
		_ = c.cmd.Process.Kill()
		_ = c.cmd.Wait()
		oracleC = nil
		tb.Fatalf("oracle died on %s: %v", line, err)
	}
	var a struct {
		Answer
		ID    int    `json:"id"`
		Fatal string `json:"fatal"`
	}
	if err := json.Unmarshal(reply, &a); err != nil {
		tb.Fatalf("oracle answer %q: %v", reply, err)
	}
	if a.Fatal != "" {
		tb.Fatalf("oracle rejected request %s: %s", line, a.Fatal)
	}
	if a.ID != c.id {
		tb.Fatalf("oracle answered request %d, want %d", a.ID, c.id)
	}
	return a.Answer
}

func (c *client) roundTrip(line []byte) ([]byte, error) {
	if _, err := c.in.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	return c.out.ReadBytes('\n')
}

// Check answers req with the Go port and, when an oracle is configured,
// with the oracle, and fails tb unless Compare accepts the pair. Without an
// oracle the Go side still runs (so seed corpora exercise it for panics),
// and the comparison is skipped with a message saying so.
func Check(tb testing.TB, req Request) {
	tb.Helper()
	if t := targets[req.op()]; t.slow != nil && t.slow(req) {
		tb.Skip("both sides take seconds on this input: see slowLottery")
	}
	got := Eval(req)
	if !Enabled() {
		tb.Skipf("Go side ran; comparison with Rust skipped: %s is not set (see fuzz/oracle/README.md)", OracleEnv)
	}
	want := Ask(tb, req)
	rule, err := Compare(req, got, want)
	if err != nil {
		b, _ := json.Marshal(req)
		tb.Fatalf("divergence: %v\nrequest: %s\n     go: %s\n   rust: %s", err, truncate(b), show(got), show(want))
	}
	if rule != "" {
		tb.Logf("accepted divergence %q", rule)
	}
}

func show(a Answer) string {
	b, _ := json.Marshal(a)
	return truncate(b)
}

func truncate(b []byte) string {
	if len(b) > 4000 {
		return string(b[:4000]) + "..."
	}
	return string(b)
}
