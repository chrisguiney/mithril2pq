package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chrisguiney/mithril2pq/internal/dataset"
)

// stats are the run's counters, updated from every stage.
type stats struct {
	chunksTotal      int64
	chunksWritten    atomic.Int64
	chunksDownloaded atomic.Int64
	cacheHits        atomic.Int64
	bytesDownloaded  atomic.Int64
	cacheBytes       atomic.Int64
	blocks           atomic.Int64
	txs              atomic.Int64
	decodeErrors     atomic.Int64
	pq               dataset.Counters
	start            time.Time
}

// progress prints a status line: in place once a second on a terminal,
// otherwise as a log line every ten seconds.
type progress struct {
	st     *stats
	out    io.Writer
	tty    bool
	stop   chan struct{}
	done   sync.WaitGroup
	mu     sync.Mutex
	last   string
	prevAt time.Time
	prevDL int64
	prevWr int64
	dlRate float64
	wrRate float64
}

func newProgress(st *stats, out io.Writer, tty bool) *progress {
	return &progress{st: st, out: out, tty: tty, stop: make(chan struct{}), prevAt: time.Now()}
}

func (p *progress) run() {
	p.done.Add(1)
	go func() {
		defer p.done.Done()
		every := time.Second
		if !p.tty {
			every = 10 * time.Second
		}
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
				p.print()
			}
		}
	}()
}

// logf prints a message without garbling the status line.
func (p *progress) logf(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tty && p.last != "" {
		fmt.Fprint(p.out, "\r\033[K")
	}
	fmt.Fprintf(p.out, format+"\n", args...)
	if p.tty && p.last != "" {
		fmt.Fprint(p.out, p.last)
	}
}

func (p *progress) finish() {
	close(p.stop)
	p.done.Wait()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tty && p.last != "" {
		fmt.Fprint(p.out, "\r\033[K")
	}
	p.last = ""
}

func (p *progress) print() {
	p.mu.Lock()
	defer p.mu.Unlock()
	line := p.line()
	if p.tty {
		fmt.Fprint(p.out, "\r\033[K"+line)
		p.last = line
	} else {
		fmt.Fprintln(p.out, line)
	}
}

func (p *progress) line() string {
	st := p.st
	now := time.Now()
	dt := now.Sub(p.prevAt).Seconds()
	dl := st.bytesDownloaded.Load()
	wr := st.pq.BytesWritten.Load() + st.cacheBytes.Load()
	if dt > 0 {
		// Smooth over a few seconds so the rates do not flicker.
		const a = 0.3
		p.dlRate = a*float64(dl-p.prevDL)/dt + (1-a)*p.dlRate
		p.wrRate = a*float64(wr-p.prevWr)/dt + (1-a)*p.wrRate
	}
	p.prevAt, p.prevDL, p.prevWr = now, dl, wr

	done := st.chunksWritten.Load()
	got := st.chunksDownloaded.Load()
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] chunks %d/%d (%.1f%%)", fmtDuration(now.Sub(st.start)), done, st.chunksTotal, pct(done, st.chunksTotal))
	fmt.Fprintf(&b, " | fetched %d", got)
	if ahead := got - done; ahead > 0 {
		fmt.Fprintf(&b, " (+%d ahead)", ahead)
	}
	fmt.Fprintf(&b, ", %s/s, %s", formatBytes(p.dlRate), formatBytes(float64(dl)))
	fmt.Fprintf(&b, " | parquet %d files, %s | disk %s/s", st.pq.FilesWritten.Load(),
		formatBytes(float64(st.pq.BytesWritten.Load())), formatBytes(p.wrRate))
	fmt.Fprintf(&b, " | %s blocks, %s txs", count(st.blocks.Load()), count(st.txs.Load()))
	if e := st.decodeErrors.Load(); e > 0 {
		fmt.Fprintf(&b, ", %d undecodable", e)
	}
	if done > 0 && done < st.chunksTotal {
		eta := time.Duration(float64(now.Sub(st.start)) / float64(done) * float64(st.chunksTotal-done))
		fmt.Fprintf(&b, " | ETA %s", fmtDuration(eta))
	}
	return b.String()
}

func pct(a, b int64) float64 {
	if b == 0 {
		return 100
	}
	return 100 * float64(a) / float64(b)
}

func count(n int64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.2fG", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.2fM", float64(n)/1e6)
	case n >= 1e4:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	}
	return fmt.Sprint(n)
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h, m, s := int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
