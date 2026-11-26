package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func discard(string, ...any) {}

func TestBackoff(t *testing.T) {
	iv := time.Second
	for _, c := range []struct {
		fails int
		want  time.Duration
	}{
		{0, iv}, {1, 2 * iv}, {2, 4 * iv}, {3, 8 * iv}, {20, maxBackoff},
	} {
		if got := backoff(iv, c.fails); got != c.want {
			t.Errorf("backoff(%d) = %s, want %s", c.fails, got, c.want)
		}
	}
	if got := backoff(time.Hour, 3); got != time.Hour {
		t.Errorf("interval above the cap must not shrink: %s", got)
	}
}

func TestWatchRetriesTransientError(t *testing.T) {
	stop := make(chan struct{})
	calls := 0
	once := func() error {
		calls++
		switch {
		case calls <= 2:
			return errors.New("connection reset")
		case calls == 5:
			close(stop)
		}
		return nil
	}
	if err := watch(stop, time.Millisecond, once, discard); err != nil {
		t.Fatalf("watch = %v, want nil after stop", err)
	}
	if calls != 5 {
		t.Errorf("calls = %d, want 5", calls)
	}
}

func TestWatchConfigErrorIsFatal(t *testing.T) {
	calls := 0
	once := func() error {
		calls++
		return configError(errors.New("wrong network"))
	}
	err := watch(make(chan struct{}), time.Hour, once, discard)
	if err == nil || !errors.Is(err, errConfig) {
		t.Fatalf("watch = %v, want a config error", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestWatchStopMidWaitExitsCleanly(t *testing.T) {
	imm, out := t.TempDir(), t.TempDir()
	copyChunks(t, imm, 0, 0)
	copyChunks(t, imm, 1, 1)
	stop := make(chan struct{})
	iters := make(chan struct{}, 4)
	once := func() error {
		_, err := runLocal(t, imm, out, devnetMagic)
		iters <- struct{}{}
		return err
	}
	done := make(chan error, 1)
	go func() { done <- watch(stop, time.Hour, once, discard) }()
	<-iters
	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("watch = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watch did not return after stop")
	}
	if m := readManifest(t, out); m.LastChunk != 0 {
		t.Errorf("manifest last chunk = %d, want 0", m.LastChunk)
	}
}

func TestWatchPicksUpNewChunk(t *testing.T) {
	imm, out := t.TempDir(), t.TempDir()
	copyChunks(t, imm, 0, 0)
	copyChunks(t, imm, 1, 1)
	stop := make(chan struct{})
	iters := make(chan int, 64)
	n := 0
	once := func() error {
		_, err := runLocal(t, imm, out, devnetMagic)
		n++
		iters <- n
		return err
	}
	done := make(chan error, 1)
	go func() { done <- watch(stop, 10*time.Millisecond, once, discard) }()

	<-iters
	if m := readManifest(t, out); m.LastChunk != 0 {
		t.Fatalf("after first pass last chunk = %d, want 0", m.LastChunk)
	}
	copyChunks(t, imm, 2, 2)
	deadline := time.After(30 * time.Second)
	for {
		select {
		case <-iters:
			if m := readManifest(t, out); m.LastChunk == 1 {
				close(stop)
				if err := <-done; err != nil {
					t.Fatalf("watch = %v", err)
				}
				if n < 2 {
					t.Errorf("iterations = %d, want at least 2", n)
				}
				return
			}
		case <-deadline:
			t.Fatal("new chunk was not converted between ticks")
		}
	}
}

func TestPlanMismatchIsConfigError(t *testing.T) {
	imm, out := t.TempDir(), t.TempDir()
	copyChunks(t, imm, 0, 0)
	copyChunks(t, imm, 1, 1)
	if _, err := runLocal(t, imm, out, devnetMagic); err != nil {
		t.Fatal(err)
	}
	_, err := runLocal(t, imm, out, 1)
	if !errors.Is(err, errConfig) {
		t.Fatalf("network mismatch = %v, want a config error", err)
	}
	if !strings.Contains(err.Error(), "holds") {
		t.Errorf("message lost: %v", err)
	}
}

func TestValidateWatch(t *testing.T) {
	cfg := baseConfig()
	cfg.watch = -time.Second
	if err := validate(&cfg); err == nil || !strings.Contains(err.Error(), "-watch") {
		t.Errorf("negative -watch: %v", err)
	}
	cfg = baseConfig()
	cfg.watch = time.Second
	if err := validate(&cfg); err != nil {
		t.Errorf("-watch with archive: %v", err)
	}
	cfg = baseConfig()
	cfg.immutableDir, cfg.networkMagic, cfg.watch = "imm", 42, time.Second
	if err := validate(&cfg); err != nil {
		t.Errorf("-watch with immutable-dir: %v", err)
	}
}
