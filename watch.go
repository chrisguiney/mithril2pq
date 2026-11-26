package main

import (
	"errors"
	"time"
)

// maxBackoff bounds the wait after consecutive failed iterations, so a long
// outage is retried every ten minutes rather than ever less often. An
// interval already above it is kept.
const maxBackoff = 10 * time.Minute

// errConfig marks failures that rerunning cannot fix: the output directory
// and the source disagree about the network, the schema or the chain.
var errConfig = errors.New("configuration error")

// configError marks err as a failure -watch must not retry.
func configError(err error) error {
	return &configErr{err}
}

type configErr struct{ err error }

func (e *configErr) Error() string        { return e.err.Error() }
func (e *configErr) Unwrap() error        { return e.err }
func (e *configErr) Is(target error) bool { return target == errConfig }

// backoff is the wait before the next iteration after fails consecutive
// failures: the interval doubled per failure, capped at maxBackoff.
func backoff(interval time.Duration, fails int) time.Duration {
	if fails <= 0 {
		return interval
	}
	d := interval
	for i := 0; i < fails && d < maxBackoff; i++ {
		d *= 2
	}
	return max(min(d, maxBackoff), interval)
}

// watch runs once immediately and then again every interval until stop is
// closed, which ends it with nil: a stop during once is that iteration's
// errStopped, after its progress was committed. A failed iteration is logged
// and retried after a backoff; a configError ends the watch with that error.
// It starts no goroutines.
func watch(stop <-chan struct{}, interval time.Duration, once func() error, logf func(string, ...any)) error {
	fails := 0
	for {
		err := once()
		switch {
		case err == nil:
			fails = 0
		case errors.Is(err, errStopped):
			return nil
		case errors.Is(err, errConfig):
			return err
		default:
			fails++
			logf("watch: iteration failed (%d in a row), retrying in %s: %v", fails, backoff(interval, fails), err)
		}
		timer := time.NewTimer(backoff(interval, fails))
		select {
		case <-stop:
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
