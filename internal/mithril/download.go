package mithril

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ErrChecksum marks a download whose bytes do not match the MD5 the storage
// server advertised.
var ErrChecksum = errors.New("download checksum mismatch")

// Download fetches url into w, retrying from scratch on failure (reset is
// called before each retry so w can be truncated). If the server sends a
// Google Cloud Storage x-goog-hash MD5, the bytes are checked against it.
// count is called with each chunk of bytes received, for throughput
// reporting.
func (c *Client) Download(ctx context.Context, urls []string, w io.Writer, reset func() error, count func(int)) (int64, error) {
	var n int64
	var lastErr error
	attempt := 0
	err := retry(ctx, 5, func() error {
		u := urls[attempt%len(urls)]
		attempt++
		if attempt > 1 {
			if err := reset(); err != nil {
				return err
			}
		}
		var err error
		n, err = c.downloadOnce(ctx, u, w, count)
		lastErr = err
		return err
	})
	if err != nil && lastErr != nil && !errors.Is(err, context.Canceled) {
		return 0, lastErr
	}
	return n, err
}

func (c *Client) downloadOnce(ctx context.Context, u string, w io.Writer, count func(int)) (int64, error) {
	// A generous per-attempt deadline; a stalled connection is caught by the
	// idle watchdog below.
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	resp, err := c.do(ctx, u)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	wantMD5 := gcsMD5(resp.Header.Values("X-Goog-Hash"))
	h := md5.New()
	var n int64
	buf := make([]byte, 256<<10)
	idle := time.AfterFunc(2*time.Minute, cancel)
	defer idle.Stop()
	for {
		k, rerr := resp.Body.Read(buf)
		if k > 0 {
			idle.Reset(2 * time.Minute)
			if _, err := w.Write(buf[:k]); err != nil {
				return n, err
			}
			h.Write(buf[:k])
			n += int64(k)
			if count != nil {
				count(k)
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			if parent.Err() != nil {
				return n, parent.Err()
			}
			if errors.Is(ctx.Err(), context.Canceled) {
				return n, fmt.Errorf("GET %s: no data received for 2 minutes", u)
			}
			return n, fmt.Errorf("GET %s: %w", u, rerr)
		}
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return n, fmt.Errorf("GET %s: received %d of %d bytes", u, n, resp.ContentLength)
	}
	if wantMD5 != "" {
		if got := base64.StdEncoding.EncodeToString(h.Sum(nil)); got != wantMD5 {
			return n, fmt.Errorf("%w: GET %s: MD5 %s, server says %s", ErrChecksum, u, got, wantMD5)
		}
	}
	return n, nil
}

func gcsMD5(values []string) string {
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if s, ok := strings.CutPrefix(part, "md5="); ok {
				return s
			}
		}
	}
	return ""
}
