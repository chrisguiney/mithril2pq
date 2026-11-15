// SPDX-License-Identifier: Apache-2.0

package chain

import "testing"

// TestChronoTimestamps pins timestamp parsing to chrono's relaxed RFC 3339
// reader, which Mithril hashes certificates with, on the spellings where
// Go's time.Parse disagrees with it.
func TestChronoTimestamps(t *testing.T) {
	base, err := unixNanos("2025-02-20T00:03:21Z")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		in   string
		want int64 // nanoseconds after base, or -1 for an error
	}{
		{"2025-02-20 00:03:21Z", 0},
		{"2025-02-20t00:03:21z", 0},
		{" 2025-2-20T00 :03:21 UTC ", 0},
		{"2025-02-20T01:03:21+0100", 0},
		{"2025-02-20T01:03:21−01:00", 2 * 3600e9},
		{"2025-02-20T00:03:21.1234567899Z", 123456789},
		{"2025-02-20T00:03:60.5Z", 39500000000}, // leap second: 00:04:00.5
		{"2025-02-20T00:03:21,5Z", -1},
		{"2025-02-20T00:03:21+24:00", -1},
		{"2025-02-20T00:03:21+00:60", -1},
		{"2025-02-20T00:03:21+01", -1},
		{"2025-02-20T00:03:21.Z", -1},
		{"2025-02-29T00:03:21Z", -1},
		{"02025-02-20T00:03:21Z", -1},
	} {
		got, err := unixNanos(tc.in)
		switch {
		case tc.want < 0 && err == nil:
			t.Errorf("%q: accepted", tc.in)
		case tc.want >= 0 && err != nil:
			t.Errorf("%q: %v", tc.in, err)
		case tc.want >= 0 && got-base != tc.want:
			t.Errorf("%q: %d ns after the base, want %d", tc.in, got-base, tc.want)
		}
	}
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"+12345-01-01T00:00:00Z", 0}, // valid, beyond an i64 of nanoseconds
		{"1677-09-21T00:12:43.145224192Z", -9223372036854775808},
		{"1677-09-21T00:12:43.145224191Z", 0},
		{"-0001-01-01T00:00:00Z", 0},
	} {
		if got, err := unixNanos(tc.in); err != nil || got != tc.want {
			t.Errorf("%q: %d, %v; want %d", tc.in, got, err, tc.want)
		}
	}
}
