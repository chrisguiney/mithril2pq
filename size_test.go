package main

import "testing"

func TestParseSize(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int64
	}{
		{"128MB", 128_000_000},
		{"128mb", 128_000_000},
		{"3GB", 3_000_000_000},
		{"300 MB", 300_000_000},
		{"512MiB", 512 << 20},
		{"1.5GiB", 3 << 29},
		{"2k", 2000},
		{"1048576", 1 << 20},
	} {
		got, err := parseSize(c.in)
		if err != nil || got != c.want {
			t.Errorf("%q: %d, %v; want %d", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "MB", "-1GB", "lots", "1e400"} {
		if _, err := parseSize(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
