package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// sizeUnits: KB/MB/GB/TB (and K/M/G/T) are decimal; KiB/MiB/GiB/TiB are
// binary. Matching is case-insensitive.
var sizeUnits = []struct {
	suffix string
	mult   float64
}{
	{"kib", 1 << 10}, {"mib", 1 << 20}, {"gib", 1 << 30}, {"tib", 1 << 40},
	{"kb", 1e3}, {"mb", 1e6}, {"gb", 1e9}, {"tb", 1e12},
	{"k", 1e3}, {"m", 1e6}, {"g", 1e9}, {"t", 1e12},
	{"b", 1},
}

// parseSize parses a human-readable size such as "128MB", "3GB", "1.5GiB"
// or a plain byte count.
func parseSize(s string) (int64, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	mult := 1.0
	for _, u := range sizeUnits {
		if strings.HasSuffix(t, u.suffix) {
			t, mult = strings.TrimSpace(strings.TrimSuffix(t, u.suffix)), u.mult
			break
		}
	}
	v, err := strconv.ParseFloat(t, 64)
	if err != nil || v < 0 || math.IsInf(v, 0) || math.IsNaN(v) {
		return 0, fmt.Errorf("%q is not a size; use a number with an optional unit, like 128MB, 3GB or 512MiB", s)
	}
	n := v * mult
	if n > math.MaxInt64 {
		return 0, fmt.Errorf("%q is too large", s)
	}
	return int64(n), nil
}

// sizeFlag is a flag.Value holding a byte count.
type sizeFlag struct{ n int64 }

func (f *sizeFlag) String() string { return formatBytes(float64(f.n)) }
func (f *sizeFlag) Set(s string) error {
	n, err := parseSize(s)
	if err != nil {
		return err
	}
	f.n = n
	return nil
}

func formatBytes(b float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	i := 0
	for b >= 1000 && i < len(units)-1 {
		b /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f B", b)
	}
	return fmt.Sprintf("%.2f %s", b, units[i])
}
