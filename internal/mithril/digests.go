package mithril

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/blake2s"
)

// Digest is one entry of a snapshot's digest list.
type Digest struct {
	ImmutableFileName string `json:"immutable_file_name"`
	Digest            string `json:"digest"`
}

// MerkleRoot computes the root Mithril certifies over a digest list.
//
// mithril-common's MKTree is a Merkle mountain range (the ckb crate) whose
// leaves are the hex digest strings' ASCII bytes and whose merge is
// Blake2s-256(left || right). Leaves are pushed in list order; peaks are
// bagged right to left, each step hashing (right peak || left peak).
func MerkleRoot(digests []Digest) ([]byte, error) {
	if len(digests) == 0 {
		return nil, errors.New("empty digest list")
	}
	merge := func(a, b []byte) []byte {
		h, _ := blake2s.New256(nil)
		h.Write(a)
		h.Write(b)
		return h.Sum(nil)
	}
	type peak struct {
		height int
		hash   []byte
	}
	var peaks []peak
	for _, d := range digests {
		p := peak{0, []byte(d.Digest)}
		for len(peaks) > 0 && peaks[len(peaks)-1].height == p.height {
			left := peaks[len(peaks)-1]
			peaks = peaks[:len(peaks)-1]
			p = peak{p.height + 1, merge(left.hash, p.hash)}
		}
		peaks = append(peaks, p)
	}
	for len(peaks) > 1 {
		right := peaks[len(peaks)-1]
		left := peaks[len(peaks)-2]
		peaks = append(peaks[:len(peaks)-2], peak{0, merge(right.hash, left.hash)})
	}
	return peaks[0].hash, nil
}

// Digests downloads the snapshot's digest list, trying each listed location.
func (c *Client) Digests(ctx context.Context, a Artifact) ([]Digest, error) {
	var errs []error
	for _, l := range a.Digests.Locations {
		var uri string
		if err := json.Unmarshal(l.URI, &uri); err != nil || uri == "" {
			continue
		}
		var list []Digest
		err := retry(ctx, 4, func() error {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			defer cancel()
			body, err := c.get(ctx, uri)
			if err != nil {
				return err
			}
			defer body.Close()
			list, err = decodeDigests(body, l.Compression)
			if err != nil {
				return fmt.Errorf("%s: %w", uri, err)
			}
			return nil
		})
		if err == nil {
			return list, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("snapshot %s lists no digest location", a.Hash)
	}
	return nil, fmt.Errorf("could not download the digest list: %w", errors.Join(errs...))
}

func decodeDigests(r io.Reader, compression string) ([]Digest, error) {
	var list []Digest
	switch compression {
	case "":
		if err := json.NewDecoder(r).Decode(&list); err != nil {
			return nil, err
		}
		return list, nil
	case "zstandard":
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		tr := tar.NewReader(zr)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				return nil, errors.New("archive holds no .digests.json file")
			}
			if err != nil {
				return nil, err
			}
			if strings.HasSuffix(h.Name, ".json") {
				if err := json.NewDecoder(tr).Decode(&list); err != nil {
					return nil, err
				}
				return list, nil
			}
		}
	default:
		return nil, fmt.Errorf("unsupported compression %q", compression)
	}
}
