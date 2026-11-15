package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chrisguiney/mithril2pq/internal/mithril"
	"github.com/chrisguiney/mithril2pq/internal/mithril/chain"
)

// verifiedCertsName is the file in the output directory that remembers
// certificates already verified back to genesis, so later runs can stop
// their chain walk there.
const verifiedCertsName = "_mithril2pq_verified_certificates.json"

// verifiedCerts maps a genesis key (hex) to the hashes of certificates a
// walk under that key verified. A hash is recorded only after a walk that
// reached a genesis certificate, or a certificate an earlier such walk
// recorded, so every recorded hash chains to genesis under its key.
type verifiedCerts struct {
	FormatVersion int                 `json:"format_version"`
	ByGenesisKey  map[string][]string `json:"by_genesis_key"`
}

// loadVerifiedCerts reads the record; a missing or unreadable file only
// costs a full walk, so it is not an error.
func loadVerifiedCerts(dir string) (*verifiedCerts, bool) {
	v := &verifiedCerts{FormatVersion: 1, ByGenesisKey: map[string][]string{}}
	b, err := os.ReadFile(filepath.Join(dir, verifiedCertsName))
	if err != nil {
		return v, !errors.Is(err, os.ErrNotExist)
	}
	var got verifiedCerts
	if json.Unmarshal(b, &got) != nil || got.FormatVersion != 1 || got.ByGenesisKey == nil {
		return v, true
	}
	return &got, false
}

func (v *verifiedCerts) trusted(key chain.GenesisKey) func(string) bool {
	set := map[string]bool{}
	for _, h := range v.ByGenesisKey[key.String()] {
		set[h] = true
	}
	return func(h string) bool { return set[h] }
}

func (v *verifiedCerts) add(key chain.GenesisKey, hashes []string) {
	k := key.String()
	seen := map[string]bool{}
	for _, h := range v.ByGenesisKey[k] {
		seen[h] = true
	}
	for _, h := range hashes {
		if !seen[h] {
			seen[h] = true
			v.ByGenesisKey[k] = append(v.ByGenesisKey[k], h)
		}
	}
}

// save replaces the file atomically. The temporary name uses the dataset's
// prefix, so a crash leaves nothing the next run does not clean up.
func (v *verifiedCerts) save(dir string) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".tmp-"+verifiedCertsName)
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, verifiedCertsName))
}

// verifyChain verifies the certificate's chain back to genesis under the
// configured genesis key, stopping early at a certificate an earlier run
// verified, and records what it verified.
func (r *runner) verifyChain(ctx context.Context, cert *mithril.Certificate) error {
	record, damaged := loadVerifiedCerts(r.cfg.out)
	if damaged {
		r.prog.logf("ignoring unreadable %s; verifying the whole certificate chain", verifiedCertsName)
	}
	fetch := func(ctx context.Context, hash string) (*chain.Certificate, error) {
		return r.client.Certificate(ctx, hash)
	}
	res, err := chain.Verify(ctx, cert, r.cfg.genesisKey, fetch, chain.Options{
		Trusted: record.trusted(r.cfg.genesisKey),
		Progress: func(n int, c *chain.Certificate) {
			if n%25 == 0 {
				r.prog.logf("verifying certificate chain: %d certificates checked, at epoch %d", n, c.Epoch)
			}
		},
	})
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}
	if res.Genesis != nil {
		r.prog.logf("verified certificate chain: %d certificates back to genesis (epoch %d)", len(res.Verified), res.Genesis.Epoch)
	} else {
		r.prog.logf("verified certificate chain: %d certificates back to certificate %s (epoch %d), verified to genesis by an earlier run",
			len(res.Verified), res.StoppedAt.Hash, res.StoppedAt.Epoch)
	}
	record.add(r.cfg.genesisKey, res.Verified)
	if err := record.save(r.cfg.out); err != nil {
		r.prog.logf("could not record verified certificates (%v); the next run will verify the whole chain again", err)
	}
	return nil
}
