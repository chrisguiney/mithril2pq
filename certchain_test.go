package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chrisguiney/mithril2pq/internal/mithril/chain"
)

func TestVerifiedCertsRecord(t *testing.T) {
	dir := t.TempDir()
	mainnet, _ := chain.NetworkGenesisKey("mainnet")
	preprod, _ := chain.NetworkGenesisKey("preprod")

	v, damaged := loadVerifiedCerts(dir)
	if damaged || v.trusted(mainnet)("a") {
		t.Fatal("empty record trusts something")
	}
	v.add(mainnet, []string{"a", "b"})
	v.add(mainnet, []string{"b", "c"})
	if err := v.save(dir); err != nil {
		t.Fatal(err)
	}
	v, damaged = loadVerifiedCerts(dir)
	if damaged {
		t.Fatal("saved record reads as damaged")
	}
	if got := v.ByGenesisKey[mainnet.String()]; len(got) != 3 {
		t.Fatalf("hashes %v", got)
	}
	if !v.trusted(mainnet)("c") || v.trusted(preprod)("c") {
		t.Fatal("trust is not scoped to the genesis key")
	}
	if err := os.WriteFile(filepath.Join(dir, verifiedCertsName), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v, damaged = loadVerifiedCerts(dir); !damaged || v.trusted(mainnet)("a") {
		t.Fatal("damaged record trusted")
	}
}
