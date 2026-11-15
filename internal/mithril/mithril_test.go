package mithril

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/chrisguiney/mithril2pq/internal/mithril/chain"
)

func TestProtocolMessageHashMatchesCertificate(t *testing.T) {
	// A real Preview certificate: its signed message is the legacy hash of
	// its protocol message parts.
	b, err := os.ReadFile("testdata/preview-certificate.json")
	if err != nil {
		t.Fatal(err)
	}
	// The fixture keeps only the fields this test needs, so it is not a
	// complete certificate message.
	var cert struct {
		SignedMessage   string                `json:"signed_message"`
		ProtocolMessage chain.ProtocolMessage `json:"protocol_message"`
	}
	if err := json.Unmarshal(b, &cert); err != nil {
		t.Fatal(err)
	}
	got, err := ProtocolMessageHash(cert.ProtocolMessage.MessageParts)
	if err != nil {
		t.Fatal(err)
	}
	if got != cert.SignedMessage {
		t.Fatalf("hash %s, certificate signed %s", got, cert.SignedMessage)
	}

	cert.ProtocolMessage.MessageParts["cardano_database_merkle_root"] = "00"
	if got, _ := ProtocolMessageHash(cert.ProtocolMessage.MessageParts); got == cert.SignedMessage {
		t.Fatal("changing the Merkle root did not change the hash")
	}
}

func TestProtocolMessageHashRejectsUnknownPart(t *testing.T) {
	if _, err := ProtocolMessageHash(map[string]string{"something_new": "1"}); err == nil {
		t.Fatal("unknown part accepted")
	}
}

func TestMerkleRoot(t *testing.T) {
	// Vectors from an independent implementation of the ckb MMR with
	// Blake2s-256 merges and right-to-left peak bagging, over leaves
	// hex(sha256([i])). The same code reproduced a real Preview snapshot's
	// certified root from its 88,860-entry digest list.
	want := []string{
		"", // one leaf: the root is the leaf itself, checked below
		"db028933d4db663675a1b6a6ea2744844a3dbc0f0c6432cfedb4d833893d0b9d",
		"c9a191d55554679634ca170967ecb4a291bbc372b1f9be4dd23050a2bde45999",
		"ef8a762a82eed24d60546017f0fc40bec48763222cb4b0e64a5f7d8d8397be9f",
		"a0e07b5fde6a602a78900ab5eb09f9bdb26ab38d2622689bc0f041599c8dba1f",
		"86126152c99f27f48cdffc1a538dc9f69e25e1cce9866b262798878f720b9083",
		"3e77b8a921569f9a385f038b3e1226ac68448d067fe9f29c2e18283c2609516b",
	}
	var leaves []Digest
	for i := range want {
		sum := sha256.Sum256([]byte{byte(i)})
		leaves = append(leaves, Digest{Digest: hex.EncodeToString(sum[:])})
		root, err := MerkleRoot(leaves)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if string(root) != leaves[0].Digest {
				t.Fatalf("1 leaf: root %q", root)
			}
			continue
		}
		if got := hex.EncodeToString(root); got != want[i] {
			t.Errorf("%d leaves: root %s, want %s", i+1, got, want[i])
		}
	}
	if _, err := MerkleRoot(nil); err == nil {
		t.Error("empty list accepted")
	}
}

func TestResolveAggregator(t *testing.T) {
	for _, c := range []struct {
		in, net string
		ok      bool
	}{
		{"mainnet", "mainnet", true},
		{"Preview", "preview", true},
		{"https://example.org/aggregator/", "", true},
		{"ftp://example.org", "", false},
		{"previewnet", "", false},
	} {
		u, net, err := ResolveAggregator(c.in)
		if (err == nil) != c.ok || net != c.net {
			t.Errorf("%q: url %q net %q err %v", c.in, u, net, err)
		}
	}
}

func TestGCSMD5(t *testing.T) {
	got := gcsMD5([]string{"crc32c=FpC+Yg==", "md5=O7M0woI7C+Cm/Wb1puDTPg=="})
	if got != "O7M0woI7C+Cm/Wb1puDTPg==" {
		t.Fatalf("got %q", got)
	}
	if gcsMD5([]string{"crc32c=FpC+Yg==, md5=abc"}) != "abc" {
		t.Fatal("comma-separated form not parsed")
	}
}
