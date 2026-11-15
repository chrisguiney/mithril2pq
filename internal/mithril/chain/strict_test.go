// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const preprodStandard = "../testdata/certs/preprod/65c0cabd8c662dae0efe18550de72411a8c3f121c3c40ed24f9ba0bc91c1c685.json"

// TestCertificateMessageStrictness checks that a certificate message decodes
// as serde decodes mithril-common's CertificateMessage, not as
// encoding/json would: keys match exactly (a key differing only in case is
// an unknown key, ignored), a repeated field is an error, fields are
// required and non-null unless Mithril makes them optional, and the hash
// scheme, message part keys and timestamps are checked when the message is
// read, not only when it is hashed.
func TestCertificateMessageStrictness(t *testing.T) {
	b, err := os.ReadFile(preprodStandard)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	once := func(old, new string) string {
		if !strings.Contains(doc, old) {
			t.Fatalf("%q not in the certificate", old)
		}
		return strings.Replace(doc, old, new, 1)
	}
	for _, tc := range []struct {
		name  string
		input string
		ok    bool
	}{
		{"as served", doc, true},
		{"key case", once(`"hash"`, `"Hash"`), false},
		{"case variant beside the key is ignored", once(`"hash"`, `"HASH":"x","hash"`), true},
		{"repeated field", once(`"network"`, `"network":"x","network"`), false},
		{"repeated unknown key", once(`"network"`, `"x":1,"x":2,"network"`), true},
		{"missing field", once(`"previous_hash"`, `"previous_hashx"`), false},
		{"null string", once(`"signed_message":"`, `"signed_message":null,"x":"`), false},
		{"null signers", once(`"signers":[`, `"signers":null,"x":[`), false},
		{"null optional", once(`"signed_message"`, `"ancillary_prover_data":null,"signed_message"`), true},
		{"empty hash scheme", once(`"message_parts"`, `"hash_scheme":"","message_parts"`), false},
		{"null hash scheme", once(`"message_parts"`, `"hash_scheme":null,"message_parts"`), false},
		{"legacy hash scheme", once(`"message_parts"`, `"hash_scheme":"legacy","message_parts"`), true},
		{"rigid hash scheme", once(`"message_parts"`, `"hash_scheme":"rigid","message_parts"`), false},
		{"unknown message part", once(`"current_epoch"`, `"snapshot_digestx":"00","current_epoch"`), false},
		{"timestamp", once(`"2025-02-25T00:03:10.398068115Z"`, `"2025-02-30T00:03:10Z"`), false},
	} {
		var c Certificate
		err := json.Unmarshal([]byte(tc.input), &c)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok = %v", tc.name, err, tc.ok)
		}
	}
}

// TestSignedEntityTypeShapes checks the signed entity types serde reads as
// known types (others make a standard certificate unusable).
func TestSignedEntityTypeShapes(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		feed string // hex, or "" for an error
	}{
		{`{"MithrilStakeDistribution":200}`, "00000000000000c8"},
		{`{"MithrilStakeDistribution":[200]}`, ""},
		{`{"MithrilStakeDistribution":200,"CardanoStakeDistribution":1}`, ""},
		{`{"MithrilStakeDistribution":200,"MithrilStakeDistribution":200}`, ""},
		{`{"CardanoDatabase":{"epoch":1,"immutable_file_number":2}}`, "00000000000000010000000000000002"},
		{`{"CardanoDatabase":[1,2]}`, "00000000000000010000000000000002"},
		{`{"CardanoDatabase":{"epoch":1,"Epoch":9,"immutable_file_number":2}}`, "00000000000000010000000000000002"},
		{`{"CardanoDatabase":{"epoch":1,"epoch":1,"immutable_file_number":2}}`, ""},
		{`{"CardanoTransactions":[1,2,3]}`, ""},
		{`{"CardanoTransactions":[1]}`, ""},
		{`{"CardanoBlocksTransactions":[1,2,3]}`, "0005000000000000000100000000000000020000000000000003"},
		{`{"CardanoBlocksTransactions":[1,2]}`, ""},
		{`"MithrilStakeDistribution"`, ""},
	} {
		got, err := signedEntityFeed(json.RawMessage(tc.raw))
		if tc.feed == "" {
			if err == nil {
				t.Errorf("%s: accepted", tc.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.raw, err)
		} else if h := hex.EncodeToString(got); h != tc.feed {
			t.Errorf("%s: feed %s, want %s", tc.raw, h, tc.feed)
		}
	}
}
