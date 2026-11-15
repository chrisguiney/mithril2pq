// SPDX-License-Identifier: Apache-2.0

package stm

import (
	"encoding/json"
	"strings"
	"testing"
)

// serde_json's derived impls for these types match keys exactly, reject a
// repeated field and require every field; they ignore unknown keys, even
// repeated ones. The
// decoders must do the same, rather than encoding/json's case folding,
// last-wins duplicates and zero defaults.
func TestCodecStrictness(t *testing.T) {
	c := committedCert(t, preprod3Signers)
	avk := string(c.avkJSON(t))
	proof := string(c.proofJSON(t))
	once := func(s, old, new string) string {
		if !strings.Contains(s, old) {
			t.Fatalf("%q not in input", old)
		}
		return strings.Replace(s, old, new, 1)
	}
	for _, tc := range []struct {
		name  string
		avk   bool
		input string
		ok    bool
	}{
		{"avk as served", true, avk, true},
		{"avk key case", true, once(avk, `"total_stake"`, `"Total_Stake"`), false},
		{"avk duplicate key", true, once(avk, `"total_stake":`, `"total_stake":1,"total_stake":`), false},
		{"avk missing field", true, once(avk, `,"hasher":null`, ``), false},
		{"avk missing total_stake", true, avk[:strings.Index(avk, `,"total_stake"`)] + "}", false},
		{"avk unknown key ignored", true, once(avk, `{"mt_commitment"`, `{"extra":[1,{"a":2}],"mt_commitment"`), true},
		{"avk repeated unknown key ignored", true, once(avk, `{"mt_commitment"`, `{"x":1,"x":2,"Hasher":0,"Hasher":0,"mt_commitment"`), true},
		{"proof as served", false, proof, true},
		{"proof key case", false, once(proof, `"sigma"`, `"Sigma"`), false},
		{"proof duplicate key", false, once(proof, `"signer_index":`, `"signer_index":0,"signer_index":`), false},
		{"proof missing signer_index", false, once(proof, `,"signer_index":`, `,"x":`), false},
		{"proof missing indexes", false, once(proof, `"indexes":`, `"indexez":`), false},
		{"proof null indexes", false, once(proof, `"indexes":[`, `"indexes":null,"y":[`), false},
		{"proof duplicate batch key", false, once(proof, `"indices":`, `"indices":[],"indices":`), false},
		{"proof unknown key ignored", false, once(proof, `"batch_proof":{`, `"batch_proof":{"z":null,`), true},
		{"proof repeated unknown key ignored", false, once(proof, `"signer_index":`, `"Hasher":1,"Hasher":1,"signer_index":`), true},
		{"proof trailing data", false, proof + "{}", false},
	} {
		var err error
		if tc.avk {
			err = json.Unmarshal([]byte(tc.input), new(AggregateVerificationKey))
		} else {
			err = json.Unmarshal([]byte(tc.input), new(ConcatenationProof))
		}
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok = %v", tc.name, err, tc.ok)
		}
	}
}
