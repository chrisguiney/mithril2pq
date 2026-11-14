package extract

import (
	"bytes"
	"testing"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger/byron"

	"github.com/chrisguiney/mithril2pq/internal/schema"
)

// byronWitness encodes a Byron TxInWitness: [ctor, #6.24(bytes .cbor [key, sig])].
func byronWitness(t *testing.T, ctor uint64, key, sig []byte) cbor.Value {
	t.Helper()
	fields, err := cbor.Encode([]any{key, sig})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cbor.Encode([]any{ctor, cbor.WrappedCbor(fields)})
	if err != nil {
		t.Fatal(err)
	}
	var v cbor.Value
	if _, err := cbor.Decode(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestByronWitnessKeys(t *testing.T) {
	xpub := bytes.Repeat([]byte{1}, 32)
	xpub = append(xpub, bytes.Repeat([]byte{2}, 32)...)
	redeem := bytes.Repeat([]byte{3}, 32)
	sig := bytes.Repeat([]byte{4}, 64)
	ws := byron.NewByronTransactionWitnessSet([]cbor.Value{
		byronWitness(t, 0, xpub, sig),   // VKWitness: extended key
		byronWitness(t, 2, redeem, sig), // RedeemWitness: plain Ed25519 key
	})
	if n := len(ws.Vkey()); n != 2 {
		t.Fatalf("gouroboros decoded %d witnesses, want 2", n)
	}

	b := &builder{rows: NewRows()}
	witnesses(b, make([]byte, 32), ws)
	if b.err != nil {
		t.Fatal(b.err)
	}
	rows := b.rows[schema.VkeyWitness.ID]
	if len(rows) != 2 {
		t.Fatalf("%d vkey_witness rows", len(rows))
	}
	if !bytes.Equal(rows[0][2].([]byte), xpub[:32]) || !bytes.Equal(rows[0][3].([]byte), xpub[32:]) {
		t.Errorf("extended key row: vkey %x chain_code %x", rows[0][2], rows[0][3])
	}
	if !bytes.Equal(rows[1][2].([]byte), redeem) || rows[1][3] != nil {
		t.Errorf("redeem key row: vkey %x chain_code %v", rows[1][2], rows[1][3])
	}
}
