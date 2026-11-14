package extract

import (
	"reflect"

	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"

	"github.com/chrisguiney/mithril2pq/internal/schema"
)

// header reads the VRF, operational-certificate and protocol-version fields
// by name from the concrete era header, because the BlockHeader interface
// stops at hash, slot and size, and Shelley..Alonzo and Babbage+ name these
// fields differently. Byron headers have none of them.
func header(b *builder, blockHash []byte, h ledger.BlockHeader) {
	prev, body := h.PrevHash(), h.BlockBodyHash()
	iv := h.IssuerVkey()
	row := schema.Row{
		blockHash, nonZero(prev[:]), nonZero(iv[:]), nil, h.BlockBodySize(), nonZero(body[:]),
		nil, nil, nil, nil, nil, nil, nil,
	}
	rv := reflect.Indirect(reflect.ValueOf(h))
	if rv.Kind() == reflect.Struct {
		// Only a Shelley+ KES signature; other eras' header structs either
		// have no such field or use it for something else.
		if sig := rv.FieldByName("Signature"); sig.IsValid() && sig.Kind() == reflect.Slice && sig.Len() == 448 {
			row[8] = sig.Bytes()
		}
		if bv := rv.FieldByName("Body"); bv.IsValid() && bv.Kind() == reflect.Struct {
			headerBody(b, blockHash, bv, row)
		}
	}
	b.add(schema.BlockHeader, row...)
}

func headerBody(b *builder, blockHash []byte, body reflect.Value, row schema.Row) {
	field := func(name string) (reflect.Value, bool) {
		f := body.FieldByName(name)
		return f, f.IsValid()
	}
	if f, ok := field("VrfKey"); ok && f.Kind() == reflect.Slice {
		row[3] = f.Bytes()
	}
	for _, v := range []struct{ field, kind string }{
		{"VrfResult", "vrf_result"}, {"NonceVrf", "nonce"}, {"LeaderVrf", "leader"},
	} {
		if f, ok := field(v.field); ok {
			if r, ok := f.Interface().(lcommon.VrfResult); ok {
				b.add(schema.BlockHeaderVrf, blockHash, v.kind, r.Output, r.Proof)
			}
		}
	}
	if f, ok := field("OpCert"); ok { // Babbage+
		row[9] = f.FieldByName("HotVkey").Bytes()
		row[10] = f.FieldByName("SequenceNumber").Uint()
		row[11] = f.FieldByName("KesPeriod").Uint()
		row[12] = f.FieldByName("Signature").Bytes()
	} else if f, ok := field("OpCertHotVkey"); ok { // Shelley..Alonzo
		row[9] = f.Bytes()
		row[10] = body.FieldByName("OpCertSequenceNumber").Uint()
		row[11] = body.FieldByName("OpCertKesPeriod").Uint()
		row[12] = body.FieldByName("OpCertSignature").Bytes()
	}
	if f, ok := field("ProtoVersion"); ok {
		row[6], row[7] = f.FieldByName("Major").Uint(), f.FieldByName("Minor").Uint()
	} else if f, ok := field("ProtoMajorVersion"); ok {
		row[6], row[7] = f.Uint(), body.FieldByName("ProtoMinorVersion").Uint()
	}
}
