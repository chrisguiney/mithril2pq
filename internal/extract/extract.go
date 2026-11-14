// Package extract turns decoded blocks into schema rows.
//
// Decoding follows chunk2json: each block is decoded with gouroboros's
// ledger package and read through its era-independent interfaces, with
// reflection only where those interfaces stop (header VRF and operational
// certificate fields, network id, parameter updates). Rows are built from
// the ledger types directly rather than from a JSON view, so metadata
// integers, byte strings and map keys keep their types.
//
// gouroboros normalises some on-chain data and these rows inherit it:
// zero-quantity assets and mint entries are dropped, duplicate redeemer keys
// are merged, Go-map-backed collections (votes, withdrawals, MIR rewards,
// committee additions) lose wire order, and a pool registration's reward
// account is only its key hash.
package extract

import (
	"bytes"
	"fmt"
	"math/big"
	"reflect"

	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"

	"github.com/chrisguiney/mithril2pq/internal/chunk"
	"github.com/chrisguiney/mithril2pq/internal/schema"
)

// Rows holds rows per table, indexed by schema.Table.ID.
type Rows [][]schema.Row

// NewRows returns an empty row set.
func NewRows() Rows { return make(Rows, len(schema.Tables)) }

// Append moves every row of o onto r.
func (r Rows) Append(o Rows) {
	for i := range o {
		r[i] = append(r[i], o[i]...)
	}
}

// Stats counts what a chunk produced.
type Stats struct {
	Blocks, Txs, DecodeErrors int
}

// Chunk builds the rows for every block of one chunk.
func Chunk(number uint64, blocks []chunk.Block) (Rows, Stats) {
	out := NewRows()
	var st Stats
	for _, b := range blocks {
		st.Blocks++
		n, failed := blockRows(number, b, out)
		st.Txs += n
		if failed {
			st.DecodeErrors++
		}
	}
	return out, st
}

// builder accumulates one block's rows. The first error sticks, so the
// emitting code can stay linear; a block with an error contributes only its
// block row, carrying the error.
type builder struct {
	rows Rows
	err  error
}

func (b *builder) add(t *schema.Table, vals ...any) {
	if b.err != nil {
		return
	}
	row := schema.Row(vals)
	for i, v := range row {
		row[i] = normalize(v)
	}
	if err := t.Check(row); err != nil {
		b.err = err
		return
	}
	b.rows[t.ID] = append(b.rows[t.ID], row)
}

func (b *builder) fail(format string, args ...any) {
	if b.err == nil {
		b.err = fmt.Errorf(format, args...)
	}
}

func blockRows(number uint64, cb chunk.Block, out Rows) (txs int, failed bool) {
	var slot, ebbEpoch any = cb.SlotOrEpoch, nil
	if cb.IsEbb {
		slot, ebbEpoch = nil, cb.SlotOrEpoch
	}
	blockRow := schema.Row{
		cb.Hash[:], number, uint64(cb.Index), slot, ebbEpoch, uint64(cb.Type),
		cb.BlockOffset, cb.BlockSize, uint64(cb.HeaderOffset), uint64(cb.HeaderSize),
		uint64(cb.Checksum), nil, nil, nil,
	}
	const colBlockNumber, colTxCount, colDecodeError = 11, 12, 13
	emit := func(errMsg string) {
		if errMsg != "" {
			blockRow[colDecodeError] = errMsg
		}
		if err := schema.Block.Check(blockRow); err != nil {
			// Only reachable through a schema bug; keep the block visible.
			blockRow[colBlockNumber], blockRow[colTxCount] = nil, nil
			blockRow[colDecodeError] = err.Error()
		}
		out[schema.Block.ID] = append(out[schema.Block.ID], blockRow)
	}

	lb, err := ledger.NewBlockFromCbor(cb.Type, cb.Cbor, lcommon.VerifyConfig{SkipBodyHashValidation: true})
	if err != nil {
		emit(err.Error())
		return 0, true
	}
	h := lb.Hash()
	if !bytes.Equal(h[:], cb.Hash[:]) {
		emit(fmt.Sprintf("decoded header hash %x differs from the secondary index's %x", h[:], cb.Hash[:]))
		return 0, true
	}
	txList := lb.Transactions()
	blockRow[colBlockNumber] = lb.BlockNumber()
	blockRow[colTxCount] = uint64(len(txList))

	b := &builder{rows: NewRows()}
	func() {
		defer func() {
			if r := recover(); r != nil {
				b.fail("panic while reading block: %v", r)
			}
		}()
		header(b, cb.Hash[:], lb.Header())
		for i, tx := range txList {
			transaction(b, cb.Hash[:], i, tx)
		}
	}()
	if b.err != nil {
		emit(b.err.Error())
		return 0, true
	}
	emit("")
	out.Append(b.rows)
	return len(txList), false
}

// ---- value helpers ----

// normalize turns gouroboros's named byte types (PoolMetadataHash,
// Blake2b224, ...) into plain []byte, which is what the schema accepts.
func normalize(v any) any {
	switch v.(type) {
	case nil, []byte, string, bool, uint64, int64, *big.Int:
		return v
	}
	rv := reflect.ValueOf(v)
	switch {
	case rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() == reflect.Uint8:
		if rv.IsNil() {
			return nil
		}
		return rv.Bytes()
	case rv.Kind() == reflect.Array && rv.Type().Elem().Kind() == reflect.Uint8:
		b := make([]byte, rv.Len())
		reflect.Copy(reflect.ValueOf(b), rv)
		return b
	}
	return v
}

func optHash(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}

func nonZero(b []byte) any {
	for _, c := range b {
		if c != 0 {
			return b
		}
	}
	return nil
}

func zeroNil(u uint64) any {
	if u == 0 {
		return nil
	}
	return u
}

// u64 converts the integer types gouroboros uses for amounts.
func (b *builder) u64(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case uint64:
		return x
	case uint:
		return uint64(x)
	case uint32:
		return uint64(x)
	case int64:
		if x < 0 {
			b.fail("negative amount %d", x)
			return nil
		}
		return uint64(x)
	case int:
		if x < 0 {
			b.fail("negative amount %d", x)
			return nil
		}
		return uint64(x)
	case *big.Int:
		if x == nil {
			return nil
		}
		if !x.IsUint64() {
			b.fail("amount %s does not fit uint64", x)
			return nil
		}
		return x.Uint64()
	default:
		b.fail("unexpected amount type %T", v)
		return nil
	}
}

func (b *builder) i64(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case int64:
		return x
	case int:
		return int64(x)
	case uint64:
		if x > 1<<63-1 {
			b.fail("amount %d does not fit int64", x)
			return nil
		}
		return int64(x)
	case *big.Int:
		if x == nil {
			return nil
		}
		if !x.IsInt64() {
			b.fail("amount %s does not fit int64", x)
			return nil
		}
		return x.Int64()
	default:
		b.fail("unexpected amount type %T", v)
		return nil
	}
}

// bigU64Zero converts an optional amount, treating zero as absent, the way
// chunk2json omits zero donations and treasury values.
func (b *builder) bigU64Zero(v *big.Int) any {
	if v == nil || v.Sign() == 0 {
		return nil
	}
	return b.u64(v)
}

// rat splits a rational into numerator and denominator.
func (b *builder) rat(r *big.Rat) (any, any) {
	if r == nil {
		return nil, nil
	}
	return b.u64(new(big.Int).Set(r.Num())), b.u64(new(big.Int).Set(r.Denom()))
}

func credential(c lcommon.Credential) (isScript bool, hash []byte) {
	h := c.Credential
	return c.CredType == 1, h[:]
}
