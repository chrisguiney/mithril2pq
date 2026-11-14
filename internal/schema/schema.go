// Package schema defines the Parquet tables mithril2pq writes and checks
// every row against them before it reaches an Arrow builder.
//
// The layout is third normal form with no nested types: every repeated value
// is its own table with one row per element, so plain readers (pyarrow,
// fastparquet, DuckDB, Spark) see only flat columns.
package schema

import (
	"fmt"
	"math"
	"math/big"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/decimal128"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

// Version is recorded in every file and in the manifest. Bump it whenever a
// table or column changes; a dataset written with another version is not
// appended to.
const Version = 2

// Column is one flat column.
type Column struct {
	Name     string
	Type     arrow.DataType
	Nullable bool
}

// Table is one Parquet table, written to its own directory.
type Table struct {
	ID      int
	Name    string
	Columns []Column
	schema  *arrow.Schema
}

// Arrow returns the table's Arrow schema.
func (t *Table) Arrow() *arrow.Schema { return t.schema }

// Row is one row: values in column order, nil for null.
type Row []any

var (
	tHash28  = &arrow.FixedSizeBinaryType{ByteWidth: 28}
	tHash32  = &arrow.FixedSizeBinaryType{ByteWidth: 32}
	tBytes64 = &arrow.FixedSizeBinaryType{ByteWidth: 64}
	tBytes80 = &arrow.FixedSizeBinaryType{ByteWidth: 80}
	tKesSig  = &arrow.FixedSizeBinaryType{ByteWidth: 448}
	tIPv4    = &arrow.FixedSizeBinaryType{ByteWidth: 4}
	tIPv6    = &arrow.FixedSizeBinaryType{ByteWidth: 16}
	tBinary  = arrow.BinaryTypes.Binary
	tString  = arrow.BinaryTypes.String
	tBool    = arrow.FixedWidthTypes.Boolean
	tU8      = arrow.PrimitiveTypes.Uint8
	tU16     = arrow.PrimitiveTypes.Uint16
	tU32     = arrow.PrimitiveTypes.Uint32
	tU64     = arrow.PrimitiveTypes.Uint64
	tI64     = arrow.PrimitiveTypes.Int64
	// Metadata integers span -2^64..2^64-1: 20 decimal digits.
	tDec20 = &arrow.Decimal128Type{Precision: 20, Scale: 0}
)

func req(name string, t arrow.DataType) Column { return Column{name, t, false} }
func opt(name string, t arrow.DataType) Column { return Column{name, t, true} }

// Tables, in a fixed order; Table.ID indexes this slice.
var Tables []*Table

var byName = map[string]*Table{}

func def(name string, cols ...Column) *Table {
	fields := make([]arrow.Field, len(cols))
	for i, c := range cols {
		fields[i] = arrow.Field{Name: c.Name, Type: c.Type, Nullable: c.Nullable}
	}
	t := &Table{ID: len(Tables), Name: name, Columns: cols, schema: arrow.NewSchema(fields, nil)}
	Tables = append(Tables, t)
	byName[name] = t
	return t
}

// ByName returns the named table, or nil.
func ByName(name string) *Table { return byName[name] }

// rational returns the numerator/denominator column pair for name.
func rational(name string) []Column {
	return []Column{opt(name+"_numerator", tU64), opt(name+"_denominator", tU64)}
}

func cols(groups ...any) []Column {
	var out []Column
	for _, g := range groups {
		switch g := g.(type) {
		case Column:
			out = append(out, g)
		case []Column:
			out = append(out, g...)
		default:
			panic(fmt.Sprintf("schema: bad column group %T", g))
		}
	}
	return out
}

// The tables. Comments give enumeration domains; see README.md for the
// relationships between tables.
var (
	// BlockType is a static lookup of the block-type tag that wraps every
	// block in a chunk file.
	BlockType = def("block_type",
		req("block_type", tU8),
		req("era", tString),
		req("is_ebb", tBool),
	)

	Block = def("block",
		req("hash", tHash32),
		req("chunk", tU32),
		req("chunk_index", tU32),
		opt("slot", tU64),      // null for an EBB
		opt("ebb_epoch", tU64), // EBBs only
		req("block_type", tU8),
		req("block_offset", tU64),
		req("block_size", tU64),
		req("header_offset", tU16),
		req("header_size", tU16),
		req("checksum", tU32),
		opt("block_number", tU64),
		opt("tx_count", tU32),
		opt("decode_error", tString),
	)

	BlockHeader = def("block_header",
		req("block_hash", tHash32),
		opt("prev_hash", tHash32),
		opt("issuer_vkey", tHash32),
		opt("vrf_vkey", tHash32),
		req("block_body_size", tU64),
		opt("block_body_hash", tHash32),
		opt("protocol_major", tU64),
		opt("protocol_minor", tU64),
		opt("signature", tKesSig),
		opt("opcert_hot_vkey", tHash32),
		opt("opcert_sequence", tU64),
		opt("opcert_kes_period", tU64),
		opt("opcert_signature", tBytes64),
	)

	BlockHeaderVrf = def("block_header_vrf",
		req("block_hash", tHash32),
		req("kind", tString), // vrf_result nonce leader
		req("output", tBytes64),
		req("proof", tBytes80),
	)

	Tx = def("tx",
		req("hash", tHash32),
		req("block_hash", tHash32),
		req("block_index", tU32),
		req("valid", tBool),
		req("fee", tU64),
		opt("ttl", tU64),
		opt("validity_interval_start", tU64),
		opt("total_collateral", tU64),
		opt("auxiliary_data_hash", tHash32),
		opt("network_id", tU8),
		opt("script_data_hash", tHash32),
		opt("current_treasury_value", tU64),
		opt("donation", tU64),
	)

	TxInput = def("tx_input",
		req("tx_hash", tHash32),
		req("kind", tString), // spend reference collateral
		req("position", tU32),
		req("src_tx_hash", tHash32),
		req("src_index", tU32),
	)

	TxOutput = def("tx_output",
		req("tx_hash", tHash32),
		req("output_index", tU32),
		req("is_collateral_return", tBool),
		req("address", tString),
		req("lovelace", tU64),
		opt("datum_hash", tHash32),
		req("has_inline_datum", tBool),
		opt("script_ref_hash", tHash28),
	)

	TxOutputAsset = def("tx_output_asset",
		req("tx_hash", tHash32),
		req("output_index", tU32),
		req("policy_id", tHash28),
		req("asset_name", tBinary),
		req("quantity", tU64),
	)

	TxMint = def("tx_mint",
		req("tx_hash", tHash32),
		req("policy_id", tHash28),
		req("asset_name", tBinary),
		req("quantity", tI64),
	)

	TxRequiredSigner = def("tx_required_signer",
		req("tx_hash", tHash32),
		req("position", tU32),
		req("key_hash", tHash28),
	)

	TxWithdrawal = def("tx_withdrawal",
		req("tx_hash", tHash32),
		req("reward_account", tString),
		req("amount", tU64),
	)

	// Script holds scripts identified by hash (output script_ref), once each.
	Script = def("script",
		req("hash", tHash28),
		req("language", tString), // native plutus_v1 plutus_v2 plutus_v3
		opt("bytes", tBinary),
	)

	TxScript = def("tx_script",
		req("tx_hash", tHash32),
		req("source", tString), // witness auxiliary
		req("language", tString),
		req("position", tU32),
		opt("bytes", tBinary),
	)

	NativeScriptNode = def("native_script_node",
		opt("owner_script_hash", tHash28),
		opt("owner_tx_hash", tHash32),
		opt("owner_source", tString),
		opt("owner_position", tU32),
		req("node_id", tU32),
		opt("parent_id", tU32),
		opt("position", tU32),
		req("type", tString), // signature all any at_least invalid_before invalid_hereafter require_guard
		opt("key_hash", tHash28),
		opt("required", tI64),
		opt("slot", tU64),
		opt("credential_is_script", tBool),
		opt("credential_hash", tHash28),
	)

	Certificate = def("certificate",
		req("tx_hash", tHash32),
		req("cert_index", tU32),
		req("cert_type", tString),
		opt("pool_key_hash", tHash28),
		opt("drep_kind", tString), // key_hash script_hash always_abstain always_no_confidence
		opt("drep_hash", tHash28),
		opt("amount", tU64),
		opt("anchor_url", tString),
		opt("anchor_data_hash", tHash32),
		opt("retirement_epoch", tU64),
		opt("unrecognised", tString), // JSON
	)

	CertificateCredential = def("certificate_credential",
		req("tx_hash", tHash32),
		req("cert_index", tU32),
		req("role", tString), // stake drep committee_cold committee_hot
		req("is_script", tBool),
		req("hash", tHash28),
	)

	PoolRegistration = def("pool_registration",
		req("tx_hash", tHash32),
		req("cert_index", tU32),
		req("operator", tHash28),
		req("vrf_key_hash", tHash32),
		req("pledge", tU64),
		req("cost", tU64),
		req("margin_numerator", tU64),
		req("margin_denominator", tU64),
		req("reward_account_key_hash", tHash28),
		opt("metadata_url", tString),
		opt("metadata_hash", tHash32),
	)

	PoolOwner = def("pool_owner",
		req("tx_hash", tHash32),
		req("cert_index", tU32),
		req("key_hash", tHash28),
	)

	PoolRelay = def("pool_relay",
		req("tx_hash", tHash32),
		req("cert_index", tU32),
		req("position", tU32),
		req("kind", tString), // single_host_addr single_host_name multi_host_name
		opt("port", tU16),
		opt("ipv4", tIPv4),
		opt("ipv6", tIPv6),
		opt("hostname", tString),
	)

	GenesisKeyDelegation = def("genesis_key_delegation",
		req("tx_hash", tHash32),
		req("cert_index", tU32),
		req("genesis_hash", tHash28),
		req("genesis_delegate_hash", tHash28),
		req("vrf_key_hash", tHash32),
	)

	Mir = def("mir",
		req("tx_hash", tHash32),
		req("cert_index", tU32),
		req("source", tString), // reserves treasury
		opt("to_other_pot", tU64),
	)

	MirReward = def("mir_reward",
		req("tx_hash", tHash32),
		req("cert_index", tU32),
		req("is_script", tBool),
		req("cred_hash", tHash28),
		req("amount", tI64),
	)

	ParamUpdate = def("param_update", cols(
		req("tx_hash", tHash32),
		opt("genesis_hash", tHash28),
		opt("epoch", tU64),
		opt("proposal_index", tU32),
		opt("min_fee_a", tU64),
		opt("min_fee_b", tU64),
		opt("max_block_body_size", tU64),
		opt("max_tx_size", tU64),
		opt("max_block_header_size", tU64),
		opt("key_deposit", tU64),
		opt("pool_deposit", tU64),
		opt("max_epoch", tU64),
		opt("n_opt", tU64),
		rational("a0"),
		rational("rho"),
		rational("tau"),
		rational("decentralization"),
		opt("extra_entropy_neutral", tBool),
		opt("extra_entropy", tHash32),
		opt("protocol_major", tU64),
		opt("protocol_minor", tU64),
		opt("min_utxo_value", tU64),
		opt("min_pool_cost", tU64),
		opt("ada_per_utxo_byte", tU64),
		rational("price_mem"),
		rational("price_steps"),
		opt("max_tx_ex_mem", tI64),
		opt("max_tx_ex_steps", tI64),
		opt("max_block_ex_mem", tI64),
		opt("max_block_ex_steps", tI64),
		opt("max_value_size", tU64),
		opt("collateral_percentage", tU64),
		opt("max_collateral_inputs", tU64),
		rational("pvt_motion_no_confidence"),
		rational("pvt_committee_normal"),
		rational("pvt_committee_no_confidence"),
		rational("pvt_hard_fork_initiation"),
		rational("pvt_pp_security_group"),
		rational("dvt_motion_no_confidence"),
		rational("dvt_committee_normal"),
		rational("dvt_committee_no_confidence"),
		rational("dvt_update_to_constitution"),
		rational("dvt_hard_fork_initiation"),
		rational("dvt_pp_network_group"),
		rational("dvt_pp_economic_group"),
		rational("dvt_pp_technical_group"),
		rational("dvt_pp_gov_group"),
		rational("dvt_treasury_withdrawal"),
		opt("min_committee_size", tU64),
		opt("committee_term_limit", tU64),
		opt("gov_action_validity_period", tU64),
		opt("gov_action_deposit", tU64),
		opt("drep_deposit", tU64),
		opt("drep_inactivity_period", tU64),
		rational("min_fee_ref_script"),
	)...)

	ParamUpdateCostModel = def("param_update_cost_model",
		req("tx_hash", tHash32),
		opt("genesis_hash", tHash28),
		opt("proposal_index", tU32),
		req("language", tU8), // 0 PlutusV1, 1 PlutusV2, 2 PlutusV3
		req("position", tU32),
		req("value", tI64),
	)

	Proposal = def("proposal",
		req("tx_hash", tHash32),
		req("proposal_index", tU32),
		req("deposit", tU64),
		req("return_address", tString),
		req("anchor_url", tString),
		req("anchor_data_hash", tHash32),
		req("action_type", tString),
		opt("prev_action_tx_hash", tHash32),
		opt("prev_action_index", tU32),
		opt("policy_hash", tHash28),
		opt("protocol_major", tU64),
		opt("protocol_minor", tU64),
		opt("quorum_numerator", tU64),
		opt("quorum_denominator", tU64),
		opt("constitution_url", tString),
		opt("constitution_hash", tHash32),
		opt("unrecognised", tString), // JSON
	)

	ProposalWithdrawal = def("proposal_withdrawal",
		req("tx_hash", tHash32),
		req("proposal_index", tU32),
		req("reward_account", tString),
		req("amount", tU64),
	)

	ProposalCommitteeRemove = def("proposal_committee_remove",
		req("tx_hash", tHash32),
		req("proposal_index", tU32),
		req("is_script", tBool),
		req("cred_hash", tHash28),
	)

	ProposalCommitteeAdd = def("proposal_committee_add",
		req("tx_hash", tHash32),
		req("proposal_index", tU32),
		req("is_script", tBool),
		req("cred_hash", tHash28),
		req("expires_epoch", tU64),
	)

	Vote = def("vote",
		req("tx_hash", tHash32),
		req("voter_role", tString),
		req("voter_hash", tHash28),
		req("action_tx_hash", tHash32),
		req("action_index", tU32),
		req("vote", tString), // no yes abstain
		opt("anchor_url", tString),
		opt("anchor_data_hash", tHash32),
	)

	VkeyWitness = def("vkey_witness",
		req("tx_hash", tHash32),
		req("position", tU32),
		req("vkey", tHash32),
		// Byron VKWitness keys are extended (CC.xpub): the Ed25519 key in
		// vkey and this chain code. Null for Shelley-era keys and Byron
		// redeem witnesses.
		opt("chain_code", tHash32),
		req("signature", tBytes64),
	)

	BootstrapWitness = def("bootstrap_witness",
		req("tx_hash", tHash32),
		req("position", tU32),
		req("public_key", tHash32),
		req("signature", tBytes64),
		req("chain_code", tHash32),
		req("attributes", tBinary),
	)

	PlutusDatumWitness = def("plutus_datum_witness",
		req("tx_hash", tHash32),
		req("position", tU32),
	)

	Redeemer = def("redeemer",
		req("tx_hash", tHash32),
		req("position", tU32),
		req("purpose", tString), // spend mint certify reward vote propose guard
		req("idx", tU32),
		req("mem", tI64),
		req("steps", tI64),
	)

	PlutusDataNode = def("plutus_data_node",
		req("tx_hash", tHash32),
		req("owner_kind", tString), // inline_datum witness_datum redeemer
		req("owner_position", tU32),
		req("node_id", tU32),
		opt("parent_id", tU32),
		opt("position", tU32),
		opt("map_role", tString), // key value
		req("kind", tString),     // constr map list int bytes
		opt("constr_tag", tU64),
		opt("int_value", tString),
		opt("bytes_value", tBinary),
	)

	MetadataNode = def("metadata_node",
		req("tx_hash", tHash32),
		req("label", tU64),
		req("node_id", tU32),
		opt("parent_id", tU32),
		opt("position", tU32),
		opt("map_role", tString),
		req("kind", tString), // int bytes text list map
		opt("int_value", tDec20),
		opt("bytes_value", tBinary),
		opt("text_value", tString),
	)
)

// BlockTypeRows is the static content of the block_type table: the tag
// gouroboros (and the node's on-disk HFC encoding) wraps each block in.
var BlockTypeRows = []Row{
	{uint64(0), "Byron", true},
	{uint64(1), "Byron", false},
	{uint64(2), "Shelley", false},
	{uint64(3), "Allegra", false},
	{uint64(4), "Mary", false},
	{uint64(5), "Alonzo", false},
	{uint64(6), "Babbage", false},
	{uint64(7), "Conway", false},
}

// Check reports whether row fits t, so a bad value is attributed to the
// block that produced it instead of panicking inside an Arrow builder.
func (t *Table) Check(row Row) error {
	if len(row) != len(t.Columns) {
		return fmt.Errorf("%s: %d values for %d columns", t.Name, len(row), len(t.Columns))
	}
	for i, c := range t.Columns {
		if err := checkValue(c, row[i]); err != nil {
			return fmt.Errorf("%s.%s: %w", t.Name, c.Name, err)
		}
	}
	return nil
}

func checkValue(c Column, v any) error {
	if v == nil {
		if !c.Nullable {
			return fmt.Errorf("null in a required column")
		}
		return nil
	}
	switch t := c.Type.(type) {
	case *arrow.FixedSizeBinaryType:
		b, ok := v.([]byte)
		if !ok {
			return fmt.Errorf("want []byte, got %T", v)
		}
		if len(b) != t.ByteWidth {
			return fmt.Errorf("want %d bytes, got %d", t.ByteWidth, len(b))
		}
	case *arrow.BinaryType:
		if _, ok := v.([]byte); !ok {
			return fmt.Errorf("want []byte, got %T", v)
		}
	case *arrow.StringType:
		if _, ok := v.(string); !ok {
			return fmt.Errorf("want string, got %T", v)
		}
	case *arrow.BooleanType:
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("want bool, got %T", v)
		}
	case *arrow.Uint8Type:
		return checkUint(v, math.MaxUint8)
	case *arrow.Uint16Type:
		return checkUint(v, math.MaxUint16)
	case *arrow.Uint32Type:
		return checkUint(v, math.MaxUint32)
	case *arrow.Uint64Type:
		return checkUint(v, math.MaxUint64)
	case *arrow.Int64Type:
		if _, ok := v.(int64); !ok {
			return fmt.Errorf("want int64, got %T", v)
		}
	case *arrow.Decimal128Type:
		b, ok := v.(*big.Int)
		if !ok {
			return fmt.Errorf("want *big.Int, got %T", v)
		}
		limit := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(t.Precision)), nil)
		if b.CmpAbs(limit) >= 0 {
			return fmt.Errorf("%s exceeds %d digits", b.Text(10), t.Precision)
		}
	default:
		return fmt.Errorf("unsupported column type %s", c.Type)
	}
	return nil
}

func checkUint(v any, max uint64) error {
	u, ok := v.(uint64)
	if !ok {
		return fmt.Errorf("want uint64, got %T", v)
	}
	if u > max {
		return fmt.Errorf("%d out of range", u)
	}
	return nil
}

// Build turns checked rows into an Arrow record batch. The caller releases
// it.
func (t *Table) Build(mem memory.Allocator, rows []Row) arrow.RecordBatch {
	b := array.NewRecordBuilder(mem, t.schema)
	defer b.Release()
	for _, fb := range b.Fields() {
		fb.Reserve(len(rows))
	}
	for _, row := range rows {
		for i, v := range row {
			appendValue(b.Field(i), v)
		}
	}
	return b.NewRecordBatch()
}

func appendValue(fb array.Builder, v any) {
	if v == nil {
		fb.AppendNull()
		return
	}
	switch fb := fb.(type) {
	case *array.FixedSizeBinaryBuilder:
		fb.Append(v.([]byte))
	case *array.BinaryBuilder:
		fb.Append(v.([]byte))
	case *array.StringBuilder:
		fb.Append(v.(string))
	case *array.BooleanBuilder:
		fb.Append(v.(bool))
	case *array.Uint8Builder:
		fb.Append(uint8(v.(uint64)))
	case *array.Uint16Builder:
		fb.Append(uint16(v.(uint64)))
	case *array.Uint32Builder:
		fb.Append(uint32(v.(uint64)))
	case *array.Uint64Builder:
		fb.Append(v.(uint64))
	case *array.Int64Builder:
		fb.Append(v.(int64))
	case *array.Decimal128Builder:
		fb.Append(decimal128.FromBigInt(v.(*big.Int)))
	default:
		panic(fmt.Sprintf("schema: unhandled builder %T", fb))
	}
}
