package extract

import (
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"unicode"

	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"

	"github.com/chrisguiney/mithril2pq/internal/schema"
)

var voterRoleNames = map[uint8]string{
	0: "constitutional_committee_hot_key", 1: "constitutional_committee_hot_script",
	2: "drep_key", 3: "drep_script", 4: "stake_pool",
}

var voteNames = map[uint8]string{0: "no", 1: "yes", 2: "abstain"}

func votes(b *builder, txh []byte, vps lcommon.VotingProcedures) {
	for voter, byAction := range vps {
		if voter == nil {
			continue
		}
		role, ok := voterRoleNames[voter.Type]
		if !ok {
			b.fail("voter with unknown role %d", voter.Type)
			return
		}
		for id, p := range byAction {
			if id == nil {
				continue
			}
			v, ok := voteNames[p.Vote]
			if !ok {
				b.fail("vote with unknown value %d", p.Vote)
				return
			}
			var url, dh any
			if p.Anchor != nil {
				url, dh = p.Anchor.Url, p.Anchor.DataHash[:]
			}
			b.add(schema.Vote, txh, role, voter.Hash[:], id.TransactionId[:], uint64(id.GovActionIdx), v, url, dh)
		}
	}
}

func proposal(b *builder, txh []byte, idx uint64, p lcommon.ProposalProcedure) {
	a := p.Anchor()
	// tx_hash, proposal_index, deposit, return_address, anchor_url,
	// anchor_data_hash, action_type, prev_action_tx_hash, prev_action_index,
	// policy_hash, protocol_major, protocol_minor, quorum_numerator,
	// quorum_denominator, constitution_url, constitution_hash, unrecognised
	row := schema.Row{txh, idx, p.Deposit(), p.RewardAccount().String(), a.Url, a.DataHash[:],
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil}
	prev := func(id *lcommon.GovActionId) {
		if id != nil {
			row[7], row[8] = id.TransactionId[:], uint64(id.GovActionIdx)
		}
	}
	var after func()
	switch x := deref(p.GovAction()).(type) {
	case conway.ConwayParameterChangeGovAction:
		row[6] = "parameter_change"
		prev(x.ActionId)
		row[9] = optHash(x.PolicyHash)
		after = func() { paramUpdate(b, txh, nil, 0, idx, x.ParamUpdate) }
	case lcommon.HardForkInitiationGovAction:
		row[6] = "hard_fork_initiation"
		prev(x.ActionId)
		row[10], row[11] = uint64(x.ProtocolVersion.Major), uint64(x.ProtocolVersion.Minor)
	case lcommon.TreasuryWithdrawalGovAction:
		row[6] = "treasury_withdrawals"
		row[9] = optHash(x.PolicyHash)
		after = func() {
			for addr, amt := range x.Withdrawals {
				b.add(schema.ProposalWithdrawal, txh, idx, addr.String(), amt)
			}
		}
	case lcommon.NoConfidenceGovAction:
		row[6] = "no_confidence"
		prev(x.ActionId)
	case lcommon.UpdateCommitteeGovAction:
		row[6] = "update_committee"
		prev(x.ActionId)
		row[12], row[13] = b.rat(x.Quorum.Rat)
		after = func() {
			for _, c := range x.Credentials {
				s, h := credential(c)
				b.add(schema.ProposalCommitteeRemove, txh, idx, s, h)
			}
			for c, e := range x.CredEpochs {
				s, h := credential(*c)
				b.add(schema.ProposalCommitteeAdd, txh, idx, s, h, uint64(e))
			}
		}
	case lcommon.NewConstitutionGovAction:
		row[6] = "new_constitution"
		prev(x.ActionId)
		row[14], row[15] = x.Constitution.Anchor.Url, x.Constitution.Anchor.DataHash[:]
		row[9] = optHash(x.Constitution.ScriptHash)
	case lcommon.InfoGovAction:
		row[6] = "info"
	default:
		row[6] = fmt.Sprintf("unknown %T", x)
		row[16] = reflectJSON(x)
	}
	b.add(schema.Proposal, row...)
	if after != nil {
		after()
	}
}

// ---- protocol-parameter updates ----

// ppRenames covers Go field names whose snake_case form is not the column
// name.
var ppRenames = map[string]string{
	"DRepDeposit":                "drep_deposit",
	"DRepInactivityPeriod":       "drep_inactivity_period",
	"MinFeeRefScriptCostPerByte": "min_fee_ref_script",
	"Decentralization":           "decentralization",
	"PoolVotingThresholds":       "pvt",
	"DRepVotingThresholds":       "dvt",
}

var ppColumns = func() map[string]int {
	m := map[string]int{}
	for i, c := range schema.ParamUpdate.Columns {
		m[c.Name] = i
	}
	return m
}()

// paramUpdate writes one parameter-update payload: a pre-Conway proposal
// (genesisHash, epoch) or a Conway parameter_change (proposalIndex). Every
// set field must map to a column; one that does not fails the block, so a
// new parameter is noticed rather than dropped.
func paramUpdate(b *builder, txh []byte, genesisHash any, epoch uint64, proposalIndex any, u any) {
	row := make(schema.Row, len(schema.ParamUpdate.Columns))
	row[0], row[1], row[3] = txh, genesisHash, proposalIndex
	if genesisHash != nil {
		row[2] = epoch
	}
	set := func(col string, v any) {
		i, ok := ppColumns[col]
		if !ok {
			b.fail("parameter update field %s has no column", col)
			return
		}
		row[i] = v
	}
	setRat := func(col string, r *cbor.Rat) {
		if r != nil {
			n, d := b.rat(r.Rat)
			set(col+"_numerator", n)
			set(col+"_denominator", d)
		}
	}
	rv := reflect.Indirect(reflect.ValueOf(u))
	if rv.Kind() != reflect.Struct {
		b.fail("parameter update of type %T", u)
		return
	}
	t := rv.Type()
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if !sf.IsExported() || sf.Anonymous {
			continue
		}
		fv := rv.Field(i)
		if (fv.Kind() == reflect.Pointer || fv.Kind() == reflect.Map) && fv.IsNil() {
			continue
		}
		col, ok := ppRenames[sf.Name]
		if !ok {
			col = snake(sf.Name)
		}
		switch v := fv.Interface().(type) {
		case *uint:
			set(col, uint64(*v))
		case *uint64:
			set(col, *v)
		case *cbor.Rat:
			setRat(col, v)
		case *lcommon.Nonce:
			set("extra_entropy_neutral", v.Type == 0)
			if v.Type != 0 {
				set("extra_entropy", append([]byte(nil), v.Value[:]...))
			}
		case *lcommon.ProtocolParametersProtocolVersion:
			set("protocol_major", uint64(v.Major))
			set("protocol_minor", uint64(v.Minor))
		case *lcommon.ExUnitPrice:
			setRat("price_mem", v.MemPrice)
			setRat("price_steps", v.StepPrice)
		case *lcommon.ExUnits:
			prefix := map[string]string{"MaxTxExUnits": "max_tx_ex", "MaxBlockExUnits": "max_block_ex"}[sf.Name]
			if prefix == "" {
				b.fail("parameter update field %s has no column", sf.Name)
				continue
			}
			set(prefix+"_mem", v.Memory)
			set(prefix+"_steps", v.Steps)
		case map[uint][]int64:
			langs := make([]uint, 0, len(v))
			for l := range v {
				langs = append(langs, l)
			}
			sort.Slice(langs, func(i, j int) bool { return langs[i] < langs[j] })
			for _, l := range langs {
				for pos, val := range v[l] {
					b.add(schema.ParamUpdateCostModel, txh, genesisHash, proposalIndex, uint64(l), uint64(pos), val)
				}
			}
		default:
			// Voting-threshold structs: every field is a cbor.Rat.
			tv := reflect.Indirect(fv)
			if tv.Kind() != reflect.Struct {
				b.fail("parameter update field %s has unsupported type %T", sf.Name, v)
				continue
			}
			for j := 0; j < tv.NumField(); j++ {
				tf := tv.Type().Field(j)
				if !tf.IsExported() || tf.Anonymous {
					continue
				}
				r, ok := tv.Field(j).Interface().(cbor.Rat)
				if !ok {
					b.fail("parameter update field %s.%s has unsupported type %s", sf.Name, tf.Name, tf.Type)
					continue
				}
				setRat(col+"_"+snake(tf.Name), &r)
			}
		}
	}
	b.add(schema.ParamUpdate, row...)
}

func snake(s string) string {
	var sb strings.Builder
	r := []rune(s)
	for i, c := range r {
		if unicode.IsUpper(c) {
			if i > 0 && (unicode.IsLower(r[i-1]) || unicode.IsDigit(r[i-1]) || (i+1 < len(r) && unicode.IsLower(r[i+1]))) {
				sb.WriteByte('_')
			}
			sb.WriteRune(unicode.ToLower(c))
		} else {
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

func itoa(u uint64) string { return new(big.Int).SetUint64(u).String() }
