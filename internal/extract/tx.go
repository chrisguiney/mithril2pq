package extract

import (
	"net"
	"reflect"
	"sort"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"

	"github.com/chrisguiney/mithril2pq/internal/schema"
)

func transaction(b *builder, blockHash []byte, index int, tx lcommon.Transaction) {
	id := tx.Hash()
	txh := id[:]
	var auxHash, sdHash any
	if h := tx.AuxDataHash(); h != nil {
		auxHash = h[:]
	}
	if h := tx.ScriptDataHash(); h != nil {
		sdHash = h[:]
	}
	var netID any
	if n := networkID(tx); n != nil {
		netID = uint64(*n)
	}
	b.add(schema.Tx,
		txh, blockHash, uint64(index), tx.IsValid(), b.u64(tx.Fee()),
		zeroNil(tx.TTL()), zeroNil(tx.ValidityIntervalStart()),
		b.bigU64Zero(tx.TotalCollateral()), auxHash, netID, sdHash,
		b.bigU64Zero(tx.CurrentTreasuryValue()), b.bigU64Zero(tx.Donation()),
	)

	inputs(b, txh, "spend", tx.Inputs())
	inputs(b, txh, "reference", tx.ReferenceInputs())
	inputs(b, txh, "collateral", tx.Collateral())

	outs := tx.Outputs()
	for i, o := range outs {
		output(b, txh, uint64(i), false, o)
	}
	// The ledger gives the collateral return index len(outputs).
	if cr := tx.CollateralReturn(); cr != nil && !isNilPtr(cr) {
		output(b, txh, uint64(len(outs)), true, cr)
	}

	if m := tx.AssetMint(); m != nil {
		for _, p := range sortedPolicies(m.Policies()) {
			for _, name := range sortedNames(m.Assets(p)) {
				b.add(schema.TxMint, txh, hash28(p), name, b.i64(m.Asset(p, name)))
			}
		}
	}

	for i, s := range tx.RequiredSigners() {
		b.add(schema.TxRequiredSigner, txh, uint64(i), hash28(s))
	}

	for addr, amt := range tx.Withdrawals() {
		b.add(schema.TxWithdrawal, txh, addr.String(), b.u64(amt))
	}

	for i, c := range tx.Certificates() {
		certificate(b, txh, uint64(i), c)
	}

	if epoch, ups := tx.ProtocolParameterUpdates(); len(ups) > 0 {
		for g, u := range ups {
			paramUpdate(b, txh, hash28(g), epoch, nil, u)
		}
	}

	votes(b, txh, tx.VotingProcedures())
	for i, p := range tx.ProposalProcedures() {
		proposal(b, txh, uint64(i), p)
	}

	witnesses(b, txh, tx.Witnesses())
	auxData(b, txh, tx.AuxiliaryData())
}

func isNilPtr(v any) bool {
	rv := reflect.ValueOf(v)
	return !rv.IsValid() || (rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface) && rv.IsNil()
}

func hash28(h lcommon.Blake2b224) []byte { return h[:] }

func inputs(b *builder, txh []byte, kind string, ins []lcommon.TransactionInput) {
	for i, in := range ins {
		id := in.Id()
		b.add(schema.TxInput, txh, kind, uint64(i), id[:], uint64(in.Index()))
	}
}

func output(b *builder, txh []byte, index uint64, collateralReturn bool, o lcommon.TransactionOutput) {
	var datumHash, scriptRef any
	hasInline := false
	if d := o.Datum(); d != nil && d.Data != nil {
		hasInline = true
		plutusData(b, txh, "inline_datum", index, d.Data)
	} else if h := o.DatumHash(); h != nil {
		datumHash = h[:]
	}
	if s := o.ScriptRef(); s != nil && !isNilPtr(s) {
		scriptRef = script(b, s)
	}
	b.add(schema.TxOutput, txh, index, collateralReturn, o.Address().String(), b.u64(o.Amount()),
		datumHash, hasInline, scriptRef)
	if a := o.Assets(); a != nil {
		for _, p := range sortedPolicies(a.Policies()) {
			for _, name := range sortedNames(a.Assets(p)) {
				b.add(schema.TxOutputAsset, txh, index, hash28(p), name, b.u64(a.Asset(p, name)))
			}
		}
	}
}

func sortedPolicies(ps []lcommon.Blake2b224) []lcommon.Blake2b224 {
	out := append([]lcommon.Blake2b224(nil), ps...)
	sort.Slice(out, func(i, j int) bool { return string(out[i][:]) < string(out[j][:]) })
	return out
}

func sortedNames(ns [][]byte) [][]byte {
	out := append([][]byte(nil), ns...)
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}

// ---- certificates ----

func certificate(b *builder, txh []byte, idx uint64, c lcommon.Certificate) {
	// tx_hash, cert_index, cert_type, pool_key_hash, drep_kind, drep_hash,
	// amount, anchor_url, anchor_data_hash, retirement_epoch, unrecognised
	row := schema.Row{txh, idx, nil, nil, nil, nil, nil, nil, nil, nil, nil}
	cred := func(role string, c lcommon.Credential) {
		s, h := credential(c)
		b.add(schema.CertificateCredential, txh, idx, role, s, h)
	}
	setAnchor := func(a *lcommon.GovAnchor) {
		if a != nil {
			row[7], row[8] = a.Url, a.DataHash[:]
		}
	}
	setDrep := func(d lcommon.Drep) {
		row[4], row[5] = drepKind(d)
	}
	var after func()
	switch x := deref(c).(type) {
	case lcommon.StakeRegistrationCertificate:
		row[2] = "stake_registration"
		after = func() { cred("stake", x.StakeCredential) }
	case lcommon.StakeDeregistrationCertificate:
		row[2] = "stake_deregistration"
		after = func() { cred("stake", x.StakeCredential) }
	case lcommon.StakeDelegationCertificate:
		row[2] = "stake_delegation"
		row[3] = hash28(lcommon.Blake2b224(x.PoolKeyHash))
		after = func() {
			if x.StakeCredential != nil {
				cred("stake", *x.StakeCredential)
			}
		}
	case lcommon.PoolRegistrationCertificate:
		row[2] = "pool_registration"
		after = func() { poolRegistration(b, txh, idx, x) }
	case lcommon.PoolRetirementCertificate:
		row[2] = "pool_retirement"
		row[3] = hash28(lcommon.Blake2b224(x.PoolKeyHash))
		row[9] = x.Epoch
	case lcommon.GenesisKeyDelegationCertificate:
		row[2] = "genesis_key_delegation"
		after = func() {
			b.add(schema.GenesisKeyDelegation, txh, idx, []byte(x.GenesisHash), []byte(x.GenesisDelegateHash), x.VrfKeyHash[:])
		}
	case lcommon.MoveInstantaneousRewardsCertificate:
		row[2] = "move_instantaneous_rewards"
		after = func() {
			src := map[uint]string{0: "reserves", 1: "treasury"}[x.Reward.Source]
			if src == "" {
				b.fail("MIR certificate with unknown source %d", x.Reward.Source)
				return
			}
			b.add(schema.Mir, txh, idx, src, zeroNil(x.Reward.OtherPot))
			for c, amt := range x.Reward.Rewards {
				s, h := credential(*c)
				b.add(schema.MirReward, txh, idx, s, h, b.i64(amt))
			}
		}
	case lcommon.RegistrationCertificate:
		row[2], row[6] = "registration", b.u64(x.Amount)
		after = func() { cred("stake", x.StakeCredential) }
	case lcommon.DeregistrationCertificate:
		row[2], row[6] = "deregistration", b.u64(x.Amount)
		after = func() { cred("stake", x.StakeCredential) }
	case lcommon.VoteDelegationCertificate:
		row[2] = "vote_delegation"
		setDrep(x.Drep)
		after = func() { cred("stake", x.StakeCredential) }
	case lcommon.StakeVoteDelegationCertificate:
		row[2] = "stake_vote_delegation"
		row[3] = hash28(lcommon.Blake2b224(x.PoolKeyHash))
		setDrep(x.Drep)
		after = func() { cred("stake", x.StakeCredential) }
	case lcommon.StakeRegistrationDelegationCertificate:
		row[2], row[6] = "stake_registration_delegation", b.u64(x.Amount)
		row[3] = hash28(lcommon.Blake2b224(x.PoolKeyHash))
		after = func() { cred("stake", x.StakeCredential) }
	case lcommon.VoteRegistrationDelegationCertificate:
		row[2], row[6] = "vote_registration_delegation", b.u64(x.Amount)
		setDrep(x.Drep)
		after = func() { cred("stake", x.StakeCredential) }
	case lcommon.StakeVoteRegistrationDelegationCertificate:
		row[2], row[6] = "stake_vote_registration_delegation", b.u64(x.Amount)
		row[3] = hash28(lcommon.Blake2b224(x.PoolKeyHash))
		setDrep(x.Drep)
		after = func() { cred("stake", x.StakeCredential) }
	case lcommon.AuthCommitteeHotCertificate:
		row[2] = "auth_committee_hot"
		after = func() {
			cred("committee_cold", x.ColdCredential)
			cred("committee_hot", x.HotCredential)
		}
	case lcommon.ResignCommitteeColdCertificate:
		row[2] = "resign_committee_cold"
		setAnchor(x.Anchor)
		after = func() { cred("committee_cold", x.ColdCredential) }
	case lcommon.RegistrationDrepCertificate:
		row[2], row[6] = "drep_registration", b.u64(x.Amount)
		setAnchor(x.Anchor)
		after = func() { cred("drep", x.DrepCredential) }
	case lcommon.DeregistrationDrepCertificate:
		row[2], row[6] = "drep_deregistration", b.u64(x.Amount)
		after = func() { cred("drep", x.DrepCredential) }
	case lcommon.UpdateDrepCertificate:
		row[2] = "drep_update"
		setAnchor(x.Anchor)
		after = func() { cred("drep", x.DrepCredential) }
	default:
		row[2] = "unknown_" + itoa(uint64(c.Type()))
		row[10] = reflectJSON(x)
	}
	b.add(schema.Certificate, row...)
	if after != nil {
		after()
	}
}

func drepKind(d lcommon.Drep) (any, any) {
	switch d.Type {
	case lcommon.DrepTypeAddrKeyHash:
		return "key_hash", d.Credential
	case lcommon.DrepTypeScriptHash:
		return "script_hash", d.Credential
	case lcommon.DrepTypeAbstain:
		return "always_abstain", nil
	case lcommon.DrepTypeNoConfidence:
		return "always_no_confidence", nil
	}
	return "unknown_" + itoa(uint64(d.Type)), optHash(d.Credential)
}

func poolRegistration(b *builder, txh []byte, idx uint64, x lcommon.PoolRegistrationCertificate) {
	num, den := b.rat(x.Margin.Rat)
	var mdURL, mdHash any
	if x.PoolMetadata != nil {
		mdURL, mdHash = x.PoolMetadata.Url, x.PoolMetadata.Hash[:]
	}
	b.add(schema.PoolRegistration, txh, idx,
		hash28(lcommon.Blake2b224(x.Operator)), x.VrfKeyHash[:], x.Pledge, x.Cost, num, den,
		hash28(lcommon.Blake2b224(x.RewardAccount)), mdURL, mdHash)
	for _, o := range x.PoolOwners {
		b.add(schema.PoolOwner, txh, idx, hash28(lcommon.Blake2b224(o)))
	}
	for i, r := range x.Relays {
		kind := map[int]string{0: "single_host_addr", 1: "single_host_name", 2: "multi_host_name"}[r.Type]
		if kind == "" {
			b.fail("pool relay with unknown type %d", r.Type)
			return
		}
		var port, v4, v6, host any
		if r.Port != nil {
			port = uint64(*r.Port)
		}
		if r.Ipv4 != nil {
			if ip := r.Ipv4.To4(); ip != nil {
				v4 = []byte(ip)
			} else {
				b.fail("pool relay IPv4 address %v is not 4 bytes", *r.Ipv4)
			}
		}
		if r.Ipv6 != nil {
			v6 = ipv6(*r.Ipv6)
		}
		if r.Hostname != nil {
			host = *r.Hostname
		}
		b.add(schema.PoolRelay, txh, idx, uint64(i), kind, port, v4, v6, host)
	}
}

// ipv6 undoes the ledger's encoding: IPv6 is serialised as four 32-bit
// words, each little-endian, and gouroboros keeps those wire bytes, so each
// 4-byte group is reversed relative to network order.
func ipv6(ip net.IP) []byte {
	b := ip.To16()
	if len(b) != net.IPv6len {
		return []byte(ip)
	}
	out := make([]byte, net.IPv6len)
	for w := 0; w < net.IPv6len; w += 4 {
		out[w], out[w+1], out[w+2], out[w+3] = b[w+3], b[w+2], b[w+1], b[w]
	}
	return out
}

// networkID reads body key 15, which is not on the Transaction interface.
// Conway bodies hold it as TxNetworkId *uint8 (nil when absent); Alonzo and
// Babbage hold NetworkId uint8 plus a presence flag in TransactionBodyBase,
// which is what tells an explicit 0 from an absent field.
func networkID(tx lcommon.Transaction) *uint8 {
	rv := reflect.Indirect(reflect.ValueOf(tx))
	if rv.Kind() != reflect.Struct {
		return nil
	}
	body := rv.FieldByName("Body")
	if !body.IsValid() || body.Kind() != reflect.Struct {
		return nil
	}
	if p := body.FieldByName("TxNetworkId"); p.IsValid() && p.Kind() == reflect.Pointer {
		if p.IsNil() {
			return nil
		}
		n := uint8(p.Elem().Uint())
		return &n
	}
	field := body.FieldByName("NetworkId")
	if !field.IsValid() || field.Kind() != reflect.Uint8 {
		return nil
	}
	ptr := reflect.New(body.Type())
	ptr.Elem().Set(body)
	present, ok := ptr.Interface().(interface{ NetworkIdPresent() bool })
	n := uint8(field.Uint())
	if (ok && present.NetworkIdPresent()) || n != 0 {
		return &n
	}
	return nil
}
