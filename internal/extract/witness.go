package extract

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"

	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/plutigo/data"

	"github.com/chrisguiney/mithril2pq/internal/schema"
)

var redeemerPurposes = map[lcommon.RedeemerTag]string{
	lcommon.RedeemerTagSpend: "spend", lcommon.RedeemerTagMint: "mint", lcommon.RedeemerTagCert: "certify",
	lcommon.RedeemerTagReward: "reward", lcommon.RedeemerTagVoting: "vote", lcommon.RedeemerTagProposing: "propose",
	lcommon.RedeemerTagGuarding: "guard",
}

func witnesses(b *builder, txh []byte, w lcommon.TransactionWitnessSet) {
	if w == nil || isNilPtr(w) {
		return
	}
	for i, v := range w.Vkey() {
		vkey, chainCode := splitVkey(v.Vkey)
		b.add(schema.VkeyWitness, txh, uint64(i), vkey, optHash(chainCode), v.Signature)
	}
	for i, bw := range w.Bootstrap() {
		b.add(schema.BootstrapWitness, txh, uint64(i), bw.PublicKey, bw.Signature, bw.ChainCode, bw.Attributes)
	}
	txScripts(b, txh, "witness", w.NativeScripts(), w.PlutusV1Scripts(), w.PlutusV2Scripts(), w.PlutusV3Scripts())
	for i, d := range w.PlutusData() {
		b.add(schema.PlutusDatumWitness, txh, uint64(i))
		plutusData(b, txh, "witness_datum", uint64(i), d.Data)
	}
	if r := w.Redeemers(); r != nil && !isNilPtr(r) {
		pos := uint64(0)
		for k, v := range r.Iter() {
			p, ok := redeemerPurposes[k.Tag]
			if !ok {
				p = fmt.Sprintf("unknown_%d", k.Tag)
			}
			b.add(schema.Redeemer, txh, pos, p, uint64(k.Index), v.ExUnits.Memory, v.ExUnits.Steps)
			plutusData(b, txh, "redeemer", pos, v.Data.Data)
			pos++
		}
	}
}

// splitVkey separates a Byron extended public key (64 bytes: Ed25519 key,
// then chain code) into its parts. Any other key is returned as is, with
// no chain code, for the row check to accept or reject.
func splitVkey(k []byte) (vkey, chainCode []byte) {
	if len(k) == 64 {
		return k[:32], k[32:]
	}
	return k, nil
}

func txScripts(b *builder, txh []byte, source string, native []lcommon.NativeScript,
	v1 []lcommon.PlutusV1Script, v2 []lcommon.PlutusV2Script, v3 []lcommon.PlutusV3Script,
) {
	for i, s := range native {
		b.add(schema.TxScript, txh, source, "native", uint64(i), nil)
		owner := nativeOwner{txHash: txh, source: source, position: uint64(i)}
		nativeScript(b, owner, s)
	}
	for i, s := range v1 {
		b.add(schema.TxScript, txh, source, "plutus_v1", uint64(i), []byte(s))
	}
	for i, s := range v2 {
		b.add(schema.TxScript, txh, source, "plutus_v2", uint64(i), []byte(s))
	}
	for i, s := range v3 {
		b.add(schema.TxScript, txh, source, "plutus_v3", uint64(i), []byte(s))
	}
}

func auxData(b *builder, txh []byte, a lcommon.AuxiliaryData) {
	if a == nil || isNilPtr(a) {
		return
	}
	md, err := a.Metadata()
	if err != nil {
		b.fail("auxiliary data metadata: %v", err)
		return
	}
	if md != nil && !isNilPtr(md) {
		top, ok := deref(md).(lcommon.MetaMap)
		if !ok {
			b.fail("transaction metadata is a %T, not a label map", md)
			return
		}
		for _, p := range top.Pairs {
			label, ok := deref(p.Key).(lcommon.MetaInt)
			if !ok || label.Value == nil || !label.Value.IsUint64() {
				b.fail("transaction metadata label is not a uint64")
				return
			}
			metadatum(b, txh, label.Value.Uint64(), p.Value)
		}
	}
	ns, _ := a.NativeScripts()
	v1, _ := a.PlutusV1Scripts()
	v2, _ := a.PlutusV2Scripts()
	v3, _ := a.PlutusV3Scripts()
	txScripts(b, txh, "auxiliary", ns, v1, v2, v3)
}

// ---- scripts ----

// script writes a script_ref's script and returns its hash. The writer
// keeps only the first occurrence of each hash.
func script(b *builder, s lcommon.Script) any {
	h := s.Hash()
	hash := h[:]
	switch x := deref(s).(type) {
	case lcommon.NativeScript:
		b.add(schema.Script, hash, "native", nil)
		nativeScript(b, nativeOwner{scriptHash: hash}, x)
	case lcommon.PlutusV1Script:
		b.add(schema.Script, hash, "plutus_v1", []byte(x))
	case lcommon.PlutusV2Script:
		b.add(schema.Script, hash, "plutus_v2", []byte(x))
	case lcommon.PlutusV3Script:
		b.add(schema.Script, hash, "plutus_v3", []byte(x))
	default:
		b.fail("script_ref of unknown type %T", x)
	}
	return hash
}

type nativeOwner struct {
	scriptHash []byte
	txHash     []byte
	source     string
	position   uint64
}

func nativeScript(b *builder, owner nativeOwner, root lcommon.NativeScript) {
	var ownerHash, ownerTx, ownerSource, ownerPos any
	if owner.scriptHash != nil {
		ownerHash = owner.scriptHash
	} else {
		ownerTx, ownerSource, ownerPos = owner.txHash, owner.source, owner.position
	}
	next := uint64(0)
	var walk func(n lcommon.NativeScript, parent, position any)
	walk = func(n lcommon.NativeScript, parent, position any) {
		id := next
		next++
		var typ string
		var keyHash, required, slot, credIsScript, credHash any
		var children []lcommon.NativeScript
		switch x := deref(n.Item()).(type) {
		case lcommon.NativeScriptPubkey:
			typ, keyHash = "signature", x.Hash
		case lcommon.NativeScriptAll:
			typ, children = "all", x.Scripts
		case lcommon.NativeScriptAny:
			typ, children = "any", x.Scripts
		case lcommon.NativeScriptNofK:
			typ, required, children = "at_least", int64(x.N), x.Scripts
		case lcommon.NativeScriptInvalidBefore:
			typ, slot = "invalid_before", x.Slot
		case lcommon.NativeScriptInvalidHereafter:
			typ, slot = "invalid_hereafter", x.Slot
		case lcommon.NativeScriptRequireGuard:
			typ = "require_guard"
			credIsScript, credHash = credential(x.Credential)
		default:
			b.fail("native script node of unknown type %T", x)
			return
		}
		b.add(schema.NativeScriptNode, ownerHash, ownerTx, ownerSource, ownerPos,
			id, parent, position, typ, keyHash, required, slot, credIsScript, credHash)
		for i, c := range children {
			walk(c, id, uint64(i))
		}
	}
	walk(root, nil, nil)
}

// ---- Plutus data ----

func plutusData(b *builder, txh []byte, ownerKind string, ownerPos uint64, d data.PlutusData) {
	next := uint64(0)
	var walk func(d data.PlutusData, parent, position, role any)
	walk = func(d data.PlutusData, parent, position, role any) {
		id := next
		next++
		add := func(kind string, tag, intVal, bytesVal any) {
			b.add(schema.PlutusDataNode, txh, ownerKind, ownerPos, id, parent, position, role, kind, tag, intVal, bytesVal)
		}
		switch x := deref(d).(type) {
		case data.Constr:
			if x.Tag == nil || !x.Tag.IsUint64() {
				b.fail("Plutus constructor tag %v does not fit uint64", x.Tag)
				return
			}
			add("constr", x.Tag.Uint64(), nil, nil)
			for i, f := range x.Fields {
				walk(f, id, uint64(i), nil)
			}
		case data.Map:
			add("map", nil, nil, nil)
			for i, p := range x.Pairs {
				walk(p[0], id, uint64(i), "key")
				walk(p[1], id, uint64(i), "value")
			}
		case data.List:
			add("list", nil, nil, nil)
			for i, e := range x.Items {
				walk(e, id, uint64(i), nil)
			}
		case data.Integer:
			if x.Inner == nil {
				b.fail("Plutus integer with no value")
				return
			}
			add("int", nil, x.Inner.String(), nil)
		case data.ByteString:
			add("bytes", nil, nil, append([]byte{}, x.Inner...))
		default:
			b.fail("Plutus data of unknown type %T", x)
		}
	}
	walk(d, nil, nil, nil)
}

// ---- metadata ----

func metadatum(b *builder, txh []byte, label uint64, m lcommon.TransactionMetadatum) {
	next := uint64(0)
	var walk func(m lcommon.TransactionMetadatum, parent, position, role any)
	walk = func(m lcommon.TransactionMetadatum, parent, position, role any) {
		id := next
		next++
		add := func(kind string, intVal, bytesVal, textVal any) {
			b.add(schema.MetadataNode, txh, label, id, parent, position, role, kind, intVal, bytesVal, textVal)
		}
		switch x := deref(m).(type) {
		case lcommon.MetaInt:
			if x.Value == nil {
				b.fail("metadata integer with no value")
				return
			}
			add("int", new(big.Int).Set(x.Value), nil, nil)
		case lcommon.MetaBytes:
			add("bytes", nil, append([]byte{}, x.Value...), nil)
		case lcommon.MetaText:
			add("text", nil, nil, x.Value)
		case lcommon.MetaList:
			add("list", nil, nil, nil)
			for i, e := range x.Items {
				walk(e, id, uint64(i), nil)
			}
		case lcommon.MetaMap:
			add("map", nil, nil, nil)
			for i, p := range x.Pairs {
				walk(p.Key, id, uint64(i), "key")
				walk(p.Value, id, uint64(i), "value")
			}
		default:
			b.fail("metadatum of unknown type %T", x)
		}
	}
	walk(m, nil, nil, nil)
}

// ---- reflection helpers ----

// deref returns the value a pointer points at, so type switches need only
// list value types; gouroboros returns some of these by pointer, some not.
func deref(v any) any {
	rv := reflect.ValueOf(v)
	for rv.IsValid() && rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	if !rv.IsValid() {
		return nil
	}
	return rv.Interface()
}

// reflectJSON renders a value with no schema of its own (an unknown
// certificate or governance action kind) as JSON: exported fields in
// snake_case, bytes as hex, big numbers as decimal strings.
func reflectJSON(v any) any {
	out, err := json.Marshal(reflectValue(reflect.ValueOf(v), 0))
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return string(out)
}

func reflectValue(rv reflect.Value, depth int) any {
	if !rv.IsValid() || depth > 64 {
		return nil
	}
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	switch x := rv.Interface().(type) {
	case big.Int:
		return x.String()
	case cbor.Rat:
		if x.Rat == nil {
			return nil
		}
		return x.Rat.String()
	}
	switch rv.Kind() {
	case reflect.Struct:
		o := map[string]any{}
		t := rv.Type()
		for i := 0; i < t.NumField(); i++ {
			sf := t.Field(i)
			if !sf.IsExported() || sf.Anonymous {
				continue
			}
			if v := reflectValue(rv.Field(i), depth+1); v != nil {
				o[snake(sf.Name)] = v
			}
		}
		return o
	case reflect.Slice, reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			buf := make([]byte, rv.Len())
			reflect.Copy(reflect.ValueOf(buf), rv)
			return hex.EncodeToString(buf)
		}
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = reflectValue(rv.Index(i), depth+1)
		}
		return out
	case reflect.Map:
		var out []any
		for _, k := range rv.MapKeys() {
			out = append(out, map[string]any{"key": reflectValue(k, depth+1), "value": reflectValue(rv.MapIndex(k), depth+1)})
		}
		return out
	default:
		return rv.Interface()
	}
}
