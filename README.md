# mithril2pq

`mithril2pq` downloads a Cardano database snapshot from a
[Mithril](https://mithril.network) aggregator and writes every block in it as
a set of flat, third-normal-form Parquet tables. A later run brings the same
output directory up to date with a newer snapshot, applying only the chunks it
does not yet hold.

```sh
go install github.com/chrisguiney/mithril2pq@latest

mithril2pq -mithril-archive preview -out ./preview-pq
mithril2pq -mithril-archive mainnet -out /data/mainnet-pq -cache-dir /data/mithril-cache -file-size 1GB
```

```python
import pyarrow.dataset as ds
txs = ds.dataset("preview-pq/tx").to_table()
```

## Docker

One Dockerfile builds two images:

```sh
docker build --target mithril2pq -t mithril2pq .     # the static binary alone
docker build -t mithril2pq-notebook .                # JupyterLab, DuckDB and notebooks/explore.ipynb

docker run --rm --user "$(id -u):$(id -g)" -v /data/mithril:/data \
  mithril2pq -mithril-archive preview -out /data/preview -cache-dir /data/cache/preview

docker run -d -p 127.0.0.1:8888:8888 -e JUPYTER_TOKEN=... \
  -v /data/mithril/preview:/data:ro -v "$PWD/notebooks:/work" mithril2pq-notebook
```

The notebook exposes every table as a DuckDB view over its Parquet files, with
`tables.<name>`, `load(...)` and `sql(...)` returning pandas DataFrames
(hashes as hex strings by default). `MITHRIL2PQ_DATA` sets the data directory
(default `/data`) and `DUCKDB_MEMORY_LIMIT` caps DuckDB's memory (default
`16GB`).

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-out` | (required) | output directory |
| `-mithril-archive` | `mainnet` | `mainnet`, `preprod`, `preview`, or an aggregator URL |
| `-snapshot` | latest | snapshot hash to convert |
| `-cache-dir` | none | keep downloaded archives here, still compressed, and reuse them; one directory per network |
| `-file-size` | `128MB` | target Parquet file size: `300MB`, `3GB`, `512MiB`, ... (KB/MB/GB are decimal, KiB/MiB/GiB binary) |
| `-concurrency` | 25 | concurrent downloads |
| `-buffer` | 2 × concurrency | without a cache, how many downloaded archives may wait in memory for the writer |
| `-workers` | CPU count | concurrent chunk decoders |
| `-checkpoint` | `30m` | commit progress at least this often; `0` commits only at the end |
| `-compression` | `zstd` | `zstd`, `snappy`, `gzip` or `none` |
| `-last-chunk` | snapshot's last | stop after this immutable file |

Downloads run ahead of decoding and writing. With `-cache-dir` they run ahead
freely onto disk; without it, at most `-buffer` archives are held in memory.
Decoding is parallel; tables are written in chunk order, all tables at once.

Progress is printed to stderr: chunks written, archives fetched and how far
ahead, download rate and total, Parquet files and bytes written, disk write
rate (Parquet plus cache), blocks, transactions and an ETA.

## Verification

For each snapshot, before converting anything:

- the certificate is for this snapshot (same beacon) and its protocol message
  carries the snapshot's Merkle root;
- the certificate's signed message is the hash of its protocol message;
- the snapshot's digest list (SHA-256 of every immutable file) hashes to the
  certified Merkle root.

For each immutable file:

- the archive's MD5 against the storage server's `x-goog-hash`, when sent;
- each of `.chunk`, `.primary` and `.secondary` against its certified SHA-256;
- every block's CRC32 against the secondary index;
- the primary index's EBB slot against each block's type tag;
- every decoded block's header hash against the secondary index;
- each chunk's first block's previous hash against the last block written.

**Not verified:** the certificate's STM multi-signature and the certificate
chain back to the genesis certificate. That needs BLS12-381 and Mithril's STM
scheme, which have no Go implementation. Use `mithril-client` when the data
must be authenticated against the Mithril signers.

## Output layout

```
out/
  _mithril2pq.json          manifest: network, snapshot, last chunk, committed files
  block/part-000000.parquet
  tx/part-000000.parquet
  tx/part-000001.parquet
  ...
```

Each table is a directory of `part-NNNNNN.parquet` files in chain order.
Every file carries `mithril2pq.first_chunk`, `mithril2pq.last_chunk` and
`mithril2pq.schema_version` key-value metadata.

The files use only features the common Python readers support (checked with
pyarrow, fastparquet and DuckDB): format 2.6 logical types, version 1 data
pages, dictionary and plain encodings, statistics, no page index, bloom
filters or byte-stream-split encoding. Hashes are `FIXED_LEN_BYTE_ARRAY`
(28 bytes for Blake2b-224, 32 for Blake2b-256), so pyarrow reads them as
`fixed_size_binary`.

### Resuming and interruption

The manifest is the source of truth. Parquet files are written under a
temporary name and renamed when complete; the manifest is replaced atomically
last, at each checkpoint and at the end. On start, files the manifest does not
list and temporary files are deleted. So after a crash or `kill -9` the
directory still holds exactly the chunks the manifest names.

Ctrl-C (or SIGTERM) finishes the current chunk, commits, and exits; a second
Ctrl-C exits at once, removing temporary files without committing.

When new chunks are applied, each table's last file is rewritten with the new
rows appended if it is under `-file-size`, otherwise a new file is started.
Committed files are never modified in place: the rewritten file gets the next
part number and the old one is deleted after the manifest stops listing it.

A run refuses an output directory from another network, another schema
version, or another chain (the snapshot's digests for the last applied chunk
must match the ones recorded in the manifest).

Files land at about `-file-size`; each can exceed it by roughly the size of
its last row group.

## Tables

Keys are natural: block hash, transaction hash, and positions within a
transaction. Parquet has no constraints, so the keys below are conventions.

| Table | Key | Content |
|---|---|---|
| `block_type` | `block_type` | static lookup: the `[type, block]` wrapper tag → era, EBB |
| `block` | `hash` | chunk position, slot (or `ebb_epoch`), offsets, CRC, block number, tx count, `decode_error` |
| `block_header` | `block_hash` | previous hash, issuer and VRF keys, body size and hash, protocol version, KES signature, operational certificate |
| `block_header_vrf` | `block_hash, kind` | VRF output and proof (`vrf_result`, or `nonce` and `leader` before Babbage) |
| `tx` | `hash` | block, index, validity, fee, TTL, collateral, hashes, network id, treasury, donation |
| `tx_input` | `tx_hash, kind, position` | spend, reference and collateral inputs |
| `tx_output` | `tx_hash, output_index` | outputs; the collateral return is index `len(outputs)` |
| `tx_output_asset` | `tx_hash, output_index, policy_id, asset_name` | multi-asset quantities |
| `tx_mint` | `tx_hash, policy_id, asset_name` | mint (negative = burn) |
| `tx_required_signer`, `tx_withdrawal` | | |
| `script` | `hash` | scripts referenced by outputs (`script_ref`), once each |
| `tx_script` | `tx_hash, source, language, position` | witness-set and auxiliary-data scripts |
| `native_script_node` | owner, `node_id` | native script trees, one row per node |
| `certificate` | `tx_hash, cert_index` | all certificate kinds, with their shared columns |
| `certificate_credential` | `tx_hash, cert_index, role` | stake, DRep and committee credentials |
| `pool_registration`, `pool_owner`, `pool_relay` | | pool parameters |
| `genesis_key_delegation`, `mir`, `mir_reward` | | |
| `param_update`, `param_update_cost_model` | | pre-Conway update proposals and Conway parameter changes, one column per parameter |
| `proposal`, `proposal_withdrawal`, `proposal_committee_add`, `proposal_committee_remove` | `tx_hash, proposal_index` | governance actions |
| `vote` | `tx_hash, voter, action` | votes |
| `vkey_witness`, `bootstrap_witness`, `plutus_datum_witness`, `redeemer` | | witnesses |
| `plutus_data_node` | owner, `node_id` | inline datums, witness datums and redeemer data, one row per node |
| `metadata_node` | `tx_hash, label, node_id` | transaction metadata, one row per node |

The tree tables (`plutus_data_node`, `metadata_node`, `native_script_node`)
hold one row per node in pre-order: `node_id` (root 0), `parent_id`,
`position` within the parent, and for map children `map_role` (`key` or
`value`). Plutus integers are unbounded, so they are decimal strings;
metadata integers are `DECIMAL(20,0)`.

### What the tables do not show

Blocks are decoded with [gouroboros](https://github.com/blinklabs-io/gouroboros),
and the tables inherit its normalisation:

- assets and mint entries with a quantity of zero are dropped;
- duplicate redeemer keys are merged;
- votes, withdrawals, MIR rewards and committee additions lose their wire
  order (they are keyed by content);
- a pool registration's reward account is its key hash only;
- Byron blocks get only what gouroboros's era-independent interfaces expose.

A block gouroboros cannot decode still gets its `block` row, with
`decode_error` set, and no other rows.

## License

Apache License 2.0; see [LICENSE](LICENSE).
