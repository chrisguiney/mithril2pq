# mithril2pq

`mithril2pq` downloads a Cardano database snapshot from a
[Mithril](https://mithril.network) aggregator and writes every block in it as
a set of flat, third-normal-form Parquet tables.

An existing output directory is **updated in place**: run the same command
again later and mithril2pq converts only the chunks the newer snapshot adds,
appending them to the existing tables. There is no need to rebuild the
dataset to bring it up to date. See
[Updating an existing dataset](#updating-an-existing-dataset).

It needs no Cardano node, no `mithril-client` and no other external program:
downloading, verification, decoding (with
[gouroboros](https://github.com/blinklabs-io/gouroboros)) and Parquet writing
are all in one static Go binary.

```sh
mithril2pq -mithril-archive preview -out ./preview-pq
mithril2pq -mithril-archive mainnet -out /data/mainnet-pq -cache-dir /data/mithril-cache/mainnet -file-size 1GB
```

```python
import duckdb
duckdb.sql("SELECT count(*) FROM read_parquet('preview-pq/tx/part-*.parquet')")
```

Contents:

- [Building](#building)
- [Usage and options](#usage-and-options)
- [Updating an existing dataset](#updating-an-existing-dataset)
- [Verification](#verification)
- [Output layout](#output-layout)
- [Parquet schema](#parquet-schema)
- [Exploring the data](#exploring-the-data)

## Building

### From source

Requires Go 1.26 or later. The binary is static (`CGO_ENABLED=0` works) and
has no runtime dependencies.

```sh
git clone https://github.com/chrisguiney/mithril2pq
cd mithril2pq
go build -o mithril2pq .
go test ./...
```

or, without cloning:

```sh
go install github.com/chrisguiney/mithril2pq@latest
```

### Docker images

One multi-stage `Dockerfile` builds two images. Choose with `--target`:

| Image | Build command | Contents | Size |
|---|---|---|---|
| **binary only** | `docker build --target mithril2pq -t mithril2pq .` | the static `mithril2pq` binary on `distroless/static` (non-root); the binary is the entrypoint | ~50 MB |
| **notebook** (default target) | `docker build -t mithril2pq-notebook .` | Python 3.12, JupyterLab, DuckDB, pandas, pyarrow, numpy, matplotlib, seaborn, plotly, altair, bokeh, ipywidgets, the `mithril2pq` binary, and `notebooks/explore.ipynb` | ~950 MB |

The binary-only image is the one for running conversions, in a scheduled job
or on a server. The notebook image is for exploring the output; it also
contains the binary, so it can convert too.

The stages are `build` (compiles the binary), `mithril2pq` (binary only) and
`notebook` (Python on top, the default). Building the notebook image builds
the binary stage as well, so building both costs little more than building
one. Python package versions are pinned in
[`notebooks/requirements.txt`](notebooks/requirements.txt).

Run a conversion with the binary-only image. Run it as your own user so the
output is owned by you, and mount the output (and cache) directories:

```sh
docker run --rm --user "$(id -u):$(id -g)" -v /data/mithril:/data \
  mithril2pq -mithril-archive preview -out /data/preview -cache-dir /data/cache/preview
```

Run JupyterLab on a converted dataset with the notebook image. The dataset is
mounted read-only at `/data`; mounting `notebooks/` at `/work` keeps notebook
edits on the host:

```sh
docker run -d --name mithril2pq-jupyter --memory 24g \
  -e JUPYTER_TOKEN="$(openssl rand -hex 16)" -e DUCKDB_MEMORY_LIMIT=16GB \
  -p 127.0.0.1:8888:8888 \
  -v /data/mithril/preview:/data:ro -v "$PWD/notebooks:/work" \
  mithril2pq-notebook
```

Then open `http://localhost:8888/lab/tree/explore.ipynb?token=<token>`. The
port is bound to localhost; from another machine, forward it with
`ssh -N -L 8888:127.0.0.1:8888 <host>`.

## Usage and options

```
mithril2pq -out DIR [options]
```

| Option | Default | Description |
|---|---|---|
| `-out DIR` | (required) | Output directory for the Parquet tables. Created, with its parents, if missing. If it already holds a mithril2pq dataset, the run updates it with the chunks it does not hold yet. |
| `-mithril-archive NET\|URL` | `mainnet` | Which Mithril aggregator to use: `mainnet`, `preprod`, `preview` (the official release/pre-release aggregators) or the base URL of any aggregator, e.g. `https://aggregator.example.org/aggregator`. |
| `-snapshot HASH` | latest | Convert this Cardano database snapshot (artifact hash) instead of the aggregator's latest. Useful to reproduce a run exactly. |
| `-cache-dir DIR` | none | Keep downloaded archives here, still compressed (`NNNNN.tar.zst`, one per immutable file), and reuse them on later runs. Created if missing. A cache directory belongs to one network: a marker file makes a run against another network refuse it. Without a cache, archives are held only in memory. |
| `-file-size SIZE` | `128MB` | Target size of each Parquet file. Accepts `300MB`, `3GB`, `1.5GiB`, `2k`, or a plain byte count. `KB`/`MB`/`GB`/`TB` (and `K`/`M`/`G`/`T`) are decimal; `KiB`/`MiB`/`GiB`/`TiB` are binary. A file can exceed the target by about one row group (row groups are at most 64 MB). |
| `-concurrency N` | `25` | Concurrent archive downloads. |
| `-buffer N` | 2 × `-concurrency` | Without `-cache-dir`: the most downloaded archives held in memory ahead of the writer. Bounds memory use. With a cache, downloads run ahead onto disk without a limit. |
| `-workers N` | CPU count | Concurrent chunk decoders. |
| `-checkpoint DURATION` | `30m` | Commit progress (finish the open files and update the manifest) at least this often, e.g. `10m`, `2h`. `0` commits only at the end. An interrupted run resumes from the last commit. |
| `-compression CODEC` | `zstd` | Parquet compression: `zstd`, `snappy`, `gzip` or `none`. All are readable by pyarrow, fastparquet and DuckDB. |
| `-last-chunk N` | snapshot's last | Stop after immutable file `N`. Converts a prefix of the chain, e.g. `-last-chunk 207` for mainnet's Byron era; a later run without it continues from there. |
| `-genesis-vkey KEY\|FILE` | pinned | Mithril genesis verification key the certificate chain must end at, as a key or a file holding one (Mithril's `genesis.vkey` JSON-hex format, or 64 hex digits). Required with an aggregator URL; overrides the built-in key of `mainnet`, `preprod` and `preview`. See [Verification](#verification). |

How the pipeline runs: archives are downloaded concurrently and run ahead of
decoding and writing. Decoding is parallel (`-workers`); tables are written in
chunk order, all tables at once.

Progress goes to stderr: once a second on a terminal, every ten seconds
otherwise.

```
[12m30s] chunks 3120/9401 (33.2%) | fetched 9401 (+6281 ahead), 0 B/s, 0 B | parquet 214 files, 26.9 GB | disk 41.2 MB/s | 5.10M blocks, 38.2M txs | ETA 25m10s
```

It shows chunks written, archives fetched (and how far ahead of the writer),
download rate and total, Parquet files and bytes written, disk write rate
(Parquet plus cache), blocks and transactions, and an estimated time left.

Interrupting: Ctrl-C (or SIGTERM) finishes the current chunk, commits, and
exits; a second Ctrl-C exits at once, removing temporary Parquet and partial
cache files without committing. Either way the next run resumes.

Errors are reported in plain terms, with a hint where there is a likely cause
(DNS or network failure, an unknown snapshot, a full disk, a permission
problem, or failed verification).

## Updating an existing dataset

Point mithril2pq at an output directory it has written before and it picks up
where that left off. The manifest (`_mithril2pq.json`) records the last chunk
(immutable file) converted; a new run fetches the aggregator's latest snapshot
and converts only the chunks after that one, appending their rows to the
existing tables. Nothing already converted is downloaded, decoded or
rewritten, except the small tail file described below.

```sh
# First run: converts the whole chain (mainnet: about 35 minutes with a warm cache).
mithril2pq -mithril-archive mainnet -out /data/mainnet-pq -cache-dir /data/mithril-cache/mainnet

# Any time later: converts only the chunks added since, typically minutes.
mithril2pq -mithril-archive mainnet -out /data/mainnet-pq -cache-dir /data/mithril-cache/mainnet
```

This makes it suitable for a cron job or systemd timer: each run brings the
dataset up to the latest certified snapshot. If nothing is new, the run says
so and exits. The same mechanism resumes a run that was interrupted (Ctrl-C,
crash, `kill -9`, reboot): it continues from the last checkpoint.

How the update is applied:

- Each table's last file is rewritten with the new rows appended if it is
  under `-file-size`; otherwise new rows go into a new file. So repeated small
  updates do not leave a trail of tiny files.
- Committed files are never modified in place. The rewritten file gets the
  next part number, and the old one is deleted only after the new manifest
  stops listing it. Readers that list files from the manifest always see a
  consistent dataset; readers that glob the directory can, during a commit,
  briefly see both the old and the new tail file.
- Before appending, mithril2pq checks that the new snapshot extends the same
  chain: the certified digests of the last chunk already converted must match
  those recorded in the manifest, and the first new block's previous hash must
  be the last block written.

A run refuses an output directory from another network, another chain, or a
different schema version. After a schema version change (a new mithril2pq
release that changes tables or columns), convert into a new directory; with
`-cache-dir`, that reuses the downloaded archives.

## Verification

For each snapshot, before converting anything:

- the certificate is for this snapshot (same beacon) and its protocol message
  carries the snapshot's Merkle root;
- the certificate's signed message is the hash of its protocol message;
- the certificate chain verifies back to a genesis certificate, as
  `mithril-client` verifies it (see below);
- the snapshot's digest list (SHA-256 of every immutable file) hashes to the
  certified Merkle root.

Certificate chain, for every certificate from the snapshot's back to genesis:

- its hash matches its content, and its signed message its protocol message;
- its STM multi-signature (Mithril's concatenation proof) verifies: every
  claimed lottery index is in range and won for the signer's stake, no index
  is claimed twice, at least `k` indexes are claimed, every signer is in the
  aggregate verification key's Merkle tree, and the aggregated BLS12-381
  signature verifies over the signed message;
- its epoch matches its protocol message, it is at most one epoch from the
  previous certificate, and the previous certificate's hash is its
  `previous_hash`;
- its aggregate verification key and protocol parameters are the ones the
  previous certificate signed for the next epoch (or equal the previous
  certificate's, within an epoch);
- the genesis certificate's Ed25519 signature verifies under the network's
  genesis verification key, with ed25519-dalek's `verify_strict` rules.

The genesis keys of mainnet, preprod and preview are built into mithril2pq,
copied from Mithril's `mithril-infra/configuration`; they are not fetched. With
an aggregator URL, pass the operator's key with `-genesis-vkey` (a key or a
file, in Mithril's `genesis.vkey` format or as 64 hex digits); a run without
it refuses to start.

The port follows Mithril release 2642.0, plus three checks Mithril added on
its main branch since: a lottery index must be below `m` (2642.0 accepts `m`
itself), the genesis certificate's aggregate verification key and parameters
must be the ones its signed message names, and the certificate after genesis
must be in the next epoch. Honest aggregators never produce what these
reject. Certificates using Mithril's experimental SNARK proofs are rejected
as unsupported; no public aggregator issues them.

A walk on mainnet checks about 130 certificates (some 110 KB each) and takes
about 20 seconds. The hashes of verified certificates are recorded, per
genesis key, in `_mithril2pq_verified_certificates.json` in the output
directory; a later run stops its walk at the first recorded certificate,
after checking that its content still matches its hash. A hash is recorded
only from a walk that reached genesis or a recorded certificate. Delete the
file to force a full walk.

For each immutable file:

- the archive's MD5 against the storage server's `x-goog-hash`, when sent;
- each of `.chunk`, `.primary` and `.secondary` against its certified SHA-256;
- every block's CRC32 against the secondary index;
- the primary index's EBB slot against each block's type tag;
- every decoded block's header hash against the secondary index;
- each chunk's first block's previous hash against the last block written.

A corrupt cached archive is downloaded again once before the run fails.

## Output layout

```
out/
  _mithril2pq.json          manifest: network, snapshot, last chunk, committed files
  block/part-000000.parquet
  tx/part-000000.parquet
  tx/part-000001.parquet
  ...
```

Each table is a directory of `part-NNNNNN.parquet` files in chain order. Read
a table by globbing its directory, e.g. `read_parquet('out/tx/part-*.parquet')`
in DuckDB or `pyarrow.dataset.dataset('out/tx')`. Every file carries
`mithril2pq.first_chunk`, `mithril2pq.last_chunk` and
`mithril2pq.schema_version` key-value metadata.

The files use only features the common Python readers support (checked with
pyarrow, fastparquet and DuckDB): format 2.6 logical types, version 1 data
pages, dictionary and plain encodings, statistics, and no page index, bloom
filters or byte-stream-split encoding. The Arrow schema is stored in each
file, so pyarrow restores exact types.

Crash safety: Parquet files are written under a temporary name and renamed
when complete; the manifest is replaced atomically last, at each checkpoint
and at the end. On start, files the manifest does not list and temporary
files are deleted. So after a crash the directory holds exactly the chunks the
manifest names. A lock file stops two runs from writing the same directory.

## Parquet schema

Schema version 2.

### Conventions

- **Keys are natural**: block hash, transaction hash, and positions within a
  transaction. Join child tables to `tx` on `tx_hash = tx.hash`, and `tx` to
  `block` on `tx.block_hash = block.hash`. Parquet has no constraints, so the
  keys listed are conventions that the writer upholds.
- **No nested types.** Every list is unwound into its own table with one row
  per element and a `position` (or index) column giving its order.
- **Hashes, keys and signatures** are `FIXED_LEN_BYTE_ARRAY` (pyarrow
  `fixed_size_binary`, DuckDB `BLOB`): 28 bytes for Blake2b-224 hashes (key,
  script and policy hashes), 32 for Blake2b-256 hashes (block, transaction,
  datum hashes) and Ed25519 keys, 64 for Ed25519 signatures. In DuckDB, compare
  with `from_hex('…')` and display with `lower(hex(col))`.
- **Amounts** are `UINT64` lovelace (or asset units) unless noted. Integers
  that can be negative (mint quantities, MIR deltas, execution units) are
  `INT64`.
- **Text values** with a fixed set of values (kinds, roles, types) are listed
  in the column description.
- The **Null** column marks nullable columns. Some optional body fields are
  also null when zero (noted per column).

Types below are Arrow types: `fsb(N)` is fixed-size binary of N bytes,
`binary` is variable-length bytes, `string` is UTF-8, `decimal(20,0)` is a
128-bit decimal.

### Blocks

#### `block_type`

Static lookup of the tag that wraps every block in a chunk file
(`[block_type, block]`). Written once, with the first chunk.

| Column | Type | Null | Description |
|---|---|---|---|
| `block_type` | uint8 | | Tag: 0 Byron epoch boundary block, 1 Byron, 2 Shelley, 3 Allegra, 4 Mary, 5 Alonzo, 6 Babbage, 7 Conway. |
| `era` | string | | Era name. |
| `is_ebb` | bool | | True for the Byron epoch boundary block (EBB) tag. |

#### `block`

One row per block in the immutable DB, including EBBs and blocks that failed
to decode. Key: `hash`.

| Column | Type | Null | Description |
|---|---|---|---|
| `hash` | fsb(32) | | Block header hash. |
| `chunk` | uint32 | | Immutable file (chunk) number the block is stored in. |
| `chunk_index` | uint32 | | Position of the block within its chunk, from 0. |
| `slot` | uint64 | yes | Absolute slot. Null for EBBs. |
| `ebb_epoch` | uint64 | yes | Epoch of an EBB. Null for other blocks. |
| `block_type` | uint8 | | Block type tag; see `block_type`. |
| `block_offset` | uint64 | | Byte offset of the block in the `.chunk` file. |
| `block_size` | uint64 | | Block size in bytes, including the type tag wrapper. |
| `header_offset` | uint16 | | Offset of the header within the block. |
| `header_size` | uint16 | | Header size in bytes. |
| `checksum` | uint32 | | CRC32 of the block from the secondary index (verified). |
| `block_number` | uint64 | yes | Block height. Null if the block could not be decoded. |
| `tx_count` | uint32 | yes | Number of transactions. Null if the block could not be decoded. |
| `decode_error` | string | yes | Why the block could not be decoded or tabulated. A block with an error has no rows in any other table. Null for good blocks. |

#### `block_header`

One row per decoded block. Key: `block_hash`. Byron headers have only
`block_hash`, `prev_hash`, `block_body_size` and `block_body_hash`; the other
columns start with Shelley.

| Column | Type | Null | Description |
|---|---|---|---|
| `block_hash` | fsb(32) | | The block (`block.hash`). |
| `prev_hash` | fsb(32) | yes | Previous block's hash. The first block's is the genesis hash. |
| `issuer_vkey` | fsb(32) | yes | Block issuer's cold verification key. The pool id is its Blake2b-224 hash. Null for Byron. |
| `vrf_vkey` | fsb(32) | yes | Issuer's VRF verification key. Null for Byron. |
| `block_body_size` | uint64 | | Body size in bytes, from the header. |
| `block_body_hash` | fsb(32) | yes | Body hash, from the header. Null for EBBs. |
| `protocol_major` | uint64 | yes | Protocol version the issuer's node signals (major). Null for Byron. |
| `protocol_minor` | uint64 | yes | Protocol version (minor). Some node implementations encode an identifier in it; Dingo sets its low byte to 69. |
| `signature` | fsb(448) | yes | KES signature over the header body. |
| `opcert_hot_vkey` | fsb(32) | yes | Operational certificate: hot (KES) verification key. |
| `opcert_sequence` | uint64 | yes | Operational certificate sequence number. |
| `opcert_kes_period` | uint64 | yes | Operational certificate start KES period. |
| `opcert_signature` | fsb(64) | yes | Operational certificate signature by the cold key. |

#### `block_header_vrf`

VRF certificates in a header: one row per certificate. Key:
`block_hash, kind`.

| Column | Type | Null | Description |
|---|---|---|---|
| `block_hash` | fsb(32) | | The block. |
| `kind` | string | | `vrf_result` (Babbage and later), or `nonce` and `leader` (Shelley to Alonzo). |
| `output` | fsb(64) | | VRF output. |
| `proof` | fsb(80) | | VRF proof. |

### Transactions

#### `tx`

One row per transaction. Key: `hash`.

| Column | Type | Null | Description |
|---|---|---|---|
| `hash` | fsb(32) | | Transaction id. |
| `block_hash` | fsb(32) | | Block containing it (`block.hash`). |
| `block_index` | uint32 | | Position in the block, from 0. |
| `valid` | bool | | False for a phase-2 invalid transaction (only its collateral is spent). |
| `fee` | uint64 | | Fee in lovelace. 0 for Byron transactions, which do not state their fee (it is inputs minus outputs). |
| `ttl` | uint64 | yes | Slot after which the transaction is invalid. Null if absent. |
| `validity_interval_start` | uint64 | yes | Slot before which the transaction is invalid. Null if absent. |
| `total_collateral` | uint64 | yes | Declared total collateral. Null if absent or zero. |
| `auxiliary_data_hash` | fsb(32) | yes | Hash of the auxiliary data (metadata). |
| `network_id` | uint8 | yes | Network id from the body. Null if absent. |
| `script_data_hash` | fsb(32) | yes | Hash of redeemers, datums and cost models. |
| `current_treasury_value` | uint64 | yes | Conway: declared treasury value. Null if absent or zero. |
| `donation` | uint64 | yes | Conway: treasury donation. Null if absent or zero. |

#### `tx_input`

Inputs, reference inputs and collateral inputs. Key:
`tx_hash, kind, position`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The spending transaction. |
| `kind` | string | | `spend`, `reference` or `collateral`. |
| `position` | uint32 | | Position in that input set, in the order gouroboros returns it. |
| `src_tx_hash` | fsb(32) | | Transaction that created the output being consumed. |
| `src_index` | uint32 | | Index of that output (`tx_output.output_index`). |

To find what an input spent, join `tx_output` on
`(tx_hash, output_index) = (src_tx_hash, src_index)`.

#### `tx_output`

Outputs, including the collateral return. Key: `tx_hash, output_index`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The creating transaction. |
| `output_index` | uint32 | | Output index. The collateral return has index `len(outputs)`, as the ledger assigns it. |
| `is_collateral_return` | bool | | True for the collateral return output. |
| `address` | string | | Address: bech32 for Shelley addresses, base58 for Byron. |
| `lovelace` | uint64 | | Ada amount in lovelace. |
| `datum_hash` | fsb(32) | yes | Datum hash. Null if none or if the datum is inline. |
| `has_inline_datum` | bool | | True if the output carries an inline datum, stored in `plutus_data_node` with `owner_kind = 'inline_datum'` and `owner_position = output_index`. |
| `script_ref_hash` | fsb(28) | yes | Hash of the reference script, stored in `script`. |

#### `tx_output_asset`

Native assets in outputs, one row per asset. Key:
`tx_hash, output_index, policy_id, asset_name`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `output_index` | uint32 | | The output. |
| `policy_id` | fsb(28) | | Minting policy id. |
| `asset_name` | binary | | Asset name (raw bytes, 0–32). |
| `quantity` | uint64 | | Quantity. |

#### `tx_mint`

Minting and burning. Key: `tx_hash, policy_id, asset_name`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `policy_id` | fsb(28) | | Minting policy id. |
| `asset_name` | binary | | Asset name. |
| `quantity` | int64 | | Amount minted; negative for a burn. |

#### `tx_required_signer`

Required signers (extra key hashes). Key: `tx_hash, position`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `position` | uint32 | | Position in the list. |
| `key_hash` | fsb(28) | | Required verification key hash. |

#### `tx_withdrawal`

Reward withdrawals. Key: `tx_hash, reward_account`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `reward_account` | string | | Reward (stake) address, bech32. |
| `amount` | uint64 | | Amount withdrawn, lovelace. |

### Scripts

#### `script`

Scripts attached to outputs as reference scripts, stored once per hash
(the first occurrence). Key: `hash`.

| Column | Type | Null | Description |
|---|---|---|---|
| `hash` | fsb(28) | | Script hash (`tx_output.script_ref_hash`). |
| `language` | string | | `native`, `plutus_v1`, `plutus_v2` or `plutus_v3`. |
| `bytes` | binary | yes | Plutus script bytes. Null for native scripts, whose structure is in `native_script_node` with `owner_script_hash = hash`. |

#### `tx_script`

Scripts in a transaction's witness set or auxiliary data. Key:
`tx_hash, source, language, position`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `source` | string | | `witness` or `auxiliary`. |
| `language` | string | | `native`, `plutus_v1`, `plutus_v2` or `plutus_v3`. |
| `position` | uint32 | | Position in that source's list for that language. |
| `bytes` | binary | yes | Plutus script bytes. Null for native scripts, whose structure is in `native_script_node` with owner `(tx_hash, source, position)`. |

#### `native_script_node`

Native (timelock/multisig) script trees, one row per node in pre-order. A
tree belongs either to a `script` row (`owner_script_hash` set) or to a
`tx_script` row (`owner_tx_hash`, `owner_source`, `owner_position` set). Key:
owner, `node_id`.

| Column | Type | Null | Description |
|---|---|---|---|
| `owner_script_hash` | fsb(28) | yes | Owning `script.hash`, for reference scripts. |
| `owner_tx_hash` | fsb(32) | yes | Owning transaction, for witness and auxiliary scripts. |
| `owner_source` | string | yes | Owning `tx_script.source`. |
| `owner_position` | uint32 | yes | Owning `tx_script.position`. |
| `node_id` | uint32 | | Node number in pre-order; the root is 0. |
| `parent_id` | uint32 | yes | Parent node. Null for the root. |
| `position` | uint32 | yes | Position among the parent's children. Null for the root. |
| `type` | string | | `signature`, `all`, `any`, `at_least`, `invalid_before`, `invalid_hereafter` or `require_guard`. |
| `key_hash` | fsb(28) | yes | `signature`: the required key hash. |
| `required` | int64 | yes | `at_least`: how many children must be satisfied. |
| `slot` | uint64 | yes | `invalid_before` / `invalid_hereafter`: the slot bound. |
| `credential_is_script` | bool | yes | `require_guard`: whether the guard credential is a script. |
| `credential_hash` | fsb(28) | yes | `require_guard`: the guard credential hash. |

### Certificates

#### `certificate`

One row per certificate, with the columns most kinds share. Key:
`tx_hash, cert_index`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `cert_index` | uint32 | | Position in the certificate list. |
| `cert_type` | string | | `stake_registration`, `stake_deregistration`, `stake_delegation`, `pool_registration`, `pool_retirement`, `genesis_key_delegation`, `move_instantaneous_rewards`, `registration`, `deregistration`, `vote_delegation`, `stake_vote_delegation`, `stake_registration_delegation`, `vote_registration_delegation`, `stake_vote_registration_delegation`, `auth_committee_hot`, `resign_committee_cold`, `drep_registration`, `drep_deregistration`, `drep_update`, or `unknown_<n>`. |
| `pool_key_hash` | fsb(28) | yes | Pool delegated to or retired (pool id). |
| `drep_kind` | string | yes | Vote delegation target: `key_hash`, `script_hash`, `always_abstain` or `always_no_confidence`. |
| `drep_hash` | fsb(28) | yes | DRep credential hash for `key_hash` / `script_hash`. |
| `amount` | uint64 | yes | Deposit paid or refunded, for the Conway kinds that state it. |
| `anchor_url` | string | yes | Anchor URL (DRep registration/update, committee resignation). |
| `anchor_data_hash` | fsb(32) | yes | Anchor data hash. |
| `retirement_epoch` | uint64 | yes | `pool_retirement`: epoch the pool retires. |
| `unrecognised` | string | yes | For `unknown_<n>`: the certificate as JSON. |

#### `certificate_credential`

Credentials a certificate names. Key: `tx_hash, cert_index, role`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `cert_index` | uint32 | | The certificate. |
| `role` | string | | `stake`, `drep`, `committee_cold` or `committee_hot`. |
| `is_script` | bool | | True for a script credential, false for a key hash. |
| `hash` | fsb(28) | | Credential hash. |

#### `pool_registration`

Pool parameters from `pool_registration` certificates. Key:
`tx_hash, cert_index`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `cert_index` | uint32 | | The certificate. |
| `operator` | fsb(28) | | Pool id (operator key hash). |
| `vrf_key_hash` | fsb(32) | | VRF key hash. |
| `pledge` | uint64 | | Pledge, lovelace. |
| `cost` | uint64 | | Fixed cost per epoch, lovelace. |
| `margin_numerator` | uint64 | | Margin as a fraction: numerator. |
| `margin_denominator` | uint64 | | Margin denominator. |
| `reward_account_key_hash` | fsb(28) | | Reward account's credential hash (the network tag and credential kind are not kept). |
| `metadata_url` | string | yes | Pool metadata URL. |
| `metadata_hash` | fsb(32) | yes | Pool metadata hash. |

#### `pool_owner`

Pool owners. Key: `tx_hash, cert_index, key_hash`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `cert_index` | uint32 | | The registration certificate. |
| `key_hash` | fsb(28) | | Owner's stake key hash. |

#### `pool_relay`

Pool relays. Key: `tx_hash, cert_index, position`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `cert_index` | uint32 | | The registration certificate. |
| `position` | uint32 | | Position in the relay list. |
| `kind` | string | | `single_host_addr`, `single_host_name` or `multi_host_name`. |
| `port` | uint16 | yes | Port. |
| `ipv4` | fsb(4) | yes | IPv4 address, network byte order. |
| `ipv6` | fsb(16) | yes | IPv6 address, network byte order. |
| `hostname` | string | yes | DNS name (A/AAAA for `single_host_name`, SRV for `multi_host_name`). |

#### `genesis_key_delegation`

Shelley-era genesis key delegations. Key: `tx_hash, cert_index`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `cert_index` | uint32 | | The certificate. |
| `genesis_hash` | fsb(28) | | Genesis key hash. |
| `genesis_delegate_hash` | fsb(28) | | Delegate key hash. |
| `vrf_key_hash` | fsb(32) | | Delegate's VRF key hash. |

#### `mir`

Move-instantaneous-rewards certificates (Shelley to Babbage). Key:
`tx_hash, cert_index`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `cert_index` | uint32 | | The certificate. |
| `source` | string | | Pot paid from: `reserves` or `treasury`. |
| `to_other_pot` | uint64 | yes | Amount moved to the other pot, for a pot-to-pot transfer. Null for a payment to stake credentials, listed in `mir_reward`. |

#### `mir_reward`

Stake credentials paid by a MIR certificate. Key:
`tx_hash, cert_index, is_script, cred_hash`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `cert_index` | uint32 | | The certificate. |
| `is_script` | bool | | Script credential. |
| `cred_hash` | fsb(28) | | Stake credential hash. |
| `amount` | int64 | | Lovelace; may be negative (a delta, from Alonzo). |

### Protocol parameters and governance

#### `param_update`

Protocol parameter changes: pre-Conway update proposals (one row per genesis
key per transaction, `genesis_hash` and `epoch` set) and Conway
`parameter_change` governance actions (`proposal_index` set). Each parameter
is a column, null when the update does not change it. A rational parameter is
two columns, `<name>_numerator` and `<name>_denominator`, both uint64. All
columns except `tx_hash` are nullable.

| Column | Type | Description |
|---|---|---|
| `tx_hash` | fsb(32) | The transaction. |
| `genesis_hash` | fsb(28) | Pre-Conway: the proposing genesis key. |
| `epoch` | uint64 | Pre-Conway: the epoch the proposal is for. |
| `proposal_index` | uint32 | Conway: the proposal (`proposal.proposal_index`). |
| `min_fee_a`, `min_fee_b` | uint64 | Linear fee coefficients (per byte, constant). |
| `max_block_body_size`, `max_tx_size`, `max_block_header_size` | uint64 | Size limits, bytes. |
| `key_deposit`, `pool_deposit` | uint64 | Stake key and pool deposits, lovelace. |
| `max_epoch` | uint64 | Maximum pool retirement epoch offset (eMax). |
| `n_opt` | uint64 | Target number of pools (k). |
| `a0` | rational | Pool pledge influence. |
| `rho` | rational | Monetary expansion. |
| `tau` | rational | Treasury cut. |
| `decentralization` | rational | Decentralisation parameter (d), pre-Babbage. |
| `extra_entropy_neutral` | bool | Extra entropy set to neutral, pre-Babbage. |
| `extra_entropy` | fsb(32) | Extra entropy nonce, pre-Babbage. |
| `protocol_major`, `protocol_minor` | uint64 | Protocol version (pre-Conway updates). |
| `min_utxo_value` | uint64 | Minimum UTxO value, Shelley to Mary. |
| `min_pool_cost` | uint64 | Minimum pool fixed cost. |
| `ada_per_utxo_byte` | uint64 | Lovelace per UTxO byte (per UTxO word in Alonzo). |
| `price_mem`, `price_steps` | rational | Script execution prices. |
| `max_tx_ex_mem`, `max_tx_ex_steps` | int64 | Per-transaction execution unit limits. |
| `max_block_ex_mem`, `max_block_ex_steps` | int64 | Per-block execution unit limits. |
| `max_value_size` | uint64 | Maximum serialised value size. |
| `collateral_percentage` | uint64 | Collateral as a percentage of the fee. |
| `max_collateral_inputs` | uint64 | Maximum collateral inputs. |
| `pvt_motion_no_confidence`, `pvt_committee_normal`, `pvt_committee_no_confidence`, `pvt_hard_fork_initiation`, `pvt_pp_security_group` | rational | Stake pool voting thresholds. |
| `dvt_motion_no_confidence`, `dvt_committee_normal`, `dvt_committee_no_confidence`, `dvt_update_to_constitution`, `dvt_hard_fork_initiation`, `dvt_pp_network_group`, `dvt_pp_economic_group`, `dvt_pp_technical_group`, `dvt_pp_gov_group`, `dvt_treasury_withdrawal` | rational | DRep voting thresholds. |
| `min_committee_size` | uint64 | Minimum constitutional committee size. |
| `committee_term_limit` | uint64 | Committee term limit, epochs. |
| `gov_action_validity_period` | uint64 | Governance action lifetime, epochs. |
| `gov_action_deposit` | uint64 | Governance action deposit, lovelace. |
| `drep_deposit` | uint64 | DRep deposit, lovelace. |
| `drep_inactivity_period` | uint64 | DRep activity period, epochs. |
| `min_fee_ref_script` | rational | Fee per reference script byte. |

#### `param_update_cost_model`

Cost models in a parameter update, one row per model entry. Key: the
`param_update` row's key, `language, position`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `genesis_hash` | fsb(28) | yes | Pre-Conway: the proposing genesis key. |
| `proposal_index` | uint32 | yes | Conway: the proposal. |
| `language` | uint8 | | 0 PlutusV1, 1 PlutusV2, 2 PlutusV3. |
| `position` | uint32 | | Index in the cost model. |
| `value` | int64 | | Cost model entry. |

#### `proposal`

Conway governance action proposals. Key: `tx_hash, proposal_index` (the
governance action id).

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `proposal_index` | uint32 | | Position in the proposal list. |
| `deposit` | uint64 | | Deposit, lovelace. |
| `return_address` | string | | Reward address the deposit returns to. |
| `anchor_url` | string | | Anchor URL. |
| `anchor_data_hash` | fsb(32) | | Anchor data hash. |
| `action_type` | string | | `parameter_change`, `hard_fork_initiation`, `treasury_withdrawals`, `no_confidence`, `update_committee`, `new_constitution` or `info`. |
| `prev_action_tx_hash` | fsb(32) | yes | Previous governance action of the same purpose: transaction. |
| `prev_action_index` | uint32 | yes | Previous governance action: index. |
| `policy_hash` | fsb(28) | yes | Guardrails script hash (`parameter_change`, `treasury_withdrawals`). |
| `protocol_major` | uint64 | yes | `hard_fork_initiation`: target version (major). |
| `protocol_minor` | uint64 | yes | `hard_fork_initiation`: target version (minor). |
| `quorum_numerator` | uint64 | yes | `update_committee`: new quorum numerator. |
| `quorum_denominator` | uint64 | yes | `update_committee`: new quorum denominator. |
| `constitution_url` | string | yes | `new_constitution`: anchor URL. |
| `constitution_hash` | fsb(32) | yes | `new_constitution`: anchor data hash. |
| `unrecognised` | string | yes | An action of unknown type, as JSON. |

Parameter changes are in `param_update`, treasury withdrawals in
`proposal_withdrawal`, committee changes in `proposal_committee_add` and
`proposal_committee_remove`.

#### `proposal_withdrawal`

`treasury_withdrawals` payees. Key: `tx_hash, proposal_index, reward_account`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `proposal_index` | uint32 | | The proposal. |
| `reward_account` | string | | Reward address paid. |
| `amount` | uint64 | | Lovelace. |

#### `proposal_committee_remove`

`update_committee` members removed. Key:
`tx_hash, proposal_index, is_script, cred_hash`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `proposal_index` | uint32 | | The proposal. |
| `is_script` | bool | | Script credential. |
| `cred_hash` | fsb(28) | | Cold credential hash. |

#### `proposal_committee_add`

`update_committee` members added. Key:
`tx_hash, proposal_index, is_script, cred_hash`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `proposal_index` | uint32 | | The proposal. |
| `is_script` | bool | | Script credential. |
| `cred_hash` | fsb(28) | | Cold credential hash. |
| `expires_epoch` | uint64 | | Epoch the membership expires. |

#### `vote`

Conway votes. Key: `tx_hash, voter_role, voter_hash, action_tx_hash,
action_index`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `voter_role` | string | | `constitutional_committee_hot_key`, `constitutional_committee_hot_script`, `drep_key`, `drep_script` or `stake_pool`. |
| `voter_hash` | fsb(28) | | Voter credential hash (pool id for `stake_pool`). |
| `action_tx_hash` | fsb(32) | | Governance action voted on: `proposal.tx_hash`. |
| `action_index` | uint32 | | Governance action: `proposal.proposal_index`. |
| `vote` | string | | `yes`, `no` or `abstain`. |
| `anchor_url` | string | yes | Vote rationale anchor URL. |
| `anchor_data_hash` | fsb(32) | yes | Anchor data hash. |

### Witnesses

#### `vkey_witness`

Key witnesses (signatures). Key: `tx_hash, position`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `position` | uint32 | | Position in the witness list. |
| `vkey` | fsb(32) | | Ed25519 verification key. |
| `chain_code` | fsb(32) | yes | Byron only: chain code of an extended key. A Byron key witness signs with a 64-byte extended public key, stored as `vkey` plus `chain_code`. Null for Shelley-era keys and Byron redeem (AVVM) witnesses. |
| `signature` | fsb(64) | | Ed25519 signature. |

#### `bootstrap_witness`

Shelley-era witnesses for Byron addresses. Key: `tx_hash, position`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `position` | uint32 | | Position in the witness list. |
| `public_key` | fsb(32) | | Ed25519 public key. |
| `signature` | fsb(64) | | Signature. |
| `chain_code` | fsb(32) | | Chain code of the extended key. |
| `attributes` | binary | | Byron address attributes (CBOR). |

#### `plutus_datum_witness`

Datums in the witness set. The datum itself is in `plutus_data_node` with
`owner_kind = 'witness_datum'` and `owner_position = position`. Key:
`tx_hash, position`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `position` | uint32 | | Position in the datum list. |

#### `redeemer`

Redeemers. The redeemer data is in `plutus_data_node` with
`owner_kind = 'redeemer'` and `owner_position = position`. Key:
`tx_hash, position`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `position` | uint32 | | Position in the redeemer list. |
| `purpose` | string | | `spend`, `mint`, `certify`, `reward`, `vote`, `propose` or `guard`. |
| `idx` | uint32 | | Index of the item redeemed within its purpose (input, policy, certificate, …). |
| `mem` | int64 | | Execution units: memory. |
| `steps` | int64 | | Execution units: CPU steps. |

### Data trees

`plutus_data_node`, `metadata_node` and `native_script_node` store trees with
one row per node in pre-order: `node_id` (root 0), `parent_id` (null for the
root), `position` within the parent, and for map entries `map_role` (`key` or
`value`, with a key and its value sharing a `position`).

#### `plutus_data_node`

Plutus data: inline datums, witness datums and redeemer data. Key:
`tx_hash, owner_kind, owner_position, node_id`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `owner_kind` | string | | `inline_datum` (an output's), `witness_datum` or `redeemer`. |
| `owner_position` | uint32 | | `tx_output.output_index`, `plutus_datum_witness.position` or `redeemer.position`. |
| `node_id` | uint32 | | Node number in pre-order; the root is 0. |
| `parent_id` | uint32 | yes | Parent node. Null for the root. |
| `position` | uint32 | yes | Position among the parent's children (map entry index for maps). |
| `map_role` | string | yes | `key` or `value` for a map entry's children. |
| `kind` | string | | `constr`, `map`, `list`, `int` or `bytes`. |
| `constr_tag` | uint64 | yes | `constr`: constructor index. |
| `int_value` | string | yes | `int`: the integer in decimal (Plutus integers are unbounded). |
| `bytes_value` | binary | yes | `bytes`: the bytes. |

#### `metadata_node`

Transaction metadata, one tree per top-level label. Key:
`tx_hash, label, node_id`.

| Column | Type | Null | Description |
|---|---|---|---|
| `tx_hash` | fsb(32) | | The transaction. |
| `label` | uint64 | | Top-level metadata label (e.g. 674 for messages, 721 for NFT metadata). |
| `node_id` | uint32 | | Node number in pre-order; the root is 0. |
| `parent_id` | uint32 | yes | Parent node. Null for the root. |
| `position` | uint32 | yes | Position among the parent's children. |
| `map_role` | string | yes | `key` or `value` for a map entry's children. |
| `kind` | string | | `int`, `bytes`, `text`, `list` or `map`. |
| `int_value` | decimal(20,0) | yes | `int`: the integer (metadata integers range over ±2⁶⁴). |
| `bytes_value` | binary | yes | `bytes`: the bytes. |
| `text_value` | string | yes | `text`: the string. |

### What the tables do not show

Blocks are decoded with gouroboros, and the tables inherit its normalisation:

- assets and mint entries with a quantity of zero are dropped;
- duplicate redeemer keys are merged;
- votes, withdrawals, MIR rewards and committee additions lose their wire
  order (they are keyed by content);
- a pool registration's reward account is its credential hash only;
- Byron blocks get only what gouroboros's era-independent interfaces expose:
  inputs, outputs and key witnesses, but not Byron delegation or update
  payloads, and no stated fee.

A block gouroboros cannot decode, or whose values do not fit the schema, still
gets its `block` row, with `decode_error` set, and no other rows.

## Exploring the data

[`notebooks/explore.ipynb`](notebooks/explore.ipynb) (in the notebook image)
creates a DuckDB view per table over its Parquet files and provides:

- `sql("…")`: any query over the views, returned as a pandas DataFrame.
  DuckDB filters, joins and aggregates within its memory limit; only the
  result becomes a DataFrame. Use this for large tables.
- `load(name, columns=…, where=…, limit=…)` and `tables.<name>`: a table, or
  part of it, as a DataFrame, with hashes as hex strings. These materialise
  every matching row in pandas, outside DuckDB's memory limit: fine for small
  tables and test networks, but mainnet's `tx`, `tx_output`, `tx_input` and
  tree tables run to tens or hundreds of GB.
- `hx(col)`: SQL macro, a blob as lowercase hex.
- `epoch(slot)`: SQL macro, a slot's epoch for the dataset's network.
- Example plots: blocks and transactions per epoch, the fee distribution, and
  blocks by node implementation.

`MITHRIL2PQ_DATA` sets the dataset directory (default `/data`) and
`DUCKDB_MEMORY_LIMIT` DuckDB's memory limit (default `16GB`); keep the
container's memory limit comfortably above it.

## License

Apache License 2.0; see [LICENSE](LICENSE).
