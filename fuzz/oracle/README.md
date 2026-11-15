# Differential-fuzzing oracle

`mithril-oracle` answers questions about Mithril's own Rust crates so the
Go port in `internal/mithril/stm` and `internal/mithril/chain` can be
compared with them. It is test tooling: the `mithril2pq` binary never links
or runs it.

It is built from:

- **mithril-stm 0.13.0** from crates.io (byte-identical to `mithril-stm/src`
  at Mithril release 2642.0, commit
  `e85df3ddc52b528c7b9ddbdddf1941fec6d5f348`), with
  [`oracle-internals.patch`](oracle-internals.patch) applied;
- **mithril-common 0.8.3** from crates.io, resolved to the same patched
  mithril-stm;
- the feature set mithril-client builds: `num-integer-backend`, no `snark`,
  no `rug-backend`; serde_json 1.0.151 without `float_roundtrip`.

`Cargo.lock` was seeded from the release's own lock file, so blst,
serde_json, ed25519-dalek, chrono and fixed are the versions Mithril 2642.0
ships.

## The patch

`is_lottery_won`, `evaluate_dense_mapping` and the batch-path membership
check are crate-private in mithril-stm 0.13.0, and its
`benchmark-internals` feature does not compile without `snark`. The patch
adds an `oracle-internals` feature and one module re-exporting those
functions. It changes no verification code. `build.sh` unpacks the crate
afresh and applies the patch on every build, and fails if it no longer
applies, which is the signal to re-audit after an upstream bump.

Mithril is Copyright 2022 Input Output (Hong Kong) Ltd., licensed under the
Apache License 2.0; see the repository's `NOTICE`.

## Building

```sh
fuzz/oracle/build.sh        # prints the binary's path on its last line
```

The crate is downloaded and checked against its crates.io checksum, then
built with the host's `cargo` if there is one, else in
`rust:1.100.0-slim-bookworm` (pinned by digest) through Docker
(`ORACLE_BUILD=docker|native` forces either). Everything lands under
`~/.cache/mithril2pq-oracle` (`MITHRIL2PQ_ORACLE_CACHE` overrides it):
`target/` (about 200 MB), `cargo-home/` (about 140 MB) and the downloaded
crate. The unpacked, patched crate goes to `fuzz/oracle/vendor/`, which git
ignores. A cold build takes about 20 s on 16 cores; the binary is
dynamically linked against glibc 2.36 and runs on any newer glibc.

## Protocol

One JSON request per line on stdin, one JSON answer per line on stdout, in
order. Byte strings are lower-case hex; floats are the 16 hex digits of
their IEEE-754 bits, so no JSON float parser stands between the fuzzer and
the code under test; integers are JSON numbers.

Request: `{"id": n, "op": "<op>", ...inputs}`. Answer:

| Field | Meaning |
|---|---|
| `id` | the request's id |
| `ok` | `true` if the operation succeeded |
| `out` | the result when `ok` (a string, a boolean or an object, per op) |
| `err` | the error class when not `ok` |
| `aux` | intermediate values a divergence rule needs (not compared) |
| `detail` | the full error text (not compared) |
| `panic` | `true` if Rust panicked (`err` is then `panic`, `detail` the message) |
| `fatal` | the request itself was malformed: a harness bug |

Error classes are the Rust error variant's name: the first
`CertificateVerifierError` in the error chain if there is one, else the
root cause (`IndexBoundFailed`, `LotteryLost`, `IndexNotUnique`,
`NotEnoughSignatures`, `BatchPathInvalid`, `SignatureInvalid`,
`SerializationError`, `ZeroTotalStake`, `PhiFValueOutOfRange`,
`CertificateHashUnmatch`, ...). Parsing failures are `serde` (with a
`serde_avk`/`serde_proof` stage for `proof_verify`), certificate conversion
failures `convert` (prefixed `prev_` for the previous certificate).

| Op | Inputs | `out` | Rust code |
|---|---|---|---|
| `ping` | | `"pong"` | |
| `sig_decode`, `vk_decode` | `b` | canonical re-encoding | `BlsSignature`/`BlsVerificationKey::from_canonical_bytes` |
| `avk_json`, `proof_json` | `s` (JSON text) | serde_json re-encoding | `AggregateVerificationKeyForConcatenation`, `AggregateSignature` (untagged) |
| `parse_f64` | `s` | float bits | `serde_json::from_str::<f64>` |
| `ln1m` | `phi` | float bits of `(1 - phi).ln()` | platform libm |
| `lottery` | `phi`, `ev` (64 bytes), `stake`, `total` | `true`/`false`; `aux` = `ln1m` bits | `is_lottery_won` |
| `ev` | `sigma`, `msgp`, `index` | the 64-byte ticket | `evaluate_dense_mapping` |
| `batch_path` | `root`, `nr_leaves`, `leaves` (`[[vk, stake]]`), `values`, `indices` | `""` | `verify_leaves_membership_from_batch_path` |
| `proof_verify` | `avk`, `proof` (JSON text), `msg`, `m`, `k`, `phi` | `""` | `AggregateSignature::verify` |
| `aggregate` | `vks`, `sigs` | `"<vk>:<sig>"` | `BlsSignature::aggregate` |
| `verify_aggregate` | `msg`, `vks`, `sigs` | `""` | `BlsSignature::verify_aggregate` |
| `gen` | `seed`, `stakes`, `m`, `k`, `phi`, `msg` | `{avk, sigs, proof}` | seeded `Initializer`/`KeyRegistration`/`Signer`/`Clerk` |
| `params_hash` | `k`, `m`, `phi` | hash | `ProtocolParameters::compute_hash` |
| `cert_hash` | `cert` (CertificateMessage JSON) | `{hash, metadata, protocol_message, parameters}` | `Certificate::try_compute_hash` and the part hashes |
| `cert_verify` | `cert`, and `prev` or `genesis_key` (genesis.vkey form) | `""` | `MithrilCertificateVerifier::verify_standard_certificate` / `verify_genesis_certificate` |
| `ed25519_verify` | `vk`, `msg`, `sig` | `""` | ed25519-dalek `verify_strict` |

The Go side of every op, the comparison and the accepted divergences are in
`internal/mithril/difftest`.
