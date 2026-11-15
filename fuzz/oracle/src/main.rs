// SPDX-License-Identifier: Apache-2.0
//
// Differential-fuzzing oracle for mithril2pq. Reads one JSON request per
// line on stdin and writes one JSON answer per line on stdout, computed by
// mithril-stm 0.13.0 and mithril-common 0.8.3 (Mithril release 2642.0,
// Copyright 2022 Input Output (Hong Kong) Ltd., Apache-2.0). The protocol is
// documented in README.md next to this file.

use std::io::{BufRead, Write};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use anyhow::{Context as _, anyhow, bail};
use async_trait::async_trait;
use mithril_common::certificate_chain::{
    CertificateRetriever, CertificateRetrieverError, CertificateVerifier, CertificateVerifierError,
    MithrilCertificateVerifier,
};
use mithril_common::crypto_helper::GenesisVerifier;
use mithril_common::entities::{Certificate, ProtocolParameters};
use mithril_common::messages::CertificateMessage;
use mithril_stm::oracle_internals::{self as oi, BlsSignature, BlsVerificationKey};
use mithril_stm::{
    AggregateSignature, AggregateSignatureType, AggregateVerificationKey,
    AggregateVerificationKeyForConcatenation, AncillaryGenesisData, AncillaryProofInput, Clerk,
    Initializer, KeyRegistration, MithrilMembershipDigest, Parameters, Signer,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Value, json};

type D = MithrilMembershipDigest;

/// The error's variant name: the first CertificateVerifierError in the
/// chain if there is one, else the root cause's Debug up to its payload.
fn class(e: &anyhow::Error) -> String {
    for c in e.chain() {
        if let Some(v) = c.downcast_ref::<CertificateVerifierError>() {
            return variant(&format!("{v:?}"));
        }
    }
    variant(&format!("{:?}", e.root_cause()))
}

fn variant(s: &str) -> String {
    s.split(['(', ' ', '{']).next().unwrap_or("").to_string()
}

fn ok(out: impl Into<Value>) -> Value {
    json!({"ok": true, "out": out.into()})
}

fn reject(err: &str, detail: String) -> Value {
    json!({"ok": false, "err": err, "detail": detail})
}

fn fail(e: anyhow::Error) -> Value {
    reject(&class(&e), format!("{e:#}"))
}

fn field<'a>(q: &'a Value, k: &str) -> anyhow::Result<&'a Value> {
    q.get(k).ok_or_else(|| anyhow!("request has no {k:?}"))
}

fn text<'a>(q: &'a Value, k: &str) -> anyhow::Result<&'a str> {
    field(q, k)?.as_str().ok_or_else(|| anyhow!("{k:?} is not a string"))
}

fn bytes(q: &Value, k: &str) -> anyhow::Result<Vec<u8>> {
    hex::decode(text(q, k)?).with_context(|| format!("{k:?} is not hex"))
}

fn u64_of(q: &Value, k: &str) -> anyhow::Result<u64> {
    field(q, k)?.as_u64().ok_or_else(|| anyhow!("{k:?} is not a u64"))
}

/// Floats travel as 16 hex digits of their IEEE-754 bits so that no JSON
/// float parser sits between the fuzzer and the code under test.
fn f64_of(q: &Value, k: &str) -> anyhow::Result<f64> {
    Ok(f64::from_bits(u64::from_str_radix(text(q, k)?, 16)?))
}

fn bits(f: f64) -> String {
    format!("{:016x}", f.to_bits())
}

fn hex_list(q: &Value, k: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    field(q, k)?
        .as_array()
        .ok_or_else(|| anyhow!("{k:?} is not an array"))?
        .iter()
        .map(|v| hex::decode(v.as_str().unwrap_or("?")).map_err(Into::into))
        .collect()
}

fn params(q: &Value) -> anyhow::Result<Parameters> {
    Ok(Parameters { m: u64_of(q, "m")?, k: u64_of(q, "k")?, phi_f: f64_of(q, "phi")? })
}

fn decode_keys_sigs(q: &Value) -> anyhow::Result<Result<(Vec<BlsVerificationKey>, Vec<BlsSignature>), Value>> {
    let mut vks = vec![];
    for b in hex_list(q, "vks")? {
        match BlsVerificationKey::from_canonical_bytes(&b) {
            Ok(v) => vks.push(v),
            Err(e) => return Ok(Err(reject("decode", format!("{e:#}")))),
        }
    }
    let mut sigs = vec![];
    for b in hex_list(q, "sigs")? {
        match BlsSignature::from_canonical_bytes(&b) {
            Ok(s) => sigs.push(s),
            Err(e) => return Ok(Err(reject("decode", format!("{e:#}")))),
        }
    }
    Ok(Ok((vks, sigs)))
}

/// Polls a future that never waits on I/O: every await in the verifier is
/// on in-memory work or on the retriever below, which answers immediately.
fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

struct NoRetriever;

#[async_trait]
impl CertificateRetriever for NoRetriever {
    async fn get_certificate_details(&self, h: &str) -> Result<Certificate, CertificateRetrieverError> {
        Err(CertificateRetrieverError(anyhow!("the oracle fetches nothing ({h})")))
    }
}

/// Parses a certificate as mithril-client does: CertificateMessage JSON,
/// then the conversion that decodes its keys and signatures.
fn certificate(s: &str) -> Result<Certificate, Value> {
    let msg: CertificateMessage = serde_json::from_str(s).map_err(|e| reject("serde", e.to_string()))?;
    Certificate::try_from(msg).map_err(|e| reject("convert", format!("{e:#}")))
}

fn handle(q: &Value) -> anyhow::Result<Value> {
    Ok(match text(q, "op")? {
        "ping" => ok("pong"),
        "sig_decode" => match BlsSignature::from_canonical_bytes(&bytes(q, "b")?) {
            Ok(s) => ok(hex::encode(s.to_canonical_bytes())),
            Err(e) => fail(e),
        },
        "vk_decode" => match BlsVerificationKey::from_canonical_bytes(&bytes(q, "b")?) {
            Ok(v) => ok(hex::encode(v.to_canonical_bytes())),
            Err(e) => fail(e),
        },
        "avk_json" => match serde_json::from_str::<AggregateVerificationKeyForConcatenation<D>>(text(q, "s")?) {
            Ok(a) => ok(serde_json::to_string(&a)?),
            Err(e) => reject("serde", e.to_string()),
        },
        "proof_json" => match serde_json::from_str::<AggregateSignature<D>>(text(q, "s")?) {
            Ok(a) => ok(serde_json::to_string(&a)?),
            Err(e) => reject("serde", e.to_string()),
        },
        "parse_f64" => match serde_json::from_str::<f64>(text(q, "s")?) {
            Ok(f) => ok(bits(f)),
            Err(e) => reject("serde", e.to_string()),
        },
        "ln1m" => ok(bits((1.0 - f64_of(q, "phi")?).ln())),
        "lottery" => {
            let ev: [u8; 64] = bytes(q, "ev")?.try_into().map_err(|_| anyhow!("ev is not 64 bytes"))?;
            let phi = f64_of(q, "phi")?;
            let mut a = match oi::is_lottery_won(phi, ev, u64_of(q, "stake")?, u64_of(q, "total")?) {
                Ok(w) => ok(w),
                Err(e) => fail(e),
            };
            // ln(1 - phi_f) comes from the platform libm; the harness uses
            // it to tell libm differences from lottery differences.
            a["aux"] = json!(bits((1.0 - phi).ln()));
            a
        }
        "ev" => match BlsSignature::from_canonical_bytes(&bytes(q, "sigma")?) {
            Ok(s) => ok(hex::encode(oi::evaluate_dense_mapping(&s, &bytes(q, "msgp")?, u64_of(q, "index")?))),
            Err(e) => fail(e),
        },
        "batch_path" => {
            let mut leaves = vec![];
            for l in field(q, "leaves")?.as_array().ok_or_else(|| anyhow!("leaves"))? {
                let vk = hex::decode(l[0].as_str().unwrap_or("?"))?;
                let vk = match BlsVerificationKey::from_canonical_bytes(&vk) {
                    Ok(v) => v,
                    Err(e) => return Ok(reject("decode", format!("{e:#}"))),
                };
                leaves.push((vk, l[1].as_u64().ok_or_else(|| anyhow!("leaf stake"))?));
            }
            // The path is built through its serde form, the only public
            // constructor; the hasher is PhantomData and must be null.
            let path = serde_json::from_value(json!({
                "values": hex_list(q, "values")?,
                "indices": field(q, "indices")?,
                "hasher": null,
            }))?;
            let nr_leaves = usize::try_from(u64_of(q, "nr_leaves")?)?;
            match oi::verify_batch_path(bytes(q, "root")?, nr_leaves, &leaves, &path) {
                Ok(()) => ok(""),
                Err(e) => fail(e),
            }
        }
        "proof_verify" => {
            let avk: AggregateVerificationKeyForConcatenation<D> = match serde_json::from_str(text(q, "avk")?) {
                Ok(a) => a,
                Err(e) => return Ok(reject("serde_avk", e.to_string())),
            };
            let proof: AggregateSignature<D> = match serde_json::from_str(text(q, "proof")?) {
                Ok(p) => p,
                Err(e) => return Ok(reject("serde_proof", e.to_string())),
            };
            match proof.verify(&bytes(q, "msg")?, &AggregateVerificationKey::new(avk), &params(q)?, None, None) {
                Ok(()) => ok(""),
                Err(e) => fail(e),
            }
        }
        "aggregate" => match decode_keys_sigs(q)? {
            Err(v) => v,
            Ok((vks, sigs)) => match BlsSignature::aggregate(&vks, &sigs) {
                Ok((vk, s)) => ok(format!(
                    "{}:{}",
                    hex::encode(vk.to_canonical_bytes()),
                    hex::encode(s.to_canonical_bytes())
                )),
                Err(e) => fail(e),
            },
        },
        "verify_aggregate" => match decode_keys_sigs(q)? {
            Err(v) => v,
            Ok((vks, sigs)) => match BlsSignature::verify_aggregate(&bytes(q, "msg")?, &vks, &sigs) {
                Ok(()) => ok(""),
                Err(e) => fail(e),
            },
        },
        "gen" => generate(q)?,
        "params_hash" => {
            let p = ProtocolParameters::new(u64_of(q, "k")?, u64_of(q, "m")?, f64_of(q, "phi")?);
            ok(p.compute_hash())
        }
        "cert_hash" => match certificate(text(q, "cert")?) {
            Err(v) => v,
            Ok(c) => match c.try_compute_hash() {
                Ok(h) => ok(json!({
                    "hash": h,
                    "metadata": c.metadata.compute_hash(),
                    "protocol_message": c.protocol_message.compute_hash(),
                    "parameters": c.metadata.protocol_parameters.compute_hash(),
                })),
                Err(e) => fail(e),
            },
        },
        "cert_verify" => {
            let cert = match certificate(text(q, "cert")?) {
                Ok(c) => c,
                Err(v) => return Ok(v),
            };
            let key = q.get("genesis_key").and_then(Value::as_str).unwrap_or("");
            let genesis = if key.is_empty() {
                GenesisVerifier::create_deterministic_verifier()
            } else {
                match GenesisVerifier::try_from_hex(key) {
                    Ok(g) => g,
                    Err(e) => return Ok(reject("genesis_key", format!("{e:#}"))),
                }
            };
            let logger = slog::Logger::root(slog::Discard, slog::o!());
            let v = MithrilCertificateVerifier::new(logger, Arc::new(NoRetriever), Arc::new(genesis));
            let r = match q.get("prev").and_then(Value::as_str) {
                None => block_on(v.verify_genesis_certificate(&cert)),
                Some(p) => match certificate(p) {
                    Ok(p) => block_on(v.verify_standard_certificate(&cert, &p)),
                    Err(mut v) => {
                        v["err"] = json!("prev_".to_string() + v["err"].as_str().unwrap_or(""));
                        return Ok(v);
                    }
                },
            };
            match r {
                Ok(()) => ok(""),
                Err(e) => fail(e),
            }
        }
        "ed25519_verify" => {
            let vk: [u8; 32] = bytes(q, "vk")?.try_into().map_err(|_| anyhow!("vk is not 32 bytes"))?;
            let sig: [u8; 64] = bytes(q, "sig")?.try_into().map_err(|_| anyhow!("sig is not 64 bytes"))?;
            match ed25519_dalek::VerifyingKey::from_bytes(&vk) {
                Err(e) => reject("key", e.to_string()),
                Ok(vk) => match vk.verify_strict(&bytes(q, "msg")?, &ed25519_dalek::Signature::from_bytes(&sig)) {
                    Ok(()) => ok(""),
                    Err(e) => reject("signature", e.to_string()),
                },
            }
        }
        op => bail!("unknown op {op:?}"),
    })
}

/// Seeded key generation, signing and aggregation, in the order Mithril's
/// own tests use: one ChaCha20 stream drawn by each Initializer in turn.
fn generate(q: &Value) -> anyhow::Result<Value> {
    let seed: [u8; 32] = bytes(q, "seed")?.try_into().map_err(|_| anyhow!("seed is not 32 bytes"))?;
    let params = params(q)?;
    let msg = bytes(q, "msg")?;
    let stakes: Vec<u64> = serde_json::from_value(field(q, "stakes")?.clone())?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let inits: Vec<Initializer> = stakes.iter().map(|s| Initializer::new(params, *s, &mut rng)).collect();
    let mut reg = KeyRegistration::initialize();
    for i in &inits {
        if let Err(e) = reg.register(i.stake, &i.get_verification_key_proof_of_possession_for_concatenation()) {
            return Ok(fail(e));
        }
    }
    let closed = match reg.close_registration(&params) {
        Ok(c) => c,
        Err(e) => return Ok(fail(e)),
    };
    let mut signers: Vec<Signer<D>> = vec![];
    for i in inits {
        match i.try_create_signer(&closed) {
            Ok(s) => signers.push(s),
            Err(e) => return Ok(fail(e)),
        }
    }
    let mut sigs = vec![];
    let mut out_sigs = vec![];
    for s in &signers {
        match s.create_single_signature(&msg) {
            Ok(sig) => {
                out_sigs.push(json!({
                    "sigma": hex::encode(sig.get_concatenation_signature_sigma().to_canonical_bytes()),
                    "indexes": sig.get_concatenation_signature_indices(),
                    "signer_index": sig.signer_index,
                }));
                sigs.push(sig);
            }
            Err(e) => out_sigs.push(json!({"err": class(&e)})),
        }
    }
    let clerk = Clerk::<D>::new_clerk_from_closed_key_registration(&params, &closed);
    let avk = clerk
        .compute_aggregate_verification_key()
        .to_concatenation_aggregate_verification_key()
        .clone();
    let proof = match clerk.aggregate_signatures_with_type(
        &sigs,
        &msg,
        AggregateSignatureType::Concatenation,
        AncillaryProofInput::new(None, AncillaryGenesisData::new()),
    ) {
        Ok((p, _)) => json!({"json": serde_json::to_string(&p)?}),
        Err(e) => json!({"err": class(&e)}),
    };
    Ok(ok(json!({
        "avk": serde_json::to_string(&avk)?,
        "sigs": out_sigs,
        "proof": proof,
    })))
}

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    // Panics are answers ("panic": true), not noise on stderr.
    std::panic::set_hook(Box::new(|_| {}));
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let q: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => json!({"fatal": format!("request is not JSON: {e}")}),
        };
        let mut a = if q.get("fatal").is_some() {
            q.clone()
        } else {
            match std::panic::catch_unwind(|| handle(&q)) {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => json!({"fatal": format!("{e:#}")}),
                Err(p) => {
                    let msg = p
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                        .unwrap_or_default();
                    json!({"ok": false, "panic": true, "err": "panic", "detail": msg})
                }
            }
        };
        a["id"] = q.get("id").cloned().unwrap_or(Value::Null);
        if writeln!(out, "{a}").and_then(|_| out.flush()).is_err() {
            break;
        }
    }
}
