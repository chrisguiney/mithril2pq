// SPDX-License-Identifier: Apache-2.0
//
// Ported from mithril-common/src/certificate_chain/certificate_verifier.rs
// and mithril-client/src/certificate_client/verify.rs in
// IntersectMBO/mithril at release 2642.0
// (e85df3ddc52b528c7b9ddbdddf1941fec6d5f348), with three checks Mithril's
// main branch added after that release (see verifyGenesis and
// verifyStandard).
// Copyright 2022 Input Output (Hong Kong) Ltd.
// Modifications: translated from Rust to Go.

package chain

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// Errors for each rule a certificate or link can break.
var (
	ErrInfiniteLoop             = errors.New("certificate chains to itself")
	ErrHashMismatch             = errors.New("certificate hash does not match its content")
	ErrProtocolMessageMismatch  = errors.New("signed message does not match the protocol message")
	ErrMultiSignature           = errors.New("multi-signature is invalid")
	ErrEpochMismatch            = errors.New("protocol message's current_epoch does not match the certificate epoch")
	ErrMissingEpoch             = errors.New("certificate chain skips an epoch")
	ErrPreviousHashMismatch     = errors.New("previous certificate's hash does not match previous_hash")
	ErrAVKMismatch              = errors.New("aggregate verification key does not chain to the previous certificate")
	ErrParametersMismatch       = errors.New("protocol parameters do not chain to the previous certificate")
	ErrGenesisSignature         = errors.New("genesis signature is invalid for the genesis verification key")
	ErrGenesisAVKMismatch       = errors.New("genesis certificate's aggregate verification key is not the one its signed message names")
	ErrGenesisParamsMismatch    = errors.New("genesis certificate's protocol parameters are not the ones its signed message names")
	ErrEpochAfterGenesis        = errors.New("certificate after the genesis certificate is not in the following epoch")
	ErrStandardIsGenesis        = errors.New("expected a standard certificate, got a genesis certificate")
	ErrChainRevisits            = errors.New("certificate chain revisits a certificate")
	ErrNotGenesisWhereExpected  = errors.New("expected a genesis certificate")
	errCurrentEpochPartRequired = errors.New("protocol message has no current_epoch")
)

// CertificateError reports which certificate broke which rule.
type CertificateError struct {
	Hash  string
	Epoch uint64
	Err   error
}

func (e *CertificateError) Error() string {
	return fmt.Sprintf("certificate %s (epoch %d): %v", e.Hash, e.Epoch, e.Err)
}

func (e *CertificateError) Unwrap() error { return e.Err }

func certErr(c *Certificate, err error) error {
	return &CertificateError{Hash: c.Hash, Epoch: c.Epoch, Err: err}
}

func (d *decoded) checkHash() error {
	got, err := d.computeHash()
	if err != nil {
		return err
	}
	if got != d.Hash {
		return fmt.Errorf("%w: computed %s", ErrHashMismatch, got)
	}
	return nil
}

func (d *decoded) checkSignedMessage() error {
	got, err := d.ProtocolMessage.Hash()
	if err != nil {
		return err
	}
	if got != d.SignedMessage {
		return fmt.Errorf("%w: protocol message hashes to %s", ErrProtocolMessageMismatch, got)
	}
	return nil
}

func (d *decoded) checkEpochPart() error {
	v, ok := d.ProtocolMessage.MessageParts["current_epoch"]
	if !ok {
		return fmt.Errorf("%w: %w", ErrEpochMismatch, errCurrentEpochPartRequired)
	}
	if v != strconv.FormatUint(d.Epoch, 10) {
		return fmt.Errorf("%w: %q", ErrEpochMismatch, v)
	}
	return nil
}

// verifyGenesis checks a genesis certificate: content hash, signed message,
// the Ed25519 signature over the signed message's hex text, and the epoch
// part. Mithril's main branch also requires the AVK and parameters the
// certificate carries to be those its signed message names for the next
// epoch; at release 2642.0 they were bound only by the certificate hash,
// which the genesis key does not sign.
func verifyGenesis(g *decoded, key GenesisKey) error {
	if g.genesis == nil {
		return ErrNotGenesisWhereExpected
	}
	if err := g.checkHash(); err != nil {
		return err
	}
	if err := g.checkSignedMessage(); err != nil {
		return err
	}
	if !verifyStrict(key, []byte(g.SignedMessage), g.genesis) {
		return ErrGenesisSignature
	}
	if err := g.checkEpochPart(); err != nil {
		return err
	}
	next, err := DecodeAVK(g.ProtocolMessage.MessageParts["next_aggregate_verification_key"])
	if err != nil || !next.Equal(g.avk) {
		return ErrGenesisAVKMismatch
	}
	ph, err := g.Metadata.Parameters.Hash()
	if err != nil || g.ProtocolMessage.MessageParts["next_protocol_parameters"] != ph {
		return ErrGenesisParamsMismatch
	}
	return nil
}

// verifyStandard checks a standard certificate c and its link to its
// previous certificate p (rules of certificate_verifier.rs, in its order).
// p's own content is checked when the walk reaches it. Mithril's main
// branch also requires a certificate that follows a genesis certificate to
// be in the next epoch.
func verifyStandard(c, p *decoded) error {
	if c.multiSig == nil {
		return ErrStandardIsGenesis
	}
	if c.Hash == c.PreviousHash {
		return ErrInfiniteLoop
	}
	if err := c.checkHash(); err != nil {
		return err
	}
	if err := c.checkSignedMessage(); err != nil {
		return err
	}
	if err := c.multiSig.Verify([]byte(c.SignedMessage), c.avk, c.Metadata.Parameters.STM()); err != nil {
		return fmt.Errorf("%w: %w", ErrMultiSignature, err)
	}
	if err := c.checkEpochPart(); err != nil {
		return err
	}
	if diff := max(c.Epoch, p.Epoch) - min(c.Epoch, p.Epoch); diff > 1 {
		return fmt.Errorf("%w: epoch %d follows epoch %d", ErrMissingEpoch, c.Epoch, p.Epoch)
	}
	if p.Hash != c.PreviousHash {
		return ErrPreviousHashMismatch
	}
	if p.IsGenesis() && c.Epoch != p.Epoch+1 {
		return fmt.Errorf("%w: epoch %d follows genesis epoch %d", ErrEpochAfterGenesis, c.Epoch, p.Epoch)
	}
	sameEpoch := p.Epoch == c.Epoch
	if sameEpoch {
		if !p.avk.Equal(c.avk) {
			return ErrAVKMismatch
		}
	} else {
		next, err := DecodeAVK(p.ProtocolMessage.MessageParts["next_aggregate_verification_key"])
		if err != nil || !next.Equal(c.avk) {
			return ErrAVKMismatch
		}
	}
	if sameEpoch {
		if !p.Metadata.Parameters.Equal(c.Metadata.Parameters) {
			return ErrParametersMismatch
		}
	} else {
		ph, err := c.Metadata.Parameters.Hash()
		if err != nil || p.ProtocolMessage.MessageParts["next_protocol_parameters"] != ph {
			return ErrParametersMismatch
		}
	}
	return nil
}

// VerifyGenesis checks a genesis certificate against the genesis key.
func VerifyGenesis(g *Certificate, key GenesisKey) error {
	d, err := decode(g)
	if err != nil {
		return certErr(g, err)
	}
	if err := verifyGenesis(d, key); err != nil {
		return certErr(g, err)
	}
	return nil
}

// VerifyStandard checks a standard certificate and its link to the
// certificate its previous_hash names.
func VerifyStandard(c, prev *Certificate) error {
	dc, err := decode(c)
	if err != nil {
		return certErr(c, err)
	}
	dp, err := decode(prev)
	if err != nil {
		return certErr(prev, err)
	}
	if err := verifyStandard(dc, dp); err != nil {
		return certErr(c, err)
	}
	return nil
}

// Fetcher returns the certificate with the given hash.
type Fetcher func(ctx context.Context, hash string) (*Certificate, error)

// Result describes a verified chain.
type Result struct {
	// Verified lists the hashes of the certificates checked, from the
	// starting certificate back. It ends with the genesis certificate, or
	// with the trusted certificate the walk stopped at.
	Verified []string
	// Genesis is the genesis certificate reached, or nil when the walk
	// stopped at a trusted certificate.
	Genesis *Certificate
	// StoppedAt is the trusted certificate the walk stopped at, or nil.
	StoppedAt *Certificate
}

// Options adjust a chain walk.
type Options struct {
	// Trusted reports whether a certificate hash was verified back to
	// genesis under the same key by an earlier walk. The walk stops at the
	// first such certificate after checking that its content matches its
	// hash, which is what binds it to the earlier verification. Nil trusts
	// nothing.
	Trusted func(hash string) bool
	// Progress, if set, is called after each certificate is verified.
	Progress func(verified int, c *Certificate)
}

// Verify walks from cert to a genesis certificate, fetching each previous
// certificate, and checks every certificate and every link. It succeeds
// only at a genesis certificate signed by key, or at a trusted certificate.
func Verify(ctx context.Context, cert *Certificate, key GenesisKey, fetch Fetcher, opt Options) (*Result, error) {
	res := &Result{}
	seen := map[string]bool{}
	cur, err := decode(cert)
	if err != nil {
		return nil, certErr(cert, err)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if seen[cur.Hash] {
			return nil, certErr(cur.Certificate, ErrChainRevisits)
		}
		seen[cur.Hash] = true
		if cur.IsGenesis() {
			if err := verifyGenesis(cur, key); err != nil {
				return nil, certErr(cur.Certificate, err)
			}
			res.Verified = append(res.Verified, cur.Hash)
			res.Genesis = cur.Certificate
			report(opt, res, cur.Certificate)
			return res, nil
		}
		prevCert, err := fetch(ctx, cur.PreviousHash)
		if err != nil {
			return nil, fmt.Errorf("fetching certificate %s, previous to %s: %w", cur.PreviousHash, cur.Hash, err)
		}
		prev, err := decode(prevCert)
		if err != nil {
			return nil, certErr(prevCert, err)
		}
		if err := verifyStandard(cur, prev); err != nil {
			return nil, certErr(cur.Certificate, err)
		}
		res.Verified = append(res.Verified, cur.Hash)
		report(opt, res, cur.Certificate)
		if opt.Trusted != nil && opt.Trusted(prev.Hash) {
			if err := prev.checkHash(); err != nil {
				return nil, certErr(prev.Certificate, err)
			}
			res.Verified = append(res.Verified, prev.Hash)
			res.StoppedAt = prev.Certificate
			return res, nil
		}
		cur = prev
	}
}

func report(opt Options, res *Result, c *Certificate) {
	if opt.Progress != nil {
		opt.Progress(len(res.Verified), c)
	}
}
