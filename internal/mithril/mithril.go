// Package mithril reads Cardano database snapshots from a Mithril
// aggregator and verifies them:
//
//   - each immutable file's SHA-256 against the snapshot's digest list;
//   - the digest list's Merkle root against the artifact and against the
//     certificate's signed protocol message;
//   - the certificate's signed message against its protocol message parts;
//   - the certificate's STM multi-signature and its chain back to a genesis
//     certificate signed by a pinned genesis key (package chain).
package mithril

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chrisguiney/mithril2pq/internal/mithril/chain"
)

// Networks maps the well-known network names to their aggregators.
var Networks = map[string]string{
	"mainnet": "https://aggregator.release-mainnet.api.mithril.network/aggregator",
	"preprod": "https://aggregator.release-preprod.api.mithril.network/aggregator",
	"preview": "https://aggregator.pre-release-preview.api.mithril.network/aggregator",
}

// ResolveAggregator turns a network name or URL into an aggregator URL, and
// returns the network the name implies ("" for a custom URL).
func ResolveAggregator(archive string) (aggregator, network string, err error) {
	if u, ok := Networks[strings.ToLower(archive)]; ok {
		return u, strings.ToLower(archive), nil
	}
	u, err := url.Parse(archive)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", "", fmt.Errorf("-mithril-archive %q is neither mainnet, preprod, preview nor an http(s) aggregator URL", archive)
	}
	return strings.TrimRight(archive, "/"), "", nil
}

// Client talks to one aggregator.
type Client struct {
	Aggregator string
	HTTP       *http.Client
	UserAgent  string
}

// NewClient returns a client with sensible timeouts for API calls; archive
// downloads use their own context.
func NewClient(aggregator string) *Client {
	return &Client{
		Aggregator: aggregator,
		HTTP: &http.Client{Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConnsPerHost: 64,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 20 * time.Second,
		}},
		UserAgent: "mithril2pq",
	}
}

// Beacon identifies a snapshot point.
type Beacon struct {
	Epoch               uint64 `json:"epoch"`
	ImmutableFileNumber uint64 `json:"immutable_file_number"`
}

// ArtifactSummary is one entry of the artifact list.
type ArtifactSummary struct {
	Hash            string `json:"hash"`
	MerkleRoot      string `json:"merkle_root"`
	Beacon          Beacon `json:"beacon"`
	CertificateHash string `json:"certificate_hash"`
	CreatedAt       string `json:"created_at"`
}

// Location is one place an archive can be fetched from.
type Location struct {
	Type        string          `json:"type"`
	URI         json.RawMessage `json:"uri"`
	Compression string          `json:"compression_algorithm"`
}

// Artifact is a Cardano database snapshot.
type Artifact struct {
	Hash            string `json:"hash"`
	MerkleRoot      string `json:"merkle_root"`
	Network         string `json:"network"`
	Beacon          Beacon `json:"beacon"`
	CertificateHash string `json:"certificate_hash"`
	Digests         struct {
		Locations []Location `json:"locations"`
	} `json:"digests"`
	Immutables struct {
		AverageSizeUncompressed uint64     `json:"average_size_uncompressed"`
		Locations               []Location `json:"locations"`
	} `json:"immutables"`
	TotalDBSizeUncompressed uint64 `json:"total_db_size_uncompressed"`
	CardanoNodeVersion      string `json:"cardano_node_version"`
	CreatedAt               string `json:"created_at"`
}

// Certificate is a Mithril certificate as the aggregator serves it.
type Certificate = chain.Certificate

// LatestArtifact returns the most recent snapshot.
func (c *Client) LatestArtifact(ctx context.Context) (ArtifactSummary, error) {
	var list []ArtifactSummary
	if err := c.getJSON(ctx, c.Aggregator+"/artifact/cardano-database", &list); err != nil {
		return ArtifactSummary{}, err
	}
	if len(list) == 0 {
		return ArtifactSummary{}, fmt.Errorf("aggregator %s lists no Cardano database snapshots", c.Aggregator)
	}
	return list[0], nil
}

// Artifact returns the snapshot with the given hash.
func (c *Client) Artifact(ctx context.Context, hash string) (Artifact, error) {
	var a Artifact
	err := c.getJSON(ctx, c.Aggregator+"/artifact/cardano-database/"+url.PathEscape(hash), &a)
	return a, err
}

// Certificate returns the certificate with the given hash.
func (c *Client) Certificate(ctx context.Context, hash string) (*Certificate, error) {
	var cert Certificate
	if err := c.getJSON(ctx, c.Aggregator+"/certificate/"+url.PathEscape(hash), &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

func (c *Client) getJSON(ctx context.Context, u string, v any) error {
	return retry(ctx, 4, func() error {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		body, err := c.get(ctx, u)
		if err != nil {
			return err
		}
		defer body.Close()
		if err := json.NewDecoder(body).Decode(v); err != nil {
			return fmt.Errorf("decoding response from %s: %w", u, err)
		}
		return nil
	})
}

// HTTPError is a non-2xx response.
type HTTPError struct {
	URL    string
	Status string
	Code   int
}

func (e *HTTPError) Error() string { return fmt.Sprintf("GET %s: %s", e.URL, e.Status) }

func (c *Client) get(ctx context.Context, u string) (io.ReadCloser, error) {
	resp, err := c.do(ctx, u)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (c *Client) do(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u, err)
	}
	if resp.StatusCode/100 != 2 {
		resp.Body.Close()
		return nil, &HTTPError{URL: u, Status: resp.Status, Code: resp.StatusCode}
	}
	return resp, nil
}

// retry runs f up to attempts times with exponential backoff. A 4xx other
// than 408/429 is not retried: asking again will not change the answer.
func retry(ctx context.Context, attempts int, f func() error) error {
	var err error
	delay := time.Second
	for i := range attempts {
		if err = f(); err == nil {
			return nil
		}
		var he *HTTPError
		if errors.As(err, &he) && he.Code/100 == 4 && he.Code != 408 && he.Code != 429 {
			return err
		}
		if ctx.Err() != nil || i == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// ProtocolMessageHash computes the legacy-scheme hash of protocol message
// parts.
func ProtocolMessageHash(parts map[string]string) (string, error) {
	return chain.ProtocolMessageHash(parts)
}

// VerifyCertificate checks that the certificate is for this artifact and
// that its signed message commits to the artifact's Merkle root. The
// certificate's own signature and chain are checked by chain.Verify.
func VerifyCertificate(a Artifact, cert *Certificate) error {
	if cert.Hash != a.CertificateHash {
		return fmt.Errorf("aggregator returned certificate %s for %s", cert.Hash, a.CertificateHash)
	}
	var set struct {
		CardanoDatabase *Beacon `json:"CardanoDatabase"`
	}
	if err := json.Unmarshal(cert.SignedEntityType, &set); err != nil || set.CardanoDatabase == nil {
		return fmt.Errorf("certificate %s does not sign a Cardano database snapshot", cert.Hash)
	}
	if *set.CardanoDatabase != a.Beacon {
		return fmt.Errorf("certificate signs epoch %d immutable %d, the snapshot is epoch %d immutable %d",
			set.CardanoDatabase.Epoch, set.CardanoDatabase.ImmutableFileNumber, a.Beacon.Epoch, a.Beacon.ImmutableFileNumber)
	}
	if root := cert.ProtocolMessage.MessageParts["cardano_database_merkle_root"]; root != a.MerkleRoot {
		return fmt.Errorf("certificate signs Merkle root %q, the snapshot's is %s", root, a.MerkleRoot)
	}
	got, err := cert.ProtocolMessage.Hash()
	if err != nil {
		return err
	}
	if got != cert.SignedMessage {
		return fmt.Errorf("certificate's protocol message hashes to %s but its signed message is %s", got, cert.SignedMessage)
	}
	return nil
}

// ImmutableURLs returns the download URLs for immutable file n, in the
// order the artifact lists them.
func (a Artifact) ImmutableURLs(n uint64) ([]string, error) {
	var out []string
	for _, l := range a.Immutables.Locations {
		var t struct {
			Template string `json:"Template"`
		}
		if err := json.Unmarshal(l.URI, &t); err != nil || t.Template == "" {
			continue
		}
		if l.Compression != "" && l.Compression != "zstandard" {
			continue
		}
		out = append(out, strings.ReplaceAll(t.Template, "{immutable_file_number}", fmt.Sprintf("%05d", n)))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("snapshot %s lists no zstandard immutable-file location this version of mithril2pq understands", a.Hash)
	}
	return out, nil
}
