// Package dataset owns the output directory: one subdirectory of Parquet
// files per table, and a manifest that says which files are committed.
//
// Crash safety rests on three rules:
//
//  1. A Parquet file is written under a temporary name and renamed only
//     when complete.
//  2. Committed files are never modified. Appending to a table whose last
//     file is under the size limit copies that file's rows into a new,
//     higher-numbered file, and the old one is deleted only after the
//     manifest stops listing it.
//  3. The manifest is replaced atomically, last. Files it does not list are
//     leftovers of an interrupted run and are deleted on the next open.
//
// So after any interruption the manifest describes a consistent dataset:
// every table holds exactly the chunks up to the manifest's last chunk.
package dataset

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chrisguiney/mithril2pq/internal/schema"
)

// ManifestName is the manifest's file name in the output directory.
const ManifestName = "_mithril2pq.json"

const (
	lockName  = ".mithril2pq.lock"
	tmpPrefix = ".tmp-"
)

var partRE = regexp.MustCompile(`^part-(\d{6,})\.parquet$`)

// Manifest records what the output directory holds.
type Manifest struct {
	FormatVersion int    `json:"format_version"`
	SchemaVersion int    `json:"schema_version"`
	Network       string `json:"network"`
	Aggregator    string `json:"aggregator"`
	// Snapshot is the Mithril snapshot the newest chunks came from.
	Snapshot SnapshotInfo `json:"snapshot"`
	// LastChunk is the last immutable file applied; -1 when none.
	LastChunk int64 `json:"last_chunk"`
	// LastChunkDigests are the certified SHA-256 digests of the last
	// chunk's files, used to check that a later snapshot continues the same
	// chain.
	LastChunkDigests map[string]string `json:"last_chunk_digests,omitempty"`
	LastBlockHash    string            `json:"last_block_hash,omitempty"`
	LastSlot         uint64            `json:"last_slot,omitempty"`
	Compression      string            `json:"compression"`
	UpdatedAt        time.Time         `json:"updated_at"`
	Tables           map[string][]File `json:"tables"`
}

// SnapshotInfo identifies a Mithril snapshot.
type SnapshotInfo struct {
	Hash                string `json:"hash"`
	Epoch               uint64 `json:"epoch"`
	ImmutableFileNumber uint64 `json:"immutable_file_number"`
	MerkleRoot          string `json:"merkle_root"`
	CertificateHash     string `json:"certificate_hash"`
}

// File is one committed Parquet file.
type File struct {
	Name       string `json:"name"`
	Rows       int64  `json:"rows"`
	Bytes      int64  `json:"bytes"`
	FirstChunk int64  `json:"first_chunk"`
	LastChunk  int64  `json:"last_chunk"`
}

const formatVersion = 1

// Dir is an opened, locked output directory.
type Dir struct {
	Path     string
	Manifest *Manifest // nil for a new dataset
	lock     *os.File
}

// Open locks dir and removes anything an interrupted run left behind. It
// returns the committed manifest, or nil if the directory holds none.
func Open(dir string) (*Dir, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, lockName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("opening lock file: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("output directory %s is in use by another mithril2pq process", dir)
	}
	d := &Dir{Path: dir, lock: lock}
	m, err := readManifest(dir)
	if err != nil {
		d.Close()
		return nil, err
	}
	d.Manifest = m
	if err := d.removeLeftovers(); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// Close releases the lock.
func (d *Dir) Close() error {
	if d.lock == nil {
		return nil
	}
	err := d.lock.Close()
	d.lock = nil
	return err
}

func readManifest(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("manifest %s is not valid JSON (%v); move the output directory aside and start over", filepath.Join(dir, ManifestName), err)
	}
	if m.FormatVersion != formatVersion {
		return nil, fmt.Errorf("output directory was written by a mithril2pq with manifest format %d; this version writes format %d", m.FormatVersion, formatVersion)
	}
	if m.Tables == nil {
		m.Tables = map[string][]File{}
	}
	return &m, nil
}

// removeLeftovers deletes temporary files and Parquet parts the manifest
// does not list. It touches only names mithril2pq itself creates, inside
// directories named after its tables.
func (d *Dir) removeLeftovers() error {
	entries, err := os.ReadDir(d.Path)
	if err != nil {
		return err
	}
	committed := map[string]bool{}
	if d.Manifest != nil {
		for table, files := range d.Manifest.Tables {
			for _, f := range files {
				committed[filepath.Join(table, f.Name)] = true
			}
		}
	} else if hasParts(d.Path) {
		return fmt.Errorf("output directory %s has Parquet parts but no %s; it was not written by mithril2pq, or its manifest was lost. Use an empty directory", d.Path, ManifestName)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, tmpPrefix) {
			if err := os.Remove(filepath.Join(d.Path, name)); err != nil {
				return err
			}
			continue
		}
		if !e.IsDir() || schema.ByName(name) == nil {
			continue
		}
		files, err := os.ReadDir(filepath.Join(d.Path, name))
		if err != nil {
			return err
		}
		for _, f := range files {
			fn := f.Name()
			if strings.HasPrefix(fn, tmpPrefix) || (partRE.MatchString(fn) && !committed[filepath.Join(name, fn)]) {
				if err := os.Remove(filepath.Join(d.Path, name, fn)); err != nil {
					return fmt.Errorf("removing leftover %s: %w", filepath.Join(name, fn), err)
				}
			}
		}
	}
	return nil
}

func hasParts(dir string) bool {
	for _, t := range schema.Tables {
		files, _ := os.ReadDir(filepath.Join(dir, t.Name))
		for _, f := range files {
			if partRE.MatchString(f.Name()) {
				return true
			}
		}
	}
	return false
}

// Commit atomically replaces the manifest, then deletes files the old one
// listed and the new one does not.
func (d *Dir) Commit(m *Manifest) error {
	m.FormatVersion = formatVersion
	m.SchemaVersion = schema.Version
	m.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(d.Path, tmpPrefix+ManifestName)
	if err := writeFileSync(tmp, b); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("writing manifest: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(d.Path, ManifestName)); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replacing manifest: %w", err)
	}
	syncDir(d.Path)
	old := d.Manifest
	d.Manifest = m
	if old != nil {
		for table, files := range old.Tables {
			keep := map[string]bool{}
			for _, f := range m.Tables[table] {
				keep[f.Name] = true
			}
			for _, f := range files {
				if !keep[f.Name] {
					os.Remove(filepath.Join(d.Path, table, f.Name))
				}
			}
		}
	}
	return nil
}

func writeFileSync(path string, b []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		f.Sync()
		f.Close()
	}
}

// partName formats a part file name.
func partName(n int) string { return fmt.Sprintf("part-%06d.parquet", n) }

// partNumber parses a part file name; -1 if it is not one.
func partNumber(name string) int {
	m := partRE.FindStringSubmatch(name)
	if m == nil {
		return -1
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return -1
	}
	return n
}

// sortFiles orders a table's files by part number, which is chain order.
func sortFiles(files []File) {
	sort.Slice(files, func(i, j int) bool { return partNumber(files[i].Name) < partNumber(files[j].Name) })
}
