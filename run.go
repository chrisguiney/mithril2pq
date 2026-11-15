package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/apache/arrow-go/v18/parquet/file"
	"github.com/apache/arrow-go/v18/parquet/pqarrow"

	"github.com/chrisguiney/mithril2pq/internal/chunk"
	"github.com/chrisguiney/mithril2pq/internal/dataset"
	"github.com/chrisguiney/mithril2pq/internal/extract"
	"github.com/chrisguiney/mithril2pq/internal/mithril"
	"github.com/chrisguiney/mithril2pq/internal/mithril/chain"
	"github.com/chrisguiney/mithril2pq/internal/schema"
)

type config struct {
	archive     string
	snapshot    string
	out         string
	cacheDir    string
	fileSize    int64
	concurrency int
	buffer      int
	workers     int
	checkpoint  time.Duration
	compression string
	lastChunk   int64 // -1: the snapshot's last immutable file

	genesisKeyArg string           // -genesis-vkey as given
	genesisKey    chain.GenesisKey // resolved by validate
}

// errStopped reports a clean stop on request; progress up to it is
// committed.
var errStopped = errors.New("stopped on request")

type runner struct {
	cfg      config
	client   *mithril.Client
	artifact mithril.Artifact
	digests  map[string]string
	network  string
	ds       *dataset.Dir
	st       *stats
	prog     *progress
	mem      memory.Allocator

	cacheImm  string // cache directory, "" for none
	cacheLock *os.File
}

func run(ctx context.Context, stopCh <-chan struct{}, cfg config, st *stats, prog *progress) error {
	r := &runner{cfg: cfg, st: st, prog: prog, mem: memory.NewGoAllocator()}
	agg, presetNet, err := mithril.ResolveAggregator(cfg.archive)
	if err != nil {
		return err
	}
	r.client = mithril.NewClient(agg)

	r.ds, err = dataset.Open(cfg.out)
	if err != nil {
		return err
	}
	defer r.ds.Close()

	if err := r.loadSnapshot(ctx, presetNet); err != nil {
		return err
	}
	start, end, err := r.plan()
	if err != nil {
		return err
	}
	if start > end {
		prog.logf("%s already holds every chunk through %d; nothing to do.", cfg.out, end)
		return nil
	}
	if err := r.openCache(); err != nil {
		return err
	}
	defer r.closeCache()

	st.chunksTotal = end - start + 1
	prog.logf("converting chunks %d..%d (%d chunks) into %s", start, end, st.chunksTotal, cfg.out)
	return r.pipeline(ctx, stopCh, start, end)
}

// loadSnapshot fetches and verifies the snapshot, its certificate and its
// digest list.
func (r *runner) loadSnapshot(ctx context.Context, presetNet string) error {
	hash := r.cfg.snapshot
	if hash == "" {
		latest, err := r.client.LatestArtifact(ctx)
		if err != nil {
			return fmt.Errorf("finding the latest snapshot: %w", err)
		}
		hash = latest.Hash
	}
	a, err := r.client.Artifact(ctx, hash)
	if err != nil {
		return fmt.Errorf("fetching snapshot %s: %w", hash, err)
	}
	r.artifact = a
	r.network = a.Network
	if presetNet != "" && a.Network != presetNet {
		return fmt.Errorf("the %s aggregator served a snapshot for network %q", presetNet, a.Network)
	}
	if r.network == "" {
		return fmt.Errorf("snapshot %s does not name its network", a.Hash)
	}
	r.prog.logf("snapshot %s: network %s, epoch %d, immutable files 0..%d, created %s",
		a.Hash, a.Network, a.Beacon.Epoch, a.Beacon.ImmutableFileNumber, a.CreatedAt)

	cert, err := r.client.Certificate(ctx, a.CertificateHash)
	if err != nil {
		return fmt.Errorf("fetching certificate %s: %w", a.CertificateHash, err)
	}
	if err := mithril.VerifyCertificate(a, cert); err != nil {
		return fmt.Errorf("snapshot verification failed: %w", err)
	}
	if err := r.verifyChain(ctx, cert); err != nil {
		return err
	}

	list, err := r.client.Digests(ctx, a)
	if err != nil {
		return err
	}
	root, err := mithril.MerkleRoot(list)
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(root); got != a.MerkleRoot {
		return fmt.Errorf("snapshot verification failed: digest list's Merkle root is %s, the snapshot certifies %s", got, a.MerkleRoot)
	}
	r.digests = make(map[string]string, len(list))
	for _, d := range list {
		r.digests[d.ImmutableFileName] = d.Digest
	}
	r.prog.logf("verified: %d file digests hash to the certified Merkle root, which the certificate's signed message commits to", len(list))
	return nil
}

// plan works out which chunks to apply and checks the output directory
// belongs to the same chain.
func (r *runner) plan() (start, end int64, err error) {
	end = int64(r.artifact.Beacon.ImmutableFileNumber)
	if r.cfg.lastChunk >= 0 && r.cfg.lastChunk < end {
		end = r.cfg.lastChunk
	}
	m := r.ds.Manifest
	if m == nil {
		return 0, end, nil
	}
	if m.SchemaVersion != schema.Version {
		return 0, 0, fmt.Errorf("%s was written with schema version %d; this mithril2pq writes version %d. Convert into a new directory", r.cfg.out, m.SchemaVersion, schema.Version)
	}
	if m.Network != r.network {
		return 0, 0, fmt.Errorf("%s holds %s data; the snapshot is for %s", r.cfg.out, m.Network, r.network)
	}
	if m.LastChunk >= 0 {
		for name, want := range m.LastChunkDigests {
			if got, ok := r.digests[name]; ok && got != want {
				return 0, 0, fmt.Errorf("%s was built from a different chain: the snapshot certifies %s as %s, the output was built from %s", r.cfg.out, name, got, want)
			}
		}
		if uint64(m.LastChunk) > r.artifact.Beacon.ImmutableFileNumber {
			return 0, 0, fmt.Errorf("%s already holds chunks through %d, past this snapshot's last immutable file %d", r.cfg.out, m.LastChunk, r.artifact.Beacon.ImmutableFileNumber)
		}
	}
	return m.LastChunk + 1, end, nil
}

// ---- cache ----

func (r *runner) openCache() error {
	if r.cfg.cacheDir == "" {
		return nil
	}
	dir := r.cfg.cacheDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("opening cache lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return fmt.Errorf("cache directory %s is in use by another mithril2pq process", dir)
	}
	r.cacheImm, r.cacheLock = dir, lock
	// Archives are named by immutable file number, which every network
	// reuses, so one cache directory holds one network's archives.
	marker := filepath.Join(dir, cacheNetworkFile)
	if b, err := os.ReadFile(marker); err == nil {
		if have := strings.TrimSpace(string(b)); have != r.network {
			return fmt.Errorf("cache directory %s holds %s archives; use a separate -cache-dir for %s", dir, have, r.network)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(marker, []byte(r.network+"\n"), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", marker, err)
		}
	} else {
		return fmt.Errorf("reading %s: %w", marker, err)
	}
	// With the lock held, any partial download is a leftover.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if isPartial(e.Name()) {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	return nil
}

// cacheNetworkFile records which network a cache directory's archives are
// from.
const cacheNetworkFile = ".mithril2pq-network"

func isPartial(name string) bool {
	return strings.HasPrefix(name, ".") && strings.Contains(name, ".tar.zst.partial-")
}

func (r *runner) closeCache() {
	if r.cacheLock != nil {
		r.cacheLock.Close()
	}
}

func (r *runner) cachePath(n uint64) string {
	return filepath.Join(r.cacheImm, fmt.Sprintf("%05d.tar.zst", n))
}

// removeCachePartials deletes this process's in-progress cache downloads;
// used on hard abort.
func removeCachePartials(cacheDir string) {
	if cacheDir == "" {
		return
	}
	suffix := fmt.Sprintf(".partial-%d", os.Getpid())
	entries, _ := os.ReadDir(cacheDir)
	for _, e := range entries {
		if isPartial(e.Name()) && strings.HasSuffix(e.Name(), suffix) {
			os.Remove(filepath.Join(cacheDir, e.Name()))
		}
	}
}

// ---- pipeline ----

type fetched struct {
	data []byte // in memory, when there is no cache
	path string // cached archive
	err  error
}

type decoded struct {
	recs      []arrow.RecordBatch // by table ID; nil for none and for deduplicated tables
	scripts   []schema.Row
	natives   []schema.Row
	firstPrev []byte // the first block's prev hash, if it decoded
	lastHash  []byte
	lastSlot  uint64
	hasSlot   bool
	stats     extract.Stats
	err       error
}

func (d *decoded) release() {
	for _, r := range d.recs {
		if r != nil {
			r.Release()
		}
	}
}

type job struct {
	n       uint64
	fetched chan fetched
	decoded chan decoded
}

func (r *runner) pipeline(ctx context.Context, stopCh <-chan struct{}, start, end int64) error {
	dlCtx, cancelDL := context.WithCancel(ctx)
	defer cancelDL()
	go func() {
		select {
		case <-stopCh:
			r.prog.logf("stopping: finishing the current chunk and committing (interrupt again to abort without committing)")
			cancelDL()
		case <-dlCtx.Done():
		}
	}()

	jobs := make([]*job, 0, end-start+1)
	for n := start; n <= end; n++ {
		jobs = append(jobs, &job{n: uint64(n), fetched: make(chan fetched, 1), decoded: make(chan decoded, 1)})
	}

	// Without a cache, downloads may run at most `buffer` archives ahead of
	// the writer; with one, they run ahead freely onto disk.
	var window chan struct{}
	if r.cacheImm == "" {
		window = make(chan struct{}, r.cfg.buffer)
	}
	feed := make(chan *job)
	go func() {
		defer close(feed)
		for _, j := range jobs {
			if window != nil {
				select {
				case window <- struct{}{}:
				case <-dlCtx.Done():
					return
				}
			}
			select {
			case feed <- j:
			case <-dlCtx.Done():
				return
			}
		}
	}()
	var dlWG sync.WaitGroup
	for range r.cfg.concurrency {
		dlWG.Add(1)
		go func() {
			defer dlWG.Done()
			for j := range feed {
				j.fetched <- r.fetch(dlCtx, j.n)
			}
		}()
	}

	// Decoding runs in parallel, at most decodeAhead chunks ahead of the
	// writer, which takes results in chunk order.
	decodeAhead := make(chan struct{}, r.cfg.workers*2)
	running := make(chan struct{}, r.cfg.workers)
	go func() {
		for _, j := range jobs {
			var f fetched
			select {
			case f = <-j.fetched:
			case <-dlCtx.Done():
				return
			}
			select {
			case decodeAhead <- struct{}{}:
			case <-dlCtx.Done():
				return
			}
			running <- struct{}{}
			go func() {
				d := r.decode(dlCtx, j.n, f)
				<-running
				if window != nil {
					<-window
				}
				j.decoded <- d
			}()
		}
	}()

	err := r.write(dlCtx, jobs, decodeAhead)
	cancelDL()
	dlWG.Wait()
	return err
}

func (r *runner) fetch(ctx context.Context, n uint64) fetched {
	urls, err := r.artifact.ImmutableURLs(n)
	if err != nil {
		return fetched{err: err}
	}
	count := func(k int) { r.st.bytesDownloaded.Add(int64(k)) }
	if r.cacheImm != "" {
		path := r.cachePath(n)
		if _, err := os.Stat(path); err == nil {
			r.st.cacheHits.Add(1)
			r.st.chunksDownloaded.Add(1)
			return fetched{path: path}
		}
		if err := r.downloadToCache(ctx, n, urls, count); err != nil {
			return fetched{err: err}
		}
		r.st.chunksDownloaded.Add(1)
		return fetched{path: path}
	}
	var buf bytes.Buffer
	reset := func() error { buf.Reset(); return nil }
	if _, err := r.client.Download(ctx, urls, &buf, reset, count); err != nil {
		return fetched{err: fmt.Errorf("downloading immutable file %d: %w", n, err)}
	}
	r.st.chunksDownloaded.Add(1)
	return fetched{data: buf.Bytes()}
}

func (r *runner) downloadToCache(ctx context.Context, n uint64, urls []string, count func(int)) error {
	path := r.cachePath(n)
	tmp := filepath.Join(r.cacheImm, fmt.Sprintf(".%05d.tar.zst.partial-%d", n, os.Getpid()))
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("creating cache file: %w", err)
	}
	cw := &cacheWriter{f: f, st: r.st}
	reset := func() error {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		return f.Truncate(0)
	}
	_, err = r.client.Download(ctx, urls, cw, reset, count)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("downloading immutable file %d: %w", n, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("caching immutable file %d: %w", n, err)
	}
	return nil
}

type cacheWriter struct {
	f  *os.File
	st *stats
}

func (c *cacheWriter) Write(p []byte) (int, error) {
	n, err := c.f.Write(p)
	c.st.cacheBytes.Add(int64(n))
	return n, err
}

func (r *runner) chunkDigests(n uint64) chunk.Digests {
	return chunk.Digests{
		Chunk:     r.digests[chunk.FileName(n, "chunk")],
		Primary:   r.digests[chunk.FileName(n, "primary")],
		Secondary: r.digests[chunk.FileName(n, "secondary")],
	}
}

func (r *runner) readArchive(n uint64, f fetched) (chunk.Files, error) {
	if f.path == "" {
		return chunk.ReadArchive(bytes.NewReader(f.data), n)
	}
	fh, err := os.Open(f.path)
	if err != nil {
		return chunk.Files{}, err
	}
	defer fh.Close()
	return chunk.ReadArchive(fh, n)
}

func (r *runner) decode(ctx context.Context, n uint64, f fetched) decoded {
	if f.err != nil {
		return decoded{err: f.err}
	}
	files, err := r.readArchive(n, f)
	if err == nil {
		err = files.Verify(r.chunkDigests(n))
	}
	if err != nil && f.path != "" {
		// A damaged cached archive: replace it once from the network.
		r.prog.logf("cached immutable file %d is unusable (%v); downloading it again", n, err)
		os.Remove(f.path)
		urls, uerr := r.artifact.ImmutableURLs(n)
		if uerr != nil {
			return decoded{err: uerr}
		}
		if derr := r.downloadToCache(ctx, n, urls, func(k int) { r.st.bytesDownloaded.Add(int64(k)) }); derr != nil {
			return decoded{err: derr}
		}
		files, err = r.readArchive(n, f)
		if err == nil {
			err = files.Verify(r.chunkDigests(n))
		}
	}
	if err != nil {
		return decoded{err: fmt.Errorf("immutable file %d: %w", n, err)}
	}
	blocks, err := chunk.Blocks(files)
	if err != nil {
		return decoded{err: fmt.Errorf("immutable file %d: %w", n, err)}
	}
	rows, stats := extract.Chunk(n, blocks)
	d := decoded{stats: stats, recs: make([]arrow.RecordBatch, len(schema.Tables))}
	if len(blocks) > 0 {
		last := blocks[len(blocks)-1]
		d.lastHash = append([]byte(nil), last.Hash[:]...)
		for i := len(blocks) - 1; i >= 0; i-- {
			if !blocks[i].IsEbb {
				d.lastSlot, d.hasSlot = blocks[i].SlotOrEpoch, true
				break
			}
		}
		br := rows[schema.Block.ID]
		hr := rows[schema.BlockHeader.ID]
		if len(br) > 0 && br[0][13] == nil && len(hr) > 0 {
			if p, ok := hr[0][1].([]byte); ok {
				d.firstPrev = p
			}
		}
	}
	d.scripts = rows[schema.Script.ID]
	d.natives = rows[schema.NativeScriptNode.ID]
	for _, t := range schema.Tables {
		if t == schema.Script || t == schema.NativeScriptNode || len(rows[t.ID]) == 0 {
			continue
		}
		d.recs[t.ID] = t.Build(r.mem, rows[t.ID])
	}
	return d
}

// write consumes decoded chunks in order and appends them to the tables.
func (r *runner) write(ctx context.Context, jobs []*job, decodeAhead chan struct{}) error {
	// Work on a copy: Commit compares the new manifest against the
	// committed one to find superseded files to delete.
	newDataset := r.ds.Manifest == nil
	m := &dataset.Manifest{LastChunk: -1, Tables: map[string][]dataset.File{}}
	if !newDataset {
		cp := *r.ds.Manifest
		m = &cp
	}
	m.Network = r.network
	m.Aggregator = r.client.Aggregator
	m.Compression = r.cfg.compression

	opts := dataset.Options{
		TargetFileSize: r.cfg.fileSize,
		Compression:    dataset.Compressions[r.cfg.compression],
		Counters:       &r.st.pq,
		Mem:            r.mem,
	}
	writers := make([]*dataset.TableWriter, len(schema.Tables))
	for _, t := range schema.Tables {
		writers[t.ID] = dataset.NewTableWriter(r.ds.Path, t, m.Tables[t.Name], opts)
	}
	abort := func() {
		for _, w := range writers {
			w.Abort()
		}
	}

	seen, err := r.loadScriptHashes(m.Tables[schema.Script.Name])
	if err != nil {
		return err
	}

	if newDataset {
		rec := schema.BlockType.Build(r.mem, schema.BlockTypeRows)
		err := writers[schema.BlockType.ID].Write(-1, rec)
		rec.Release()
		if err != nil {
			abort()
			return err
		}
	}

	prevHash := []byte(nil)
	if m.LastBlockHash != "" {
		prevHash, _ = hex.DecodeString(m.LastBlockHash)
	}
	pending := newDataset // something written that is not committed
	lastCommit := time.Now()
	commit := func() error {
		if !pending {
			return nil
		}
		if err := parallelTables(writers, func(_ int, w *dataset.TableWriter) error { return w.Finish() }); err != nil {
			abort()
			return err
		}
		tables := map[string][]dataset.File{}
		for _, t := range schema.Tables {
			if fs := writers[t.ID].Files(); len(fs) > 0 {
				tables[t.Name] = fs
			}
		}
		m.Tables = tables
		m.Snapshot = dataset.SnapshotInfo{
			Hash: r.artifact.Hash, Epoch: r.artifact.Beacon.Epoch,
			ImmutableFileNumber: r.artifact.Beacon.ImmutableFileNumber,
			MerkleRoot:          r.artifact.MerkleRoot, CertificateHash: r.artifact.CertificateHash,
		}
		committed := *m
		if err := r.ds.Commit(&committed); err != nil {
			return err
		}
		pending = false
		lastCommit = time.Now()
		return nil
	}

	var stopErr error
loop:
	for _, j := range jobs {
		var d decoded
		select {
		case d = <-j.decoded:
		case <-ctx.Done():
			stopErr = errStopped
			break loop
		}
		<-decodeAhead
		if d.err != nil {
			d.release()
			if ctx.Err() != nil {
				stopErr = errStopped
			} else {
				stopErr = d.err
			}
			break
		}
		if prevHash != nil && d.firstPrev != nil && !bytes.Equal(prevHash, d.firstPrev) {
			d.release()
			stopErr = fmt.Errorf("immutable file %d does not continue the chain: its first block's previous hash is %x, the last block written was %x", j.n, d.firstPrev, prevHash)
			break
		}

		r.dedupeScripts(&d, seen)
		err := parallelTables(writers, func(i int, w *dataset.TableWriter) error {
			rec := d.recs[i]
			if rec == nil {
				return nil
			}
			return w.Write(int64(j.n), rec)
		})
		d.release()
		if err != nil {
			abort()
			return describeIOError(err)
		}
		pending = true
		m.LastChunk = int64(j.n)
		m.LastChunkDigests = map[string]string{}
		for _, ext := range []string{"chunk", "primary", "secondary"} {
			name := chunk.FileName(j.n, ext)
			m.LastChunkDigests[name] = r.digests[name]
		}
		if d.lastHash != nil {
			prevHash = d.lastHash
			m.LastBlockHash = hex.EncodeToString(d.lastHash)
		}
		if d.hasSlot {
			m.LastSlot = d.lastSlot
		}
		r.st.blocks.Add(int64(d.stats.Blocks))
		r.st.txs.Add(int64(d.stats.Txs))
		r.st.decodeErrors.Add(int64(d.stats.DecodeErrors))
		r.st.chunksWritten.Add(1)

		if r.cfg.checkpoint > 0 && time.Since(lastCommit) >= r.cfg.checkpoint {
			if err := commit(); err != nil {
				return describeIOError(err)
			}
		}
	}
	if err := commit(); err != nil {
		return describeIOError(err)
	}
	return stopErr
}

// parallelTables runs f on every table writer concurrently; each writer is
// used by one goroutine only.
func parallelTables(writers []*dataset.TableWriter, f func(int, *dataset.TableWriter) error) error {
	errs := make([]error, len(writers))
	var wg sync.WaitGroup
	for i, w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = f(i, w)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// dedupeScripts keeps the first occurrence of each script_ref script, and
// of its native-script tree, across the whole dataset.
func (r *runner) dedupeScripts(d *decoded, seen map[string]bool) {
	fresh := map[string]bool{}
	var scripts []schema.Row
	for _, row := range d.scripts {
		h := string(row[0].([]byte))
		if seen[h] {
			continue
		}
		seen[h], fresh[h] = true, true
		scripts = append(scripts, row)
	}
	var natives []schema.Row
	keep := false
	emitted := map[string]bool{}
	for _, row := range d.natives {
		owner, ok := row[0].([]byte)
		if !ok {
			natives = append(natives, row)
			continue
		}
		if row[4].(uint64) == 0 { // a new tree starts
			h := string(owner)
			keep = fresh[h] && !emitted[h]
			emitted[h] = true
		}
		if keep {
			natives = append(natives, row)
		}
	}
	if len(scripts) > 0 {
		d.recs[schema.Script.ID] = schema.Script.Build(r.mem, scripts)
	}
	if len(natives) > 0 {
		d.recs[schema.NativeScriptNode.ID] = schema.NativeScriptNode.Build(r.mem, natives)
	}
}

// loadScriptHashes reads the hashes already in the script table, so a
// resumed run does not write a script twice.
func (r *runner) loadScriptHashes(files []dataset.File) (map[string]bool, error) {
	seen := map[string]bool{}
	for _, f := range files {
		path := filepath.Join(r.ds.Path, schema.Script.Name, f.Name)
		rdr, err := file.OpenParquetFile(path, false)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		fr, err := pqarrow.NewFileReader(rdr, pqarrow.ArrowReadProperties{}, r.mem)
		if err != nil {
			rdr.Close()
			return nil, err
		}
		tbl, err := fr.ReadTable(context.Background())
		rdr.Close()
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		for _, c := range tbl.Column(0).Data().Chunks() {
			a := c.(*array.FixedSizeBinary)
			for i := range a.Len() {
				seen[string(a.Value(i))] = true
			}
		}
		tbl.Release()
	}
	return seen, nil
}

func describeIOError(err error) error {
	if errors.Is(err, syscall.ENOSPC) {
		return fmt.Errorf("the disk is full: %w", err)
	}
	return err
}

// removeTemps deletes this run's temporary Parquet files; used on hard
// abort, when the writers may still hold them open.
func removeTemps(out string) {
	for _, t := range schema.Tables {
		dir := filepath.Join(out, t.Name)
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".tmp-") {
				os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	os.Remove(filepath.Join(out, ".tmp-"+dataset.ManifestName))
}
