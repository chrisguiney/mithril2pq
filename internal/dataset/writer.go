package dataset

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/apache/arrow-go/v18/parquet"
	"github.com/apache/arrow-go/v18/parquet/compress"
	"github.com/apache/arrow-go/v18/parquet/file"
	"github.com/apache/arrow-go/v18/parquet/pqarrow"

	"github.com/chrisguiney/mithril2pq/internal/schema"
)

// Counters are shared, atomically updated totals for progress reporting.
type Counters struct {
	BytesWritten atomic.Int64 // Parquet bytes written, including rewrites
	FilesWritten atomic.Int64 // Parquet files completed this run
}

// Options configures Parquet output.
type Options struct {
	TargetFileSize int64
	Compression    compress.Compression
	Counters       *Counters
	Mem            memory.Allocator
}

// Compressions maps flag values to codecs that pyarrow and fastparquet can
// both read.
var Compressions = map[string]compress.Compression{
	"zstd":   compress.Codecs.Zstd,
	"snappy": compress.Codecs.Snappy,
	"gzip":   compress.Codecs.Gzip,
	"none":   compress.Codecs.Uncompressed,
}

// writerProps keeps to features every mainstream Python reader handles:
// format 2.6 logical types, version 1 data pages, dictionary and plain
// encodings, statistics, and no page index, bloom filters or byte-stream
// split. The Arrow schema is stored so pyarrow restores exact types.
func (o Options) writerProps() (*parquet.WriterProperties, pqarrow.ArrowWriterProperties) {
	props := parquet.NewWriterProperties(
		parquet.WithVersion(parquet.V2_6),
		parquet.WithDataPageVersion(parquet.DataPageV1),
		parquet.WithCompression(o.Compression),
		parquet.WithDictionaryDefault(true),
		parquet.WithStats(true),
		parquet.WithPageIndexEnabled(false),
		parquet.WithCreatedBy("mithril2pq"),
		parquet.WithAllocator(o.Mem),
	)
	return props, pqarrow.NewArrowWriterProperties(pqarrow.WithStoreSchema(), pqarrow.WithAllocator(o.Mem))
}

// rowGroupTarget bounds a row group's compressed size: small enough to keep
// writer memory modest, large enough for efficient scans.
func (o Options) rowGroupTarget() int64 {
	return min(max(o.TargetFileSize, 1<<20), 64<<20)
}

// TableWriter appends record batches to one table, rolling files at the
// target size. It is not safe for concurrent use.
type TableWriter struct {
	table *schema.Table
	dir   string
	opts  Options

	files    []File // committed files, plus files completed this segment
	nextPart int
	// tailReopened is set once the last committed file has been considered
	// for rewriting in this segment.
	tailReopened bool

	cur *openFile
}

type openFile struct {
	tmp, final string
	f          *os.File
	cw         *countingWriter
	fw         *pqarrow.FileWriter
	rows       int64
	first      int64
	last       int64
}

// NewTableWriter resumes a table from its committed files.
func NewTableWriter(dir string, t *schema.Table, committed []File, opts Options) *TableWriter {
	files := append([]File(nil), committed...)
	sortFiles(files)
	next := 0
	if len(files) > 0 {
		next = partNumber(files[len(files)-1].Name) + 1
	}
	return &TableWriter{table: t, dir: filepath.Join(dir, t.Name), opts: opts, files: files, nextPart: next}
}

// Write appends rec, which holds rows from chunk.
func (w *TableWriter) Write(chunk int64, rec arrow.RecordBatch) error {
	if rec.NumRows() == 0 {
		return nil
	}
	if w.cur == nil {
		if err := w.open(chunk); err != nil {
			return err
		}
	}
	if err := w.cur.fw.WriteBuffered(rec); err != nil {
		return w.fail(fmt.Errorf("writing %s: %w", w.table.Name, err))
	}
	w.cur.rows += rec.NumRows()
	w.cur.last = chunk
	return w.maybeRoll()
}

func (w *TableWriter) maybeRoll() error {
	rg := w.cur.fw.RowGroupTotalCompressedBytes()
	if w.cur.cw.n.Load()+rg >= w.opts.TargetFileSize {
		return w.finish()
	}
	if rg >= w.opts.rowGroupTarget() {
		if err := w.cur.fw.NewBufferedRowGroupChecked(); err != nil {
			return w.fail(fmt.Errorf("writing %s: %w", w.table.Name, err))
		}
	}
	return nil
}

// open starts a new file. The first file opened in a segment absorbs the
// table's last committed file if that is under the target size, so
// repeated runs do not leave a trail of small files.
func (w *TableWriter) open(chunk int64) error {
	if err := os.MkdirAll(w.dir, 0o755); err != nil {
		return err
	}
	name := partName(w.nextPart)
	w.nextPart++
	of := &openFile{
		tmp:   filepath.Join(w.dir, tmpPrefix+name),
		final: filepath.Join(w.dir, name),
		first: chunk,
	}
	f, err := os.Create(of.tmp)
	if err != nil {
		return fmt.Errorf("creating %s: %w", of.tmp, err)
	}
	of.f = f
	of.cw = &countingWriter{w: f, counters: w.opts.Counters}
	props, aprops := w.opts.writerProps()
	of.fw, err = pqarrow.NewFileWriter(w.table.Arrow(), of.cw, props, aprops)
	if err != nil {
		f.Close()
		os.Remove(of.tmp)
		return fmt.Errorf("starting %s: %w", of.tmp, err)
	}
	w.cur = of

	if !w.tailReopened {
		w.tailReopened = true
		if n := len(w.files); n > 0 && w.files[n-1].Bytes < w.opts.TargetFileSize {
			tail := w.files[n-1]
			if err := w.copyFrom(filepath.Join(w.dir, tail.Name)); err != nil {
				return w.fail(fmt.Errorf("rewriting %s/%s: %w", w.table.Name, tail.Name, err))
			}
			of.first = tail.FirstChunk
			// The old file stays on disk, still listed by the committed
			// manifest, until the next commit drops it.
			w.files = w.files[:n-1]
		}
	}
	return nil
}

func (w *TableWriter) copyFrom(path string) error {
	rdr, err := file.OpenParquetFile(path, false)
	if err != nil {
		return err
	}
	defer rdr.Close()
	fr, err := pqarrow.NewFileReader(rdr, pqarrow.ArrowReadProperties{BatchSize: 64 << 10}, w.opts.Mem)
	if err != nil {
		return err
	}
	rr, err := fr.GetRecordReader(context.Background(), nil, nil)
	if err != nil {
		return err
	}
	defer rr.Release()
	for rr.Next() {
		got := rr.RecordBatch()
		if err := sameColumns(got.Schema(), w.table.Arrow()); err != nil {
			return err
		}
		// The reader attaches field metadata (PARQUET:field_id); rewrap the
		// columns in the table's own schema.
		rec := array.NewRecordBatch(w.table.Arrow(), got.Columns(), got.NumRows())
		err := w.cur.fw.WriteBuffered(rec)
		rec.Release()
		if err != nil {
			return err
		}
		w.cur.rows += rec.NumRows()
		if w.cur.fw.RowGroupTotalCompressedBytes() >= w.opts.rowGroupTarget() {
			if err := w.cur.fw.NewBufferedRowGroupChecked(); err != nil {
				return err
			}
		}
	}
	if err := rr.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// sameColumns compares names, types and nullability, ignoring metadata.
func sameColumns(got, want *arrow.Schema) error {
	if got.NumFields() != want.NumFields() {
		return fmt.Errorf("file has %d columns, this version's schema has %d", got.NumFields(), want.NumFields())
	}
	for i, g := range got.Fields() {
		wf := want.Field(i)
		if g.Name != wf.Name || !arrow.TypeEqual(g.Type, wf.Type) || g.Nullable != wf.Nullable {
			return fmt.Errorf("file column %d is %s %s (nullable %v), this version's is %s %s (nullable %v)",
				i, g.Name, g.Type, g.Nullable, wf.Name, wf.Type, wf.Nullable)
		}
	}
	return nil
}

// finish closes the open file and renames it into place. It stays
// uncommitted until the manifest lists it.
func (w *TableWriter) finish() error {
	of := w.cur
	if of == nil {
		return nil
	}
	of.fw.AppendKeyValueMetadata("mithril2pq.first_chunk", strconv.FormatInt(of.first, 10))
	of.fw.AppendKeyValueMetadata("mithril2pq.last_chunk", strconv.FormatInt(of.last, 10))
	of.fw.AppendKeyValueMetadata("mithril2pq.schema_version", strconv.Itoa(schema.Version))
	if err := of.fw.Close(); err != nil { // also closes the file
		return w.fail(fmt.Errorf("closing %s: %w", of.tmp, err))
	}
	w.cur = nil
	if err := os.Rename(of.tmp, of.final); err != nil {
		os.Remove(of.tmp)
		return fmt.Errorf("renaming %s: %w", of.tmp, err)
	}
	w.files = append(w.files, File{
		Name: filepath.Base(of.final), Rows: of.rows, Bytes: of.cw.n.Load(),
		FirstChunk: of.first, LastChunk: of.last,
	})
	if w.opts.Counters != nil {
		w.opts.Counters.FilesWritten.Add(1)
	}
	return nil
}

// Finish completes the open file, if any, for a commit. The next write
// opens a new file, absorbing the last one if it is small.
func (w *TableWriter) Finish() error {
	if err := w.finish(); err != nil {
		return err
	}
	w.tailReopened = false
	return nil
}

// Files returns the table's files as the next manifest should list them.
// Call it after Finish.
func (w *TableWriter) Files() []File { return append([]File(nil), w.files...) }

// Abort discards the open file.
func (w *TableWriter) Abort() {
	if w.cur != nil {
		w.cur.f.Close()
		os.Remove(w.cur.tmp)
		w.cur = nil
	}
}

func (w *TableWriter) fail(err error) error {
	w.Abort()
	return err
}

type countingWriter struct {
	w        io.Writer
	n        atomic.Int64
	counters *Counters
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	if c.counters != nil {
		c.counters.BytesWritten.Add(int64(n))
	}
	return n, err
}

// Close lets pqarrow close the underlying file when the writer closes. The
// file is synced first: the manifest will soon list it, and the manifest is
// itself synced.
func (c *countingWriter) Close() error {
	if f, ok := c.w.(*os.File); ok {
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
	}
	if cl, ok := c.w.(io.Closer); ok {
		return cl.Close()
	}
	return nil
}
