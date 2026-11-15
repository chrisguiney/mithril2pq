// mithril2pq downloads a Cardano database snapshot from a Mithril
// aggregator and writes its blocks as a set of flat Parquet tables.
//
// Each immutable file is verified against the snapshot's certified digest
// list, every block's CRC32 against the chunk's secondary index, and every
// block is decoded with gouroboros. Output is resumable: a later run applies
// only the chunks the output directory does not yet hold.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/chrisguiney/mithril2pq/internal/dataset"
	"github.com/chrisguiney/mithril2pq/internal/mithril"
	"github.com/chrisguiney/mithril2pq/internal/mithril/chain"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	cfg := config{}
	fileSize := sizeFlag{n: 128_000_000}
	flag.StringVar(&cfg.archive, "mithril-archive", "mainnet", "`network or URL`: mainnet, preprod, preview, or a Mithril aggregator URL")
	flag.StringVar(&cfg.snapshot, "snapshot", "", "snapshot `hash` to use (default: the aggregator's latest)")
	flag.StringVar(&cfg.out, "out", "", "output `directory` for the Parquet tables (required)")
	flag.StringVar(&cfg.cacheDir, "cache-dir", "", "`directory` to keep downloaded archives in, compressed (default: no cache)")
	flag.Var(&fileSize, "file-size", "target Parquet file `size`, e.g. 128MB, 3GB, 512MiB")
	flag.IntVar(&cfg.concurrency, "concurrency", 25, "concurrent `downloads`")
	flag.IntVar(&cfg.buffer, "buffer", 0, "without -cache-dir, the most downloaded `archives` held in memory ahead of the writer (default 2x -concurrency)")
	flag.IntVar(&cfg.workers, "workers", runtime.GOMAXPROCS(0), "concurrent chunk `decoders`")
	flag.DurationVar(&cfg.checkpoint, "checkpoint", 30*time.Minute, "commit progress at least this often (`duration`; 0 commits only at the end)")
	flag.StringVar(&cfg.compression, "compression", "zstd", "Parquet `codec`: zstd, snappy, gzip or none")
	flag.Int64Var(&cfg.lastChunk, "last-chunk", -1, "stop after this immutable file `number` (default: the snapshot's last)")
	flag.StringVar(&cfg.genesisKeyArg, "genesis-vkey", "", "Mithril genesis verification `key or file` (genesis.vkey format or 64 hex digits); required with an aggregator URL, overrides the pinned key of mainnet, preprod and preview")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s -out DIR [flags]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Convert a Mithril Cardano database snapshot into Parquet tables, or bring\nan existing output directory up to date.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	cfg.fileSize = fileSize.n

	if err := validate(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "mithril2pq: %v\n\n", err)
		flag.Usage()
		return 2
	}

	tty := term.IsTerminal(int(os.Stderr.Fd()))
	st := &stats{start: time.Now()}
	prog := newProgress(st, os.Stderr, tty)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopCh := make(chan struct{})
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		close(stopCh)
		<-sigs
		// Second signal: abort without committing. Committed data is
		// untouched; temporary files are removed here, and anything a
		// crash could leave is removed on the next run.
		prog.finish()
		fmt.Fprintln(os.Stderr, "mithril2pq: aborted; removing temporary files")
		removeTemps(cfg.out)
		removeCachePartials(cfg.cacheDir)
		os.Exit(130)
	}()

	prog.run()
	err := run(ctx, stopCh, cfg, st, prog)
	prog.print()
	prog.finish()
	summary(st)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errStopped):
		fmt.Fprintln(os.Stderr, "mithril2pq: stopped; progress is committed and the next run resumes from it")
		return 130
	default:
		fmt.Fprintf(os.Stderr, "mithril2pq: %s\n", explain(err))
		if !errors.Is(err, errStopped) && st.chunksWritten.Load() > 0 {
			fmt.Fprintln(os.Stderr, "mithril2pq: chunks written before the error are committed; rerun to continue")
		}
		return 1
	}
}

func validate(cfg *config) error {
	if cfg.out == "" {
		return errors.New("-out is required")
	}
	if cfg.fileSize < 1_000_000 {
		return fmt.Errorf("-file-size %s is too small; use at least 1MB", formatBytes(float64(cfg.fileSize)))
	}
	if cfg.concurrency < 1 {
		return errors.New("-concurrency must be at least 1")
	}
	if cfg.buffer == 0 {
		cfg.buffer = 2 * cfg.concurrency
	}
	if cfg.buffer < 1 {
		return errors.New("-buffer must be at least 1")
	}
	if cfg.workers < 1 {
		return errors.New("-workers must be at least 1")
	}
	if _, ok := dataset.Compressions[cfg.compression]; !ok {
		return fmt.Errorf("-compression %q is not one of zstd, snappy, gzip, none", cfg.compression)
	}
	_, network, err := mithril.ResolveAggregator(cfg.archive)
	if err != nil {
		return err
	}
	switch {
	case cfg.genesisKeyArg != "":
		if cfg.genesisKey, err = chain.ReadGenesisKey(cfg.genesisKeyArg); err != nil {
			return fmt.Errorf("-genesis-vkey: %w", err)
		}
	case network != "":
		cfg.genesisKey, _ = chain.NetworkGenesisKey(network)
	default:
		return fmt.Errorf("-genesis-vkey is required with an aggregator URL: certificates are verified back to a genesis certificate, and mithril2pq pins genesis keys only for mainnet, preprod and preview. Use the genesis.vkey file the aggregator's operator publishes")
	}
	return nil
}

func summary(st *stats) {
	el := time.Since(st.start)
	fmt.Fprintf(os.Stderr, "mithril2pq: %d chunks, %s blocks, %s transactions in %s; downloaded %s",
		st.chunksWritten.Load(), count(st.blocks.Load()), count(st.txs.Load()), fmtDuration(el),
		formatBytes(float64(st.bytesDownloaded.Load())))
	if h := st.cacheHits.Load(); h > 0 {
		fmt.Fprintf(os.Stderr, " (%d archives from cache)", h)
	}
	fmt.Fprintf(os.Stderr, "; wrote %d Parquet files, %s\n", st.pq.FilesWritten.Load(), formatBytes(float64(st.pq.BytesWritten.Load())))
	if e := st.decodeErrors.Load(); e > 0 {
		fmt.Fprintf(os.Stderr, "mithril2pq: %d blocks could not be decoded; their rows in the block table carry decode_error\n", e)
	}
}

// explain adds a hint to errors with a common, fixable cause.
func explain(err error) string {
	msg := err.Error()
	var dnsErr *net.DNSError
	var opErr *net.OpError
	var he *mithril.HTTPError
	switch {
	case errors.As(err, &dnsErr):
		return msg + "\n  (could not resolve a host name; check the network connection and -mithril-archive)"
	case errors.As(err, &opErr):
		return msg + "\n  (network error; check the connection, then rerun to continue)"
	case errors.As(err, &he) && he.Code == 404:
		return msg + "\n  (not found; the snapshot may have been pruned from the aggregator. Rerun without -snapshot to use the latest)"
	case errors.Is(err, syscall.ENOSPC):
		return msg + "\n  (free some space, then rerun to continue)"
	case errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission):
		return msg + "\n  (permission denied; check -out and -cache-dir)"
	case errors.Is(err, context.DeadlineExceeded):
		return msg + "\n  (timed out; rerun to continue)"
	case strings.Contains(msg, "certificate chain verification failed"):
		return msg + "\n  (the snapshot's certificate does not chain back to a genesis certificate signed by the genesis key; do not use this snapshot. With an aggregator URL, check -genesis-vkey)"
	case strings.Contains(msg, "verification failed"):
		return msg + "\n  (the aggregator's data does not match what its certificate signs; do not use this snapshot)"
	}
	return msg
}
