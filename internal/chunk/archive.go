package chunk

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"path"

	"github.com/klauspost/compress/zstd"
)

// maxFileSize bounds a single file read out of an archive, so a hostile or
// corrupt archive cannot make the reader allocate without limit. Mainnet
// chunk files are tens of megabytes.
const maxFileSize = 1 << 30

// FileName returns the file name of an immutable file, e.g. "00042.chunk".
func FileName(number uint64, ext string) string {
	return fmt.Sprintf("%05d.%s", number, ext)
}

// ReadArchive decompresses a Mithril immutable-file archive (a zstd tarball
// of immutable/NNNNN.{chunk,primary,secondary}) into memory.
func ReadArchive(r io.Reader, number uint64) (Files, error) {
	zr, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1))
	if err != nil {
		return Files{}, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	var f Files
	want := map[string]*[]byte{
		FileName(number, "chunk"):     &f.Chunk,
		FileName(number, "primary"):   &f.Primary,
		FileName(number, "secondary"): &f.Secondary,
	}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Files{}, fmt.Errorf("reading archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		dst, ok := want[path.Base(h.Name)]
		if !ok {
			continue
		}
		if h.Size > maxFileSize {
			return Files{}, fmt.Errorf("archive member %s is %d bytes, over the %d-byte limit", h.Name, h.Size, maxFileSize)
		}
		buf := make([]byte, h.Size)
		if _, err := io.ReadFull(tr, buf); err != nil {
			return Files{}, fmt.Errorf("reading %s from archive: %w", h.Name, err)
		}
		*dst = buf
	}
	for name, dst := range want {
		if *dst == nil {
			return Files{}, fmt.Errorf("archive has no %s", name)
		}
	}
	return f, nil
}
