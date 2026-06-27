package pac

import (
	"bytes"
	"encoding/binary"

	"github.com/hstern/x/rpc/mstypes"
)

// pacWriter accumulates little-endian bytes for the non-NDR PAC buffer types,
// mirroring mstypes.Reader.
type pacWriter struct {
	buf *bytes.Buffer
}

func newPACWriter() *pacWriter {
	return &pacWriter{buf: new(bytes.Buffer)}
}

// align8 rounds n up to the next multiple of 8.
func align8(n int) int {
	if r := n % 8; r != 0 {
		return n + (8 - r)
	}

	return n
}

func (w *pacWriter) bytes() []byte {
	return w.buf.Bytes()
}

func (w *pacWriter) writeUint16(v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	w.buf.Write(b[:])
}

func (w *pacWriter) writeUint32(v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	w.buf.Write(b[:])
}

func (w *pacWriter) writeBytes(b []byte) {
	w.buf.Write(b)
}

func (w *pacWriter) writeFileTime(ft mstypes.FileTime) {
	w.writeUint32(ft.LowDateTime)
	w.writeUint32(ft.HighDateTime)
}

// writeUTF16 writes s as UTF-16LE, one uint16 per rune, mirroring
// mstypes.Reader.UTF16String (which reads rune(uint16); BMP only).
func (w *pacWriter) writeUTF16(s string) {
	for _, r := range s {
		w.writeUint16(uint16(r))
	}
}
