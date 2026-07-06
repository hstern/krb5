package pac

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/hstern/x/rpc/mstypes"
)

func TestPACWriter(t *testing.T) {
	t.Parallel()

	w := newPACWriter()
	w.writeUint16(0x0302)
	w.writeUint32(0x07060504)
	w.writeBytes([]byte{0xaa, 0xbb})
	w.writeUTF16("Ab")
	w.writeFileTime(mstypes.FileTime{LowDateTime: 0x11223344, HighDateTime: 0x55667788})

	got := w.bytes()
	want := []byte{
		0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0xaa, 0xbb,
		'A', 0x00, 'b', 0x00,
		0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55,
	}
	assert.Equal(t, want, got)
}
