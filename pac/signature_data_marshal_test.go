package pac

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hstern/krb5/test/testdata"
)

func TestSignatureData_Marshal_RoundTrip(t *testing.T) {
	t.Parallel()

	for _, vector := range []string{
		testdata.MarshaledPAC_Server_Signature,
		testdata.MarshaledPAC_KDC_Signature,
	} {
		b, err := hex.DecodeString(vector)
		require.NoError(t, err)

		var orig SignatureData
		_, err = orig.Unmarshal(b)
		require.NoError(t, err)

		mb, err := orig.Marshal()
		require.NoError(t, err)

		assert.Equal(t, b, mb, "SignatureData marshal not byte-identical")

		var got SignatureData
		_, err = got.Unmarshal(mb)
		require.NoError(t, err)
		assert.True(t, reflect.DeepEqual(orig, got), "SignatureData round trip mismatch")
	}
}
