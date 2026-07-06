package pac

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hstern/krb5/test/testdata"
)

func TestKerbValidationInfo_Marshal_RoundTrip(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_Kerb_Validation_Info_MS)
	require.NoError(t, err)

	var orig KerbValidationInfo
	require.NoError(t, orig.Unmarshal(b))

	mb, err := orig.Marshal()
	require.NoError(t, err)

	var got KerbValidationInfo
	require.NoError(t, got.Unmarshal(mb))

	assert.True(t, reflect.DeepEqual(orig, got),
		"KerbValidationInfo did not survive Marshal round trip")
}
