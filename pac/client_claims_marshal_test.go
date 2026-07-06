package pac

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hstern/krb5/test/testdata"
)

func TestClientClaimsInfo_Marshal_RoundTrip(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfoStr)
	require.NoError(t, err)

	var orig ClientClaimsInfo
	require.NoError(t, orig.Unmarshal(b))

	mb, err := orig.Marshal()
	require.NoError(t, err)

	var got ClientClaimsInfo
	require.NoError(t, got.Unmarshal(mb))

	assert.True(t, reflect.DeepEqual(orig, got),
		"ClientClaimsInfo did not survive Marshal round trip")
}
