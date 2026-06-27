package pac

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hstern/krb5/test/testdata"
)

func TestClientInfo_Marshal_RoundTrip(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_Client_Info)
	require.NoError(t, err)

	var orig ClientInfo
	require.NoError(t, orig.Unmarshal(b))

	mb, err := orig.Marshal()
	require.NoError(t, err)

	var got ClientInfo
	require.NoError(t, got.Unmarshal(mb))

	assert.True(t, reflect.DeepEqual(orig, got),
		"ClientInfo did not survive Marshal round trip: %+v vs %+v", orig, got)
}
