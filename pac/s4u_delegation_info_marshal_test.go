package pac

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/rpc/mstypes"
)

func TestS4UDelegationInfo_Marshal_RoundTrip(t *testing.T) {
	t.Parallel()

	orig := S4UDelegationInfo{
		S4U2proxyTarget:      mstypes.RPCUnicodeString{Length: 6, MaximumLength: 8, Value: "abc"},
		TransitedListSize:    0,
		S4UTransitedServices: nil,
	}

	mb, err := orig.Marshal()
	require.NoError(t, err)

	var got S4UDelegationInfo
	require.NoError(t, got.Unmarshal(mb))

	assert.True(t, reflect.DeepEqual(orig, got),
		"S4UDelegationInfo did not survive Marshal round trip: %+v vs %+v", orig, got)
}
