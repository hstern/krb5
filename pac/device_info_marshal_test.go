package pac

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/rpc/mstypes"
)

func TestDeviceInfo_Marshal_RoundTrip(t *testing.T) {
	t.Parallel()

	orig := DeviceInfo{
		UserID:         500,
		PrimaryGroupID: 513,
		AccountDomainID: mstypes.RPCSID{
			Revision:            1,
			SubAuthorityCount:   1,
			IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
			SubAuthority:        []uint32{21},
		},
		AccountGroupCount: 1,
		AccountGroupIDs: []mstypes.GroupMembership{
			{RelativeID: 513, Attributes: 7},
		},
		SIDCount:         0,
		ExtraSIDs:        nil,
		DomainGroupCount: 0,
		DomainGroup:      nil,
	}

	mb, err := orig.Marshal()
	require.NoError(t, err)

	var got DeviceInfo
	require.NoError(t, got.Unmarshal(mb))

	assert.True(t, reflect.DeepEqual(orig, got),
		"DeviceInfo did not survive Marshal round trip: %+v vs %+v", orig, got)
}
