package pac

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hstern/krb5/test/testdata"
)

func TestUPNDNSInfo_Marshal_RoundTrip(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_UPN_DNS_Info)
	require.NoError(t, err)

	var orig UPNDNSInfo
	require.NoError(t, orig.Unmarshal(b))

	mb, err := orig.Marshal()
	require.NoError(t, err)

	var got UPNDNSInfo
	require.NoError(t, got.Unmarshal(mb))

	assert.Equal(t, orig.UPN, got.UPN, "UPN not preserved")
	assert.Equal(t, orig.DNSDomain, got.DNSDomain, "DNSDomain not preserved")
	assert.Equal(t, orig.Flags, got.Flags, "Flags not preserved")

	// The base UPN_DNS_INFO layout 8-aligns each section, so the marshal is
	// byte-identical to the captured vector.
	assert.Equal(t, b, mb, "UPN_DNS_INFO marshal not byte-identical to vector")
}
