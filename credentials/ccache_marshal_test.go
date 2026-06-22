package credentials

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/test/testdata"
)

func TestMarshalRoundTrip(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	require.NoError(t, err, "decode test data")

	c := new(CCache)
	require.NoError(t, c.Unmarshal(b), "unmarshal test ccache")

	marshalled, err := c.Marshal()
	require.NoError(t, err, "marshal ccache")

	assert.Equal(t, b, marshalled, "marshalled bytes must equal the original")
}
