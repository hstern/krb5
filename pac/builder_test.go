package pac

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestBuilder_SignAndMarshal(t *testing.T) {
	t.Parallel()

	kviB, err := hex.DecodeString(testdata.MarshaledPAC_Kerb_Validation_Info_MS)
	require.NoError(t, err)
	var kvi KerbValidationInfo
	require.NoError(t, kvi.Unmarshal(kviB))

	ciB, err := hex.DecodeString(testdata.MarshaledPAC_Client_Info)
	require.NoError(t, err)
	var ci ClientInfo
	require.NoError(t, ci.Unmarshal(ciB))

	ktb, _ := hex.DecodeString(testdata.KEYTAB_SYSHTTP_TEST_GOKRB5)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(ktb))
	pn, _ := types.ParseSPNString("sysHTTP")
	key, _, err := kt.GetEncryptionKey(pn, "TEST.GOKRB5", 2, 18)
	require.NoError(t, err)

	b, err := NewPAC().
		WithKerbValidationInfo(&kvi).
		WithClientInfo(&ci).
		SignAndMarshal(key, key)
	require.NoError(t, err)

	var got PACType
	require.NoError(t, got.Unmarshal(b))
	l := log.New(bytes.NewBufferString(""), "", 0)
	require.NoError(t, got.ProcessPACInfoBuffers(key, l))
	assert.Equal(t, ci.Name, got.ClientInfo.Name)
}

func TestBuilder_RequiresKVIAndClientInfo(t *testing.T) {
	t.Parallel()

	_, err := NewPAC().SignAndMarshal(types.EncryptionKey{}, types.EncryptionKey{})
	require.Error(t, err)
}
