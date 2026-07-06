package pac

import (
	"bytes"
	"encoding/hex"
	"log"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hstern/krb5/crypto"
	"github.com/hstern/krb5/iana/keyusage"
	"github.com/hstern/krb5/keytab"
	"github.com/hstern/krb5/test/testdata"
	"github.com/hstern/krb5/types"
)

func TestPACType_Marshal_Layout(t *testing.T) {
	t.Parallel()

	kviB, err := hex.DecodeString(testdata.MarshaledPAC_Kerb_Validation_Info_MS)
	require.NoError(t, err)
	var kvi KerbValidationInfo
	require.NoError(t, kvi.Unmarshal(kviB))

	ciB, err := hex.DecodeString(testdata.MarshaledPAC_Client_Info)
	require.NoError(t, err)
	var ci ClientInfo
	require.NoError(t, ci.Unmarshal(ciB))

	pac := &PACType{
		Version:            0,
		KerbValidationInfo: &kvi,
		ClientInfo:         &ci,
	}

	b, err := pac.Marshal()
	require.NoError(t, err)

	var got PACType
	require.NoError(t, got.Unmarshal(b))

	assert.Equal(t, uint32(2), got.CBuffers, "buffer count")
	require.Len(t, got.Buffers, 2)
	for _, buf := range got.Buffers {
		assert.Zero(t, buf.Offset%8, "buffer offset must be 8-aligned")
	}

	var gotKVI KerbValidationInfo
	for _, buf := range got.Buffers {
		if buf.ULType == infoTypeKerbValidationInfo {
			require.NoError(t, gotKVI.Unmarshal(b[buf.Offset:buf.Offset+uint64(buf.CBBufferSize)]))
		}
	}
	assert.True(t, reflect.DeepEqual(kvi, gotKVI), "KerbValidationInfo not preserved through container")
}

func TestPACType_SignAndMarshal_Verify(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_AD_WIN2K_PAC)
	require.NoError(t, err)

	var pac PACType
	require.NoError(t, pac.Unmarshal(b))

	ktb, _ := hex.DecodeString(testdata.KEYTAB_SYSHTTP_TEST_GOKRB5)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(ktb))
	pn, _ := types.ParseSPNString("sysHTTP")
	key, _, err := kt.GetEncryptionKey(pn, "TEST.GOKRB5", 2, 18)
	require.NoError(t, err)

	l := log.New(bytes.NewBufferString(""), "", 0)
	require.NoError(t, pac.ProcessPACInfoBuffers(key, l))

	// Re-sign with the same key for both server and KDC (verify only checks the
	// server checksum; the KDC checksum is asserted directly below).
	signed, err := pac.SignAndMarshal(key, key)
	require.NoError(t, err)

	var got PACType
	require.NoError(t, got.Unmarshal(signed))
	require.NoError(t, got.ProcessPACInfoBuffers(key, l)) // verifies the server checksum

	assert.True(t, reflect.DeepEqual(pac.KerbValidationInfo, got.KerbValidationInfo),
		"KerbValidationInfo not preserved through SignAndMarshal")
	assert.Equal(t, pac.ClientInfo.Name, got.ClientInfo.Name, "ClientInfo.Name not preserved")

	// The KDC signature is computed over the server signature bytes.
	et, err := crypto.GetEtype(key.KeyType)
	require.NoError(t, err)
	wantKDC, err := et.GetChecksumHash(key.KeyValue, got.ServerChecksum.Signature, keyusage.KERB_NON_KERB_CKSUM_SALT)
	require.NoError(t, err)
	assert.Equal(t, wantKDC, got.KDCChecksum.Signature, "KDC checksum incorrect")
}
