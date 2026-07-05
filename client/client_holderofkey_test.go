package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hstern/krb5/config"
	"github.com/hstern/krb5/credentials"
	"github.com/hstern/krb5/iana"
	"github.com/hstern/krb5/iana/nametype"
	"github.com/hstern/krb5/messages"
	"github.com/hstern/krb5/types"
)

// TestNewFromCCache_HolderOfKey verifies the holder-of-key case: a ccache that
// holds a single service ticket and its session key, with no krbtgt entry,
// builds a client and serves that ticket offline (no KDC, no TGS exchange).
func TestNewFromCCache_HolderOfKey(t *testing.T) {
	t.Parallel()

	const (
		realm = "TEST.GOKRB5"
		spn   = "HTTP/host.test.gokrb5"
	)

	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn)
	tkt := messages.Ticket{
		TktVNO:  iana.PVNO,
		Realm:   realm,
		SName:   sname,
		EncPart: types.EncryptedData{EType: 18, KVNO: 1, Cipher: []byte("ciphertext")},
	}

	tb, err := tkt.Marshal()
	require.NoError(t, err)

	now := time.Now().UTC()
	clientName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "testuser")

	cc := credentials.NewV4CCache()
	cc.SetDefaultPrincipal(credentials.NewPrincipal(clientName, realm))
	cc.AddCredential(&credentials.Credential{
		Client:    credentials.NewPrincipal(clientName, realm),
		Server:    credentials.NewPrincipal(sname, realm),
		Key:       types.EncryptionKey{KeyType: 18, KeyValue: []byte("0123456789abcdef0123456789abcdef")},
		AuthTime:  now.Add(-time.Hour),
		StartTime: now.Add(-time.Hour),
		EndTime:   now.Add(time.Hour),
		Ticket:    tb,
	})

	// No krbtgt entry: the holder-of-key case that NewFromCCache used to reject.
	cl, err := NewFromCCache(cc, config.New())
	require.NoError(t, err)
	require.NotNil(t, cl)

	// The client principal is taken from the ccache default principal.
	assert.Equal(t, "testuser", cl.Credentials.UserName())

	// The service ticket is served straight from the cache: no KDC, no session.
	got, key, err := cl.GetServiceTicket(spn)
	require.NoError(t, err)
	assert.Equal(t, spn, got.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)
}
