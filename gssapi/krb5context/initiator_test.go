package krb5context

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/hstern/x/encoding/asn1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hstern/krb5/asn1tools"
	"github.com/hstern/krb5/credentials"
	"github.com/hstern/krb5/crypto"
	"github.com/hstern/krb5/gssapi"
	"github.com/hstern/krb5/iana"
	"github.com/hstern/krb5/iana/asn1apptag"
	"github.com/hstern/krb5/iana/errorcode"
	"github.com/hstern/krb5/iana/flags"
	"github.com/hstern/krb5/iana/keyusage"
	"github.com/hstern/krb5/iana/msgtype"
	"github.com/hstern/krb5/iana/nametype"
	"github.com/hstern/krb5/messages"
	"github.com/hstern/krb5/test/testdata"
	"github.com/hstern/krb5/types"
)

// fakeTickets is an offline ticketGetter returning a pre-minted ticket + key.
type fakeTickets struct {
	tkt messages.Ticket
	key types.EncryptionKey
	err error
}

func (f fakeTickets) GetServiceTicket(string) (messages.Ticket, types.EncryptionKey, error) {
	return f.tkt, f.key, f.err
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)

	return b
}

// testSessionKey is an aes128-cts-hmac-sha1-96 (etype 17) key.
func testSessionKey(t *testing.T) types.EncryptionKey {
	return types.EncryptionKey{KeyType: 17, KeyValue: mustHex(t, "14f9bde6b50ec508201a97f74c4e5bd3")}
}

func testInitiator(t *testing.T, ctxFlags []int, cb *gssapi.ChannelBindings) *Initiator {
	t.Helper()

	var tkt messages.Ticket
	require.NoError(t, tkt.Unmarshal(mustHex(t, testdata.MarshaledKRB5ticket)))

	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})

	return &Initiator{
		tickets: fakeTickets{tkt: tkt, key: testSessionKey(t)},
		creds:   creds,
		spn:     "HTTP/host.test.gokrb5",
		flags:   ctxFlags,
		cb:      cb,
	}
}

// buildTestAPRep hand-assembles the acceptor's AP-REP token echoing auth's
// ctime/cusec, encrypted under key. It marshals EncAPRepPart directly (not via
// messages.Marshal) so this test does not depend on PR A (#98).
func buildTestAPRep(t *testing.T, auth types.Authenticator, key types.EncryptionKey, subkey *types.EncryptionKey, seq int64) []byte {
	t.Helper()

	enc := messages.EncAPRepPart{
		CTime:          auth.CTime,
		Cusec:          auth.Cusec,
		SequenceNumber: seq,
	}
	if subkey != nil {
		enc.Subkey = *subkey
	}

	encB, err := asn1.Marshal(enc, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)
	encB = asn1tools.AddASNAppTag(encB, asn1apptag.EncAPRepPart)

	ed, err := crypto.GetEncryptedData(encB, key, keyusage.AP_REP_ENCPART, 0)
	require.NoError(t, err)

	apRep := messages.APRep{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REP, EncPart: ed}

	repB, err := asn1.Marshal(apRep, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)
	repB = asn1tools.AddASNAppTag(repB, asn1apptag.APREP)

	framed, err := frameInitialContextToken(tokIDAPRep, repB)
	require.NoError(t, err)

	return framed
}

func TestInitSecContextFirstCallProducesInitialContextToken(t *testing.T) {
	t.Parallel()

	i := testInitiator(t, []int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)

	out, done, err := i.InitSecContext(nil)
	require.NoError(t, err)
	assert.False(t, done)
	require.NotEmpty(t, out)
	assert.Equal(t, byte(0x60), out[0])

	inner, err := unframeInitialContextToken(out, tokIDAPReq)
	require.NoError(t, err)

	var apReq messages.APReq
	require.NoError(t, apReq.Unmarshal(inner))
	assert.True(t, types.IsFlagSet(&apReq.APOptions, flags.APOptionMutualRequired))
}

func TestInitSecContextSecondCallEstablishesContext(t *testing.T) {
	t.Parallel()

	i := testInitiator(t, []int{gssapi.ContextFlagMutual}, nil)

	_, _, err := i.InitSecContext(nil)
	require.NoError(t, err)

	subkey := types.EncryptionKey{KeyType: 17, KeyValue: mustHex(t, "00112233445566778899aabbccddeeff")}
	apRep := buildTestAPRep(t, i.auth, i.sessionKey, &subkey, 42)

	out, done, err := i.InitSecContext(apRep)
	require.NoError(t, err)
	assert.True(t, done)
	assert.Nil(t, out)

	sc, err := i.Context()
	require.NoError(t, err)
	assert.Equal(t, subkey.KeyValue, sc.Key.KeyValue)
}

func TestInitSecContextFallsBackToSessionKeyWithoutSubkey(t *testing.T) {
	t.Parallel()

	i := testInitiator(t, []int{gssapi.ContextFlagMutual}, nil)

	_, _, err := i.InitSecContext(nil)
	require.NoError(t, err)

	apRep := buildTestAPRep(t, i.auth, i.sessionKey, nil, 7)

	_, done, err := i.InitSecContext(apRep)
	require.NoError(t, err)
	require.True(t, done)

	sc, err := i.Context()
	require.NoError(t, err)
	assert.Equal(t, i.sessionKey.KeyValue, sc.Key.KeyValue)
}

func TestInitSecContextRejectsMismatchedAuthenticatorTime(t *testing.T) {
	t.Parallel()

	i := testInitiator(t, []int{gssapi.ContextFlagMutual}, nil)

	_, _, err := i.InitSecContext(nil)
	require.NoError(t, err)

	badAuth := i.auth
	badAuth.Cusec = i.auth.Cusec + 1
	apRep := buildTestAPRep(t, badAuth, i.sessionKey, nil, 1)

	_, done, err := i.InitSecContext(apRep)
	require.Error(t, err)
	assert.False(t, done)
}

func TestInitSecContextCarriesChannelBindingsInChecksum(t *testing.T) {
	t.Parallel()

	cb := &gssapi.ChannelBindings{ApplicationData: []byte("tls-server-end-point:abc123")}
	i := testInitiator(t, []int{gssapi.ContextFlagMutual}, cb)

	out, _, err := i.InitSecContext(nil)
	require.NoError(t, err)

	inner, err := unframeInitialContextToken(out, tokIDAPReq)
	require.NoError(t, err)

	var apReq messages.APReq
	require.NoError(t, apReq.Unmarshal(inner))

	plain, err := crypto.DecryptEncPart(apReq.EncryptedAuthenticator, i.sessionKey, keyusage.AP_REQ_AUTHENTICATOR)
	require.NoError(t, err)

	var auth types.Authenticator
	require.NoError(t, auth.Unmarshal(plain))

	// Bnd occupies bytes [4:20] of the 0x8003 checksum (RFC 4121 §4.1.1.2).
	require.GreaterOrEqual(t, len(auth.Cksum.Checksum), 20)
	assert.Equal(t, cb.Bytes(), auth.Cksum.Checksum[4:20])
}

func TestInitSecContextForcesMutualFlag(t *testing.T) {
	t.Parallel()

	// A caller requesting a non-mutual context still gets mutual: this initiator
	// is mutual-only, and the AP-Options must agree with the checksum flags.
	i := testInitiator(t, []int{gssapi.ContextFlagInteg}, nil)

	out, done, err := i.InitSecContext(nil)
	require.NoError(t, err)
	require.False(t, done)

	inner, err := unframeInitialContextToken(out, tokIDAPReq)
	require.NoError(t, err)

	var apReq messages.APReq
	require.NoError(t, apReq.Unmarshal(inner))
	assert.True(t, types.IsFlagSet(&apReq.APOptions, flags.APOptionMutualRequired))

	plain, err := crypto.DecryptEncPart(apReq.EncryptedAuthenticator, i.sessionKey, keyusage.AP_REQ_AUTHENTICATOR)
	require.NoError(t, err)

	var auth types.Authenticator
	require.NoError(t, auth.Unmarshal(plain))

	// GSS context flags occupy bytes [20:24] of the 0x8003 checksum.
	cksumFlags := binary.LittleEndian.Uint32(auth.Cksum.Checksum[20:24])
	assert.NotZero(t, cksumFlags&uint32(gssapi.ContextFlagMutual))
}

func TestInitSecContextSurfacesKRBError(t *testing.T) {
	t.Parallel()

	i := testInitiator(t, []int{gssapi.ContextFlagMutual}, nil)

	_, _, err := i.InitSecContext(nil)
	require.NoError(t, err)

	kerr := messages.NewKRBError(
		types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"HTTP", "host.test.gokrb5"}},
		testdata.TEST_REALM, errorcode.KRB_AP_ERR_SKEW, "clock skew too great",
	)

	kb, err := kerr.Marshal()
	require.NoError(t, err)

	framed, err := frameInitialContextToken(tokIDError, kb)
	require.NoError(t, err)

	_, done, err := i.InitSecContext(framed)
	require.Error(t, err)
	assert.False(t, done)

	var got messages.KRBError
	require.ErrorAs(t, err, &got)
	assert.Equal(t, errorcode.KRB_AP_ERR_SKEW, got.ErrorCode)
}

func TestContextBeforeEstablishedErrors(t *testing.T) {
	t.Parallel()

	i := testInitiator(t, nil, nil)

	_, err := i.Context()
	require.Error(t, err)
}
