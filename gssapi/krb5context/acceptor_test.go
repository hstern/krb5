package krb5context

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func httpServiceKeytab(t *testing.T) *keytab.Keytab {
	t.Helper()

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(mustHex(t, testdata.HTTP_KEYTAB)))

	return kt
}

func testClient(t *testing.T) *client.Client {
	t.Helper()

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(mustHex(t, testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)))

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	return client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
}

// verifiableTicket mints a service ticket (and its session key) encrypted under
// the HTTP service keytab, so service.VerifyAPREQ can validate it offline.
func verifiableTicket(t *testing.T, cl *client.Client, kt *keytab.Keytab) (messages.Ticket, types.EncryptionKey) {
	t.Helper()

	sname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"HTTP", "host.test.gokrb5"}}
	st := time.Now().UTC()

	tkt, key, err := messages.NewTicket(
		cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(), kt, 18, 1,
		st, st, st.Add(24*time.Hour), st.Add(48*time.Hour),
	)
	require.NoError(t, err)

	return tkt, key
}

func TestAcceptSecContextEndToEndWithInitiator(t *testing.T) {
	t.Parallel()

	kt := httpServiceKeytab(t)
	cl := testClient(t)
	tkt, sessionKey := verifiableTicket(t, cl, kt)

	init := &Initiator{
		tickets: fakeTickets{tkt: tkt, key: sessionKey},
		creds:   cl.Credentials,
		spn:     "HTTP/host.test.gokrb5",
		flags:   []int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg, gssapi.ContextFlagConf},
	}

	apReqTok, done, err := init.InitSecContext(nil)
	require.NoError(t, err)
	require.False(t, done)

	acc := NewAcceptor(kt)

	apRepTok, done, err := acc.AcceptSecContext(apReqTok)
	require.NoError(t, err)
	require.True(t, done)
	require.NotEmpty(t, apRepTok)

	out, done, err := init.InitSecContext(apRepTok)
	require.NoError(t, err)
	require.True(t, done)
	require.Nil(t, out)

	initCtx, err := init.Context()
	require.NoError(t, err)

	accCtx, err := acc.Context()
	require.NoError(t, err)

	// Both ends derived the same per-message key (the acceptor subkey).
	assert.Equal(t, initCtx.Key.KeyValue, accCtx.Key.KeyValue)

	// Initiator wraps, acceptor unwraps.
	wt, err := initCtx.Wrap([]byte("client says hi"))
	require.NoError(t, err)
	ok, err := accCtx.Unwrap(wt)
	require.NoError(t, err)
	assert.True(t, ok)

	// Acceptor signs a MIC, initiator verifies it.
	mt, err := accCtx.MIC([]byte("server signs"))
	require.NoError(t, err)
	ok, err = initCtx.VerifyMIC([]byte("server signs"), mt)
	require.NoError(t, err)
	assert.True(t, ok)

	// The acceptor propagated the initiator's requested flags.
	assert.Contains(t, accCtx.Flags, gssapi.ContextFlagMutual)

	// The acceptor exposes the authenticated client's identity.
	creds := acc.Credentials()
	require.NotNil(t, creds)
	assert.Equal(t, "testuser1", creds.UserName())
}

func TestParseGSSChecksum(t *testing.T) {
	t.Parallel()

	chk := spnego.NewAuthenticatorChksum([]int{gssapi.ContextFlagMutual, gssapi.ContextFlagConf}, nil)

	flags, bnd, err := parseGSSChecksum(types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: chk})
	require.NoError(t, err)
	assert.Contains(t, flags, gssapi.ContextFlagMutual)
	assert.Contains(t, flags, gssapi.ContextFlagConf)
	assert.Len(t, bnd, 16)

	// A non-GSSAPI checksum type is rejected rather than trusted.
	_, _, err = parseGSSChecksum(types.Checksum{CksumType: 1, Checksum: chk})
	require.Error(t, err)

	// A GSSAPI checksum too short to hold the flags word is rejected.
	_, _, err = parseGSSChecksum(types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: []byte{0x10, 0x00, 0x00, 0x00}})
	require.Error(t, err)
}

func TestAcceptSecContextEnforcesChannelBindings(t *testing.T) {
	t.Parallel()

	kt := httpServiceKeytab(t)
	cl := testClient(t)
	cb := &gssapi.ChannelBindings{ApplicationData: []byte("tls-server-end-point:deadbeef")}

	newBoundInitiator := func() *Initiator {
		tkt, key := verifiableTicket(t, cl, kt)

		return &Initiator{
			tickets: fakeTickets{tkt: tkt, key: key},
			creds:   cl.Credentials,
			spn:     "HTTP/host.test.gokrb5",
			flags:   []int{gssapi.ContextFlagMutual},
			cb:      cb,
		}
	}

	// Matching bindings: accepted.
	tok, _, err := newBoundInitiator().InitSecContext(nil)
	require.NoError(t, err)

	_, done, err := NewAcceptor(kt, ExpectChannelBindings(cb)).AcceptSecContext(tok)
	require.NoError(t, err)
	assert.True(t, done)

	// Mismatched bindings: rejected with a framed KRB-ERROR token.
	tok2, _, err := newBoundInitiator().InitSecContext(nil)
	require.NoError(t, err)

	other := &gssapi.ChannelBindings{ApplicationData: []byte("tls-server-end-point:feedface")}
	out, done, err := NewAcceptor(kt, ExpectChannelBindings(other)).AcceptSecContext(tok2)
	require.Error(t, err)
	assert.False(t, done)
	assert.NotEmpty(t, out)
}

func TestAcceptSecContextFramesKRBErrorForInitiator(t *testing.T) {
	kt := httpServiceKeytab(t)
	cl := testClient(t)
	tkt, key := verifiableTicket(t, cl, kt)

	init := &Initiator{
		tickets: fakeTickets{tkt: tkt, key: key},
		creds:   cl.Credentials,
		spn:     "HTTP/host.test.gokrb5",
		flags:   []int{gssapi.ContextFlagMutual},
	}

	tok, _, err := init.InitSecContext(nil)
	require.NoError(t, err)

	// First acceptance succeeds; a replay of the same token is rejected.
	_, done, err := NewAcceptor(kt).AcceptSecContext(tok)
	require.NoError(t, err)
	require.True(t, done)

	out, done, err := NewAcceptor(kt).AcceptSecContext(tok)
	require.Error(t, err)
	require.False(t, done)
	require.NotEmpty(t, out)

	// The initiator surfaces the acceptor's KRB-ERROR from the framed token.
	_, idone, ierr := init.InitSecContext(out)
	require.Error(t, ierr)
	assert.False(t, idone)

	var kerr messages.KRBError
	require.ErrorAs(t, ierr, &kerr)
	assert.Equal(t, errorcode.KRB_AP_ERR_REPEAT, kerr.ErrorCode)
}

func TestAcceptSecContextRejectsWrongKeytab(t *testing.T) {
	t.Parallel()

	kt := httpServiceKeytab(t)
	cl := testClient(t)
	tkt, sessionKey := verifiableTicket(t, cl, kt)

	init := &Initiator{
		tickets: fakeTickets{tkt: tkt, key: sessionKey},
		creds:   cl.Credentials,
		spn:     "HTTP/host.test.gokrb5",
		flags:   []int{gssapi.ContextFlagMutual},
	}

	apReqTok, _, err := init.InitSecContext(nil)
	require.NoError(t, err)

	// An acceptor holding a different service key cannot decrypt the ticket.
	wrongKt := keytab.New()
	require.NoError(t, wrongKt.Unmarshal(mustHex(t, testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)))
	acc := NewAcceptor(wrongKt)

	_, done, err := acc.AcceptSecContext(apReqTok)
	require.Error(t, err)
	assert.False(t, done)
}

func TestAcceptSecContextRejectsNonAPReqToken(t *testing.T) {
	t.Parallel()

	acc := NewAcceptor(httpServiceKeytab(t))

	_, done, err := acc.AcceptSecContext([]byte{0x00, 0x01, 0x02})
	require.Error(t, err)
	assert.False(t, done)
}

func TestAcceptorContextBeforeEstablishedErrors(t *testing.T) {
	t.Parallel()

	acc := NewAcceptor(httpServiceKeytab(t))

	_, err := acc.Context()
	require.Error(t, err)
}
