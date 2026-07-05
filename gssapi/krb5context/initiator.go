package krb5context

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/krb5/types"
)

// ticketGetter obtains a service ticket and its session key for an SPN. It is
// satisfied by *client.Client and abstracted so the Initiator can be exercised
// without a live KDC.
type ticketGetter interface {
	GetServiceTicket(spn string) (messages.Ticket, types.EncryptionKey, error)
}

// Initiator establishes a GSS-API security context as the client using the
// Kerberos 5 mechanism, independent of SPNEGO. It performs mutual
// authentication: the first InitSecContext call produces the initial-context
// token, and the second verifies the acceptor's AP-REP and completes the
// context.
type Initiator struct {
	tickets ticketGetter
	creds   *credentials.Credentials
	spn     string
	flags   []int
	cb      *gssapi.ChannelBindings

	sessionKey types.EncryptionKey
	auth       types.Authenticator
	secCtx     *gssapi.SecContext
	started    bool
	done       bool
}

// Option configures an Initiator.
type Option func(*Initiator)

// WithContextFlags sets the requested GSS-API context flags (see
// gssapi.ContextFlag*), replacing the default of mutual authentication with
// integrity. ContextFlagMutual is always included regardless of what is passed:
// this initiator only implements mutual authentication.
func WithContextFlags(f ...int) Option {
	return func(i *Initiator) { i.flags = f }
}

// WithChannelBindings sets the channel bindings carried in the authenticator
// checksum. Nil (the default) means GSS_C_NO_CHANNEL_BINDINGS.
func WithChannelBindings(cb *gssapi.ChannelBindings) Option {
	return func(i *Initiator) { i.cb = cb }
}

// NewInitiator returns an Initiator that authenticates cl's credentials to the
// service named by spn. By default it requests mutual authentication with
// integrity and confidentiality and no channel bindings; use the options to
// override.
func NewInitiator(cl *client.Client, spn string, opts ...Option) *Initiator {
	i := &Initiator{
		tickets: cl,
		creds:   cl.Credentials,
		spn:     spn,
		flags:   []int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg},
	}

	for _, opt := range opts {
		opt(i)
	}

	return i
}

// InitSecContext advances context establishment. The first call (in == nil)
// returns the initial-context token to send to the acceptor with done == false.
// The second call takes the acceptor's AP-REP token, verifies mutual
// authentication, and returns done == true.
func (i *Initiator) InitSecContext(in []byte) (out []byte, done bool, err error) {
	if !i.started {
		out, err = i.initialContextToken()

		return out, false, err
	}

	if err = i.consumeAPRep(in); err != nil {
		return nil, false, err
	}

	return nil, true, nil
}

// Context returns the established security context, or an error if context
// establishment has not completed.
func (i *Initiator) Context() (*gssapi.SecContext, error) {
	if !i.done || i.secCtx == nil {
		return nil, errors.New("security context is not yet established")
	}

	return i.secCtx, nil
}

// initialContextToken obtains the service ticket, builds the AP-REQ carrying the
// 0x8003 authenticator checksum with mutual-required AP-Options, and frames it
// as the initial-context token.
func (i *Initiator) initialContextToken() ([]byte, error) {
	// This initiator only implements mutual authentication, so ensure the
	// mutual flag is set: it keeps the authenticator checksum flags and the
	// mutual-required AP-Option in agreement.
	i.flags = ensureFlag(i.flags, gssapi.ContextFlagMutual)

	tkt, key, err := i.tickets.GetServiceTicket(i.spn)
	if err != nil {
		return nil, fmt.Errorf("obtaining service ticket for %q: %w", i.spn, err)
	}

	i.sessionKey = key

	auth, err := types.NewAuthenticator(i.creds.Domain(), i.creds.CName())
	if err != nil {
		return nil, fmt.Errorf("creating authenticator: %w", err)
	}

	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  spnego.NewAuthenticatorChksum(i.flags, i.cb),
	}
	i.auth = auth

	apReq, err := messages.NewAPReq(tkt, key, auth)
	if err != nil {
		return nil, fmt.Errorf("building AP-REQ: %w", err)
	}

	types.SetFlag(&apReq.APOptions, flags.APOptionMutualRequired)

	inner, err := apReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshaling AP-REQ: %w", err)
	}

	token, err := frameInitialContextToken(tokIDAPReq, inner)
	if err != nil {
		return nil, err
	}

	i.started = true

	return token, nil
}

// consumeAPRep unframes the acceptor's reply. A KRB-ERROR reply is surfaced as
// its messages.KRBError. Otherwise it decrypts the AP-REP, verifies mutual
// authentication by matching the echoed ctime/cusec against our authenticator,
// and establishes the security context.
func (i *Initiator) consumeAPRep(in []byte) error {
	tokID, inner, err := stripContextToken(in)
	if err != nil {
		return err
	}

	switch {
	case bytes.Equal(tokID, tokIDError):
		var kerr messages.KRBError
		if err := kerr.Unmarshal(inner); err != nil {
			return fmt.Errorf("unmarshaling KRB-ERROR from acceptor: %w", err)
		}

		return kerr
	case !bytes.Equal(tokID, tokIDAPRep):
		return fmt.Errorf("unexpected token ID %x from acceptor, want AP-REP", tokID)
	}

	var apRep messages.APRep
	if err := apRep.Unmarshal(inner); err != nil {
		return fmt.Errorf("unmarshaling AP-REP: %w", err)
	}

	plain, err := crypto.DecryptEncPart(apRep.EncPart, i.sessionKey, keyusage.AP_REP_ENCPART)
	if err != nil {
		return fmt.Errorf("decrypting AP-REP: %w", err)
	}

	var enc messages.EncAPRepPart
	if err := enc.Unmarshal(plain); err != nil {
		return fmt.Errorf("unmarshaling AP-REP encrypted part: %w", err)
	}

	// The authenticator's ctime is transmitted at second precision, so compare
	// seconds plus the microsecond cusec rather than the in-memory time.Time.
	if enc.CTime.Unix() != i.auth.CTime.Unix() || enc.Cusec != i.auth.Cusec {
		return errors.New("mutual authentication failed: AP-REP time does not match authenticator")
	}

	// Per-message key: the acceptor's subkey if it asserted one, else the
	// ticket session key.
	key := i.sessionKey
	acceptorSubkey := len(enc.Subkey.KeyValue) > 0
	if acceptorSubkey {
		key = enc.Subkey
	}

	i.secCtx = gssapi.NewSecContext(key, i.flags, true, acceptorSubkey, uint64(i.auth.SeqNumber))
	i.done = true

	return nil
}

// ensureFlag returns flags with flag appended if it is not already present.
func ensureFlag(flags []int, flag int) []int {
	if slices.Contains(flags, flag) {
		return flags
	}

	return append(flags, flag)
}
