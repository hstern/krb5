package krb5context

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/types"
)

// Acceptor establishes a GSS-API security context as the service using the
// Kerberos 5 mechanism, without the SPNEGO negotiation layer. AcceptSecContext
// verifies the initiator's AP-REQ against the service keytab and produces the
// AP-REP that completes mutual authentication.
//
// The Acceptor always emits an AP-REP on success: it implements mutual
// authentication, the mirror of this package's Initiator. On failure it frames
// the KRB-ERROR as an output token so the initiator can surface the reason.
type Acceptor struct {
	settings *service.Settings
	cb       *gssapi.ChannelBindings
	creds    *credentials.Credentials
	secCtx   *gssapi.SecContext
	done     bool
}

// AcceptorOption configures an Acceptor.
type AcceptorOption func(*Acceptor)

// ExpectChannelBindings makes AcceptSecContext verify the initiator's channel
// bindings against cb, rejecting a mismatch. The default (nil) is
// GSS_C_NO_CHANNEL_BINDINGS: the initiator's bindings, if any, are not checked.
func ExpectChannelBindings(cb *gssapi.ChannelBindings) AcceptorOption {
	return func(a *Acceptor) { a.cb = cb }
}

// NewAcceptor returns an Acceptor that verifies AP-REQs against kt.
func NewAcceptor(kt *keytab.Keytab, opts ...AcceptorOption) *Acceptor {
	a := &Acceptor{settings: service.NewSettings(kt)}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

// AcceptSecContext consumes the initiator's initial-context token and verifies
// the AP-REQ. On success it returns the AP-REP token that completes mutual
// authentication with done == true; the established context and the
// authenticated client's credentials are then available from Context and
// Credentials. On failure it returns a non-nil error and, where the failure
// maps to a Kerberos error, a framed KRB-ERROR token for the initiator.
func (a *Acceptor) AcceptSecContext(in []byte) (out []byte, done bool, err error) {
	inner, err := unframeInitialContextToken(in, tokIDAPReq)
	if err != nil {
		return nil, false, err
	}

	var apReq messages.APReq
	if err := apReq.Unmarshal(inner); err != nil {
		return nil, false, fmt.Errorf("unmarshaling AP-REQ: %w", err)
	}

	ok, creds, err := service.VerifyAPREQ(&apReq, a.settings)
	if err != nil {
		return rejection(err)
	}

	if !ok {
		return rejection(errors.New("AP-REQ verification failed"))
	}

	flags, bnd, err := parseGSSChecksum(apReq.Authenticator.Cksum)
	if err != nil {
		return rejection(newKRBError(&apReq, errorcode.KRB_AP_ERR_INAPP_CKSUM, err.Error()))
	}

	if err := a.verifyChannelBindings(bnd); err != nil {
		return rejection(newKRBError(&apReq, errorcode.KRB_AP_ERR_MODIFIED, err.Error()))
	}

	out, subkey, seq, err := a.buildAPRep(&apReq)
	if err != nil {
		return nil, false, err
	}

	// The context is keyed with the acceptor's own subkey, so acceptorSubkey is
	// true: outgoing per-message tokens carry the AcceptorSubkey flag.
	a.creds = creds
	a.secCtx = gssapi.NewSecContext(subkey, flags, false, true, seq)
	a.done = true

	return out, true, nil
}

// Context returns the established security context, or an error if context
// establishment has not completed.
func (a *Acceptor) Context() (*gssapi.SecContext, error) {
	if !a.done || a.secCtx == nil {
		return nil, errors.New("security context is not yet established")
	}

	return a.secCtx, nil
}

// Credentials returns the authenticated client's credentials (principal, realm,
// and any PAC authorization data), or nil if no context has been established.
func (a *Acceptor) Credentials() *credentials.Credentials {
	return a.creds
}

// verifyChannelBindings checks the initiator's Bnd against the bindings the
// acceptor expects. A nil expectation (GSS_C_NO_CHANNEL_BINDINGS) skips the
// check.
func (a *Acceptor) verifyChannelBindings(bnd []byte) error {
	if a.cb == nil {
		return nil
	}

	if !bytes.Equal(bnd, a.cb.Bytes()) {
		return errors.New("channel bindings do not match")
	}

	return nil
}

// buildAPRep generates an acceptor subkey and sequence number, then builds,
// encrypts, and frames the AP-REP that echoes the authenticator's ctime/cusec.
// It returns the framed token along with the subkey and sequence number for the
// security context.
func (a *Acceptor) buildAPRep(apReq *messages.APReq) (out []byte, subkey types.EncryptionKey, seq uint64, err error) {
	sessionKey := apReq.Ticket.DecryptedEncPart.Key

	etype, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return nil, subkey, 0, err
	}

	subkey, err = types.GenerateEncryptionKey(etype)
	if err != nil {
		return nil, subkey, 0, fmt.Errorf("generating acceptor subkey: %w", err)
	}

	seq, err = randSequenceNumber()
	if err != nil {
		return nil, subkey, 0, err
	}

	encPart := messages.EncAPRepPart{
		CTime:          apReq.Authenticator.CTime,
		Cusec:          apReq.Authenticator.Cusec,
		Subkey:         subkey,
		SequenceNumber: int64(seq),
	}

	encB, err := encPart.Marshal()
	if err != nil {
		return nil, subkey, 0, fmt.Errorf("marshaling AP-REP encrypted part: %w", err)
	}

	ed, err := crypto.GetEncryptedData(encB, sessionKey, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return nil, subkey, 0, fmt.Errorf("encrypting AP-REP: %w", err)
	}

	apRep := messages.APRep{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REP, EncPart: ed}

	repB, err := apRep.Marshal()
	if err != nil {
		return nil, subkey, 0, fmt.Errorf("marshaling AP-REP: %w", err)
	}

	out, err = frameInitialContextToken(tokIDAPRep, repB)
	if err != nil {
		return nil, subkey, 0, err
	}

	return out, subkey, seq, nil
}

// rejection frames a KRBError as a KRB-ERROR context token so the caller can
// relay the failure reason to the initiator. err is always returned; the token
// is nil when err is not (or does not wrap) a messages.KRBError.
func rejection(err error) (out []byte, done bool, retErr error) {
	var kerr messages.KRBError
	if errors.As(err, &kerr) {
		if tok, ferr := frameKRBError(kerr); ferr == nil {
			return tok, false, err
		}
	}

	return nil, false, err
}

func frameKRBError(kerr messages.KRBError) ([]byte, error) {
	b, err := kerr.Marshal()
	if err != nil {
		return nil, err
	}

	return frameInitialContextToken(tokIDError, b)
}

func newKRBError(apReq *messages.APReq, code int32, msg string) messages.KRBError {
	return messages.NewKRBError(apReq.Ticket.SName, apReq.Ticket.Realm, code, msg)
}

// randSequenceNumber returns a random 30-bit sequence number, matching the
// range used for authenticator sequence numbers.
func randSequenceNumber() (uint64, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return 0, fmt.Errorf("generating sequence number: %w", err)
	}

	return uint64(n.Int64() & 0x3fffffff), nil
}

// parseGSSChecksum validates that cksum is the RFC 4121 §4.1.1 GSSAPI (0x8003)
// authenticator checksum and returns the requested GSS-API context flags (from
// bytes [20:24]) and the channel-binding field Bnd (bytes [4:20]).
func parseGSSChecksum(cksum types.Checksum) (flags []int, bnd []byte, err error) {
	if cksum.CksumType != chksumtype.GSSAPI {
		return nil, nil, fmt.Errorf("authenticator checksum type is %d, want GSSAPI (%d)", cksum.CksumType, chksumtype.GSSAPI)
	}

	if len(cksum.Checksum) < 24 {
		return nil, nil, fmt.Errorf("GSSAPI authenticator checksum is %d bytes, want at least 24", len(cksum.Checksum))
	}

	bnd = cksum.Checksum[4:20]

	f := binary.LittleEndian.Uint32(cksum.Checksum[20:24])

	for _, flag := range []int{
		gssapi.ContextFlagDeleg,
		gssapi.ContextFlagMutual,
		gssapi.ContextFlagReplay,
		gssapi.ContextFlagSequence,
		gssapi.ContextFlagConf,
		gssapi.ContextFlagInteg,
		gssapi.ContextFlagAnon,
	} {
		if f&uint32(flag) != 0 {
			flags = append(flags, flag)
		}
	}

	return flags, bnd, nil
}
