package gssapi

import (
	"errors"

	"github.com/hstern/krb5/crypto"
	"github.com/hstern/krb5/iana/keyusage"
	"github.com/hstern/krb5/types"
)

// SecContext is an established GSS-API security context. It holds the per-message
// key and the outgoing sequence state negotiated during context establishment
// and bridges to WrapToken/MICToken so callers need not select key usages or the
// sender-role flags by hand.
//
// SecContext stamps an incrementing sequence number on each token it sends. It
// does NOT validate the sequence numbers of received tokens: Unwrap and
// VerifyMIC confirm the checksum and sender role only, so replay and reordering
// detection, where required, remain the caller's responsibility.
//
// Wrap provides integrity protection only: the payload is authenticated but not
// encrypted, as the underlying WrapToken has no confidentiality (sealing)
// support.
type SecContext struct {
	// Key is the per-message key: the acceptor's subkey if one was asserted
	// during establishment, otherwise the ticket session key.
	Key types.EncryptionKey

	// Flags are the negotiated GSS-API context flags.
	Flags []int

	// send is the flag byte stamped on tokens this end sends (acceptor and
	// acceptor-subkey bits); expectAcceptor is the sender-role bit expected on
	// received tokens.
	send           byte
	expectAcceptor bool

	sendSeal uint32
	recvSeal uint32
	sendSign uint32
	recvSign uint32

	sendSeq uint64
}

// NewSecContext returns an established security context for the given
// per-message key and negotiated flags. initiator reports whether this end
// initiated the context; acceptorSubkey reports whether key is the acceptor's
// asserted subkey (which sets the AcceptorSubkey flag on outgoing per-message
// tokens). Together they select the key usages and sender-role flags. seq is the
// initial outgoing sequence number (the local party's authenticator or AP-REP
// sequence number).
func NewSecContext(key types.EncryptionKey, flags []int, initiator, acceptorSubkey bool, seq uint64) *SecContext {
	sc := &SecContext{
		Key:            key,
		Flags:          flags,
		expectAcceptor: initiator,
		sendSeq:        seq,
	}

	if initiator {
		sc.sendSeal, sc.recvSeal = keyusage.GSSAPI_INITIATOR_SEAL, keyusage.GSSAPI_ACCEPTOR_SEAL
		sc.sendSign, sc.recvSign = keyusage.GSSAPI_INITIATOR_SIGN, keyusage.GSSAPI_ACCEPTOR_SIGN
	} else {
		sc.sendSeal, sc.recvSeal = keyusage.GSSAPI_ACCEPTOR_SEAL, keyusage.GSSAPI_INITIATOR_SEAL
		sc.sendSign, sc.recvSign = keyusage.GSSAPI_ACCEPTOR_SIGN, keyusage.GSSAPI_INITIATOR_SIGN
		sc.send |= MICTokenFlagSentByAcceptor
	}

	if acceptorSubkey {
		sc.send |= MICTokenFlagAcceptorSubkey
	}

	return sc
}

// MIC returns a MICToken authenticating payload under this context's key,
// stamped with the next send sequence number and this end's sender role.
func (sc *SecContext) MIC(payload []byte) (*MICToken, error) {
	token := &MICToken{
		Flags:     sc.send,
		SndSeqNum: sc.nextSeq(),
		Payload:   payload,
	}

	if err := token.SetChecksum(sc.Key, sc.sendSign); err != nil {
		return nil, err
	}

	return token, nil
}

// VerifyMIC verifies that t authenticates payload and was sent by this context's
// peer (a MICToken is a detached signature, so the payload is supplied
// separately). It does not check t's sequence number.
func (sc *SecContext) VerifyMIC(payload []byte, t *MICToken) (bool, error) {
	if err := sc.checkSenderRole(t.Flags); err != nil {
		return false, err
	}

	t.Payload = payload

	return t.Verify(sc.Key, sc.recvSign)
}

// Wrap returns a WrapToken carrying payload with an authenticated checksum under
// this context's key, stamped with the next send sequence number and this end's
// sender role. The payload is authenticated but not encrypted.
func (sc *SecContext) Wrap(payload []byte) (*WrapToken, error) {
	encType, err := crypto.GetEtype(sc.Key.KeyType)
	if err != nil {
		return nil, err
	}

	token := &WrapToken{
		Flags:     sc.send,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: sc.nextSeq(),
		Payload:   payload,
	}

	if err := token.SetCheckSum(sc.Key, sc.sendSeal); err != nil {
		return nil, err
	}

	return token, nil
}

// Unwrap verifies that t was sent by this context's peer and has a valid
// checksum over its payload. It does not check t's sequence number.
func (sc *SecContext) Unwrap(t *WrapToken) (bool, error) {
	if err := sc.checkSenderRole(t.Flags); err != nil {
		return false, err
	}

	return t.Verify(sc.Key, sc.recvSeal)
}

// checkSenderRole confirms a received token's acceptor flag matches the sender
// this context expects to receive from.
func (sc *SecContext) checkSenderRole(flags byte) error {
	if fromAcceptor := flags&MICTokenFlagSentByAcceptor != 0; fromAcceptor != sc.expectAcceptor {
		return errors.New("per-message token sender role does not match context expectation")
	}

	return nil
}

// nextSeq returns the current send sequence number and advances the counter.
func (sc *SecContext) nextSeq() uint64 {
	seq := sc.sendSeq
	sc.sendSeq++

	return seq
}
