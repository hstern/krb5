// Package krb5context provides a public GSS-API context-establishment API for
// the Kerberos 5 mechanism (1.2.840.113554.1.2.2). It performs raw Kerberos 5
// GSS context establishment without the SPNEGO negotiation layer (it reuses
// spnego.NewAuthenticatorChksum for the RFC 4121 authenticator checksum). Its
// Initiator and Acceptor establish a security context and expose a
// gssapi.SecContext for driving the per-message WrapToken/MICToken exchange.
package krb5context

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/gssapi"
)

// GSS-API KRB5 mechanism token IDs (RFC 4121 §4.1): the two-byte prefix on the
// mechanism-specific inner token that distinguishes an AP-REQ, an AP-REP, and a
// KRB-ERROR.
var (
	tokIDAPReq = []byte{0x01, 0x00}
	tokIDAPRep = []byte{0x02, 0x00}
	tokIDError = []byte{0x03, 0x00}
)

// frameInitialContextToken wraps a mechanism-specific inner token (a marshaled
// AP-REQ or AP-REP) in the RFC 2743 §3.1 initial-context token framing:
//
//	0x60 ‖ DER-length ‖ OID(KRB5) ‖ tokID ‖ inner
//
// This intentionally re-implements the framing rather than reusing
// spnego.KRB5Token: that type's token ID is unexported and its constructor
// hardcodes nil channel bindings, neither of which suits a public initiator.
func frameInitialContextToken(tokID, inner []byte) ([]byte, error) {
	oid, err := asn1.Marshal(gssapi.OIDKRB5.OID(), asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, fmt.Errorf("marshaling KRB5 mechanism OID: %w", err)
	}

	b := make([]byte, 0, len(oid)+len(tokID)+len(inner))
	b = append(b, oid...)
	b = append(b, tokID...)
	b = append(b, inner...)

	return asn1tools.AddASNAppTag(b, 0), nil
}

// stripContextToken removes the [APPLICATION 0] wrapper, verifies the KRB5
// mechanism OID, and returns the two-byte token ID and the inner token. It lets
// callers dispatch on the token ID (e.g. AP-REP vs KRB-ERROR).
func stripContextToken(b []byte) (tokID, inner []byte, err error) {
	var oid asn1.ObjectIdentifier

	rest, err := asn1.UnmarshalWithParams(b, &oid, "application,explicit,tag:0")
	if err != nil {
		return nil, nil, fmt.Errorf("unframing initial context token: %w", err)
	}

	if !oid.Equal(gssapi.OIDKRB5.OID()) {
		return nil, nil, fmt.Errorf("unexpected mechanism OID %s, want %s", oid, gssapi.OIDKRB5.OID())
	}

	if len(rest) < 2 {
		return nil, nil, errors.New("context token too short to contain a token ID")
	}

	return rest[:2], rest[2:], nil
}

// unframeInitialContextToken reverses frameInitialContextToken and asserts the
// token ID is wantTokID, returning the inner token.
func unframeInitialContextToken(b, wantTokID []byte) ([]byte, error) {
	tokID, inner, err := stripContextToken(b)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(tokID, wantTokID) {
		return nil, fmt.Errorf("unexpected token ID %x, want %x", tokID, wantTokID)
	}

	return inner, nil
}
