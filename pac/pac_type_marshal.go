package pac

import (
	"encoding/binary"
	"fmt"

	"github.com/hstern/krb5/crypto"
	"github.com/hstern/krb5/iana/keyusage"
	"github.com/hstern/krb5/types"
)

// Marshal assembles the PACTYPE byte stream from the populated buffers, using
// the signature bytes currently held in the SignatureData structs. Buffer
// payloads are placed at 8-byte-aligned offsets and the info-buffer table is
// built from their sizes and offsets.
//
// Marshal does NOT compute or refresh the Server/KDC signatures: it emits
// whatever signature bytes are present. Re-marshalling a parsed, signed PAC
// therefore yields bytes that will fail checksum verification, because the
// stored signatures were computed over the original byte layout. Use
// SignAndMarshal to produce a verify-able PAC.
func (pac *PACType) Marshal() ([]byte, error) {
	data, _, err := pac.assemble()

	return data, err
}

// bufferOrder returns the ordered ULTypes to emit. A parsed PAC preserves its
// original buffer order; a freshly built PAC uses the canonical Windows order
// with the signatures last.
func (pac *PACType) bufferOrder() []uint32 {
	if len(pac.Buffers) > 0 {
		order := make([]uint32, len(pac.Buffers))
		for i, b := range pac.Buffers {
			order[i] = b.ULType
		}

		return order
	}

	var order []uint32

	for _, c := range []struct {
		ul  uint32
		set bool
	}{
		{infoTypeKerbValidationInfo, pac.KerbValidationInfo != nil},
		{infoTypePACClientInfo, pac.ClientInfo != nil},
		{infoTypeUPNDNSInfo, pac.UPNDNSInfo != nil},
		{infoTypeS4UDelegationInfo, pac.S4UDelegationInfo != nil},
		{infoTypePACClientClaimsInfo, pac.ClientClaimsInfo != nil},
		{infoTypePACDeviceInfo, pac.DeviceInfo != nil},
		{infoTypePACDeviceClaimsInfo, pac.DeviceClaimsInfo != nil},
		{infoTypePACServerSignatureData, pac.ServerChecksum != nil},
		{infoTypePACKDCSignatureData, pac.KDCChecksum != nil},
	} {
		if c.set {
			order = append(order, c.ul)
		}
	}

	return order
}

// marshalBuffer returns the marshalled payload for a buffer type when the
// corresponding typed struct is populated. handled is false when no typed
// struct backs the type (the caller falls back to raw passthrough).
func (pac *PACType) marshalBuffer(ulType uint32) (b []byte, handled bool, err error) {
	switch ulType {
	case infoTypeKerbValidationInfo:
		if pac.KerbValidationInfo != nil {
			b, err = pac.KerbValidationInfo.Marshal()
			return b, true, err
		}
	case infoTypePACClientInfo:
		if pac.ClientInfo != nil {
			b, err = pac.ClientInfo.Marshal()
			return b, true, err
		}
	case infoTypePACServerSignatureData:
		if pac.ServerChecksum != nil {
			b, err = pac.ServerChecksum.Marshal()
			return b, true, err
		}
	case infoTypePACKDCSignatureData:
		if pac.KDCChecksum != nil {
			b, err = pac.KDCChecksum.Marshal()
			return b, true, err
		}
	case infoTypeUPNDNSInfo:
		if pac.UPNDNSInfo != nil {
			b, err = pac.UPNDNSInfo.Marshal()
			return b, true, err
		}
	case infoTypeS4UDelegationInfo:
		if pac.S4UDelegationInfo != nil {
			b, err = pac.S4UDelegationInfo.Marshal()
			return b, true, err
		}
	case infoTypePACClientClaimsInfo:
		if pac.ClientClaimsInfo != nil {
			b, err = pac.ClientClaimsInfo.Marshal()
			return b, true, err
		}
	case infoTypePACDeviceInfo:
		if pac.DeviceInfo != nil {
			b, err = pac.DeviceInfo.Marshal()
			return b, true, err
		}
	case infoTypePACDeviceClaimsInfo:
		if pac.DeviceClaimsInfo != nil {
			b, err = pac.DeviceClaimsInfo.Marshal()
			return b, true, err
		}
	}

	return nil, false, nil
}

// rawBuffer copies the original bytes of a buffer that has no typed marshaller
// (e.g. Credentials) from the parsed PAC data.
func (pac *PACType) rawBuffer(ulType uint32) ([]byte, error) {
	for _, buf := range pac.Buffers {
		if buf.ULType == ulType {
			end := int(buf.Offset) + int(buf.CBBufferSize)
			if end > len(pac.Data) {
				return nil, fmt.Errorf("raw buffer type %d out of range", ulType)
			}

			out := make([]byte, buf.CBBufferSize)
			copy(out, pac.Data[buf.Offset:end])

			return out, nil
		}
	}

	return nil, fmt.Errorf("no data for buffer type %d", ulType)
}

// assemble lays out the header, info-buffer table and 8-byte-aligned payloads,
// returning the bytes and a map from ULType to the file offset of that buffer's
// payload (used by signing to patch checksums in place).
func (pac *PACType) assemble() ([]byte, map[uint32]int, error) {
	order := pac.bufferOrder()
	payloads := make([][]byte, len(order))

	for i, ul := range order {
		p, handled, err := pac.marshalBuffer(ul)
		if err != nil {
			return nil, nil, fmt.Errorf("error marshalling buffer type %d: %w", ul, err)
		}

		if !handled {
			p, err = pac.rawBuffer(ul)
			if err != nil {
				return nil, nil, err
			}
		}

		payloads[i] = p
	}

	n := len(order)
	cursor := 8 + 16*n
	offsets := make([]int, n)

	for i := range payloads {
		cursor = align8(cursor)
		offsets[i] = cursor
		cursor += len(payloads[i])
	}

	data := make([]byte, align8(cursor))
	binary.LittleEndian.PutUint32(data[0:4], uint32(n))
	binary.LittleEndian.PutUint32(data[4:8], pac.Version)

	offsetsByType := make(map[uint32]int, n)

	for i := range payloads {
		base := 8 + 16*i
		binary.LittleEndian.PutUint32(data[base:base+4], order[i])
		binary.LittleEndian.PutUint32(data[base+4:base+8], uint32(len(payloads[i])))
		binary.LittleEndian.PutUint64(data[base+8:base+16], uint64(offsets[i]))
		copy(data[offsets[i]:], payloads[i])
		offsetsByType[order[i]] = offsets[i]
	}

	return data, offsetsByType, nil
}

// prepareSignatures (re)creates the Server and KDC signature buffers with the
// checksum type derived from each key's encryption type and a zero-filled
// signature of the correct length, ready for the checksum to be patched in.
func (pac *PACType) prepareSignatures(serverKey, kdcKey types.EncryptionKey) error {
	serverEt, err := crypto.GetEtype(serverKey.KeyType)
	if err != nil {
		return fmt.Errorf("server key etype: %w", err)
	}

	kdcEt, err := crypto.GetEtype(kdcKey.KeyType)
	if err != nil {
		return fmt.Errorf("kdc key etype: %w", err)
	}

	serverType := uint32(serverEt.GetHashID())
	kdcType := uint32(kdcEt.GetHashID())

	serverLen, err := signatureSize(serverType)
	if err != nil {
		return err
	}

	kdcLen, err := signatureSize(kdcType)
	if err != nil {
		return err
	}

	pac.ServerChecksum = &SignatureData{SignatureType: serverType, Signature: make([]byte, serverLen)}
	pac.KDCChecksum = &SignatureData{SignatureType: kdcType, Signature: make([]byte, kdcLen)}

	return nil
}

// SignAndMarshal assembles the PAC with both signature fields zeroed, computes
// the server checksum over the whole PAC, then the KDC checksum over the server
// signature, patches them in place, and returns the signed bytes.
func (pac *PACType) SignAndMarshal(serverKey, kdcKey types.EncryptionKey) ([]byte, error) {
	if err := pac.prepareSignatures(serverKey, kdcKey); err != nil {
		return nil, err
	}

	data, offsets, err := pac.assemble()
	if err != nil {
		return nil, err
	}

	serverOff, ok := offsets[infoTypePACServerSignatureData]
	if !ok {
		return nil, fmt.Errorf("server signature buffer missing")
	}

	kdcOff, ok := offsets[infoTypePACKDCSignatureData]
	if !ok {
		return nil, fmt.Errorf("kdc signature buffer missing")
	}

	serverEt, err := crypto.GetEtype(serverKey.KeyType)
	if err != nil {
		return nil, err
	}

	serverSig, err := serverEt.GetChecksumHash(serverKey.KeyValue, data, keyusage.KERB_NON_KERB_CKSUM_SALT)
	if err != nil {
		return nil, fmt.Errorf("server checksum: %w", err)
	}

	// The signature region begins 4 bytes into the buffer, after SignatureType.
	copy(data[serverOff+4:], serverSig)

	kdcEt, err := crypto.GetEtype(kdcKey.KeyType)
	if err != nil {
		return nil, err
	}

	kdcSig, err := kdcEt.GetChecksumHash(kdcKey.KeyValue, serverSig, keyusage.KERB_NON_KERB_CKSUM_SALT)
	if err != nil {
		return nil, fmt.Errorf("kdc checksum: %w", err)
	}

	copy(data[kdcOff+4:], kdcSig)

	return data, nil
}
