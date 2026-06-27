package pac

import (
	"fmt"

	"github.com/hstern/krb5/iana/chksumtype"
)

// signatureSize returns the byte length of a SignatureData signature for the
// given checksum type, mirroring the switch in SignatureData.Unmarshal.
func signatureSize(signatureType uint32) (int, error) {
	switch signatureType {
	case chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED:
		return 16, nil
	case uint32(chksumtype.HMAC_SHA1_96_AES128):
		return 12, nil
	case uint32(chksumtype.HMAC_SHA1_96_AES256):
		return 12, nil
	case uint32(chksumtype.HMAC_SHA256_128_AES128):
		return 16, nil
	case uint32(chksumtype.HMAC_SHA384_192_AES256):
		return 24, nil
	default:
		return 0, fmt.Errorf("unsupported signature type: %d", signatureType)
	}
}

// Marshal encodes the SignatureData into its (non-NDR) byte representation. The
// trailing RODCIdentifier is emitted only when HasRODCIdentifier is set.
func (k *SignatureData) Marshal() ([]byte, error) {
	w := newPACWriter()
	w.writeUint32(k.SignatureType)
	w.writeBytes(k.Signature)

	if k.HasRODCIdentifier {
		w.writeUint16(k.RODCIdentifier)
	}

	return w.bytes(), nil
}
