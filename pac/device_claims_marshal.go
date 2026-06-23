package pac

import (
	"bytes"
	"fmt"

	"github.com/go-krb5/x/rpc/ndr"
)

// Marshal encodes the DeviceClaimsInfo into its NDR byte representation. As with
// ClientClaimsInfo, only the ClaimsSetMetadata is on the wire and its raw
// ClaimsSetBytes are re-emitted verbatim.
func (k *DeviceClaimsInfo) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	if err := ndr.NewEncoder(&buf).Encode(&k.ClaimsSetMetadata); err != nil {
		return nil, fmt.Errorf("error marshalling DeviceClaimsInfo: %w", err)
	}

	return buf.Bytes(), nil
}
