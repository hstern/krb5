package pac

import (
	"bytes"
	"fmt"

	"github.com/hstern/x/rpc/ndr"
)

// Marshal encodes the ClientClaimsInfo into its NDR byte representation. Only
// the ClaimsSetMetadata is on the wire; it carries the raw (possibly
// compressed) ClaimsSetBytes, which are re-emitted verbatim. The derived
// ClaimsSet view is not serialized.
func (k *ClientClaimsInfo) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	if err := ndr.NewEncoder(&buf).Encode(&k.ClaimsSetMetadata); err != nil {
		return nil, fmt.Errorf("error marshalling ClientClaimsInfo: %w", err)
	}

	return buf.Bytes(), nil
}
