package pac

import (
	"bytes"
	"fmt"

	"github.com/go-krb5/x/rpc/ndr"
)

// Marshal encodes the S4UDelegationInfo into its NDR byte representation.
func (k *S4UDelegationInfo) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	if err := ndr.NewEncoder(&buf).Encode(k); err != nil {
		return nil, fmt.Errorf("error marshalling S4UDelegationInfo: %w", err)
	}

	return buf.Bytes(), nil
}
