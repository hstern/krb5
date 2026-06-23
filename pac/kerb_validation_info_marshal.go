package pac

import (
	"bytes"
	"fmt"

	"github.com/go-krb5/x/rpc/ndr"
)

// Marshal encodes the KerbValidationInfo into its NDR byte representation,
// the inverse of Unmarshal.
func (k *KerbValidationInfo) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	if err := ndr.NewEncoder(&buf).Encode(k); err != nil {
		return nil, fmt.Errorf("error marshalling KerbValidationInfo: %w", err)
	}

	return buf.Bytes(), nil
}
