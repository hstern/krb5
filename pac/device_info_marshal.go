package pac

import (
	"bytes"
	"fmt"

	"github.com/go-krb5/x/rpc/ndr"
)

// Marshal encodes the DeviceInfo into its NDR byte representation.
func (k *DeviceInfo) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	if err := ndr.NewEncoder(&buf).Encode(k); err != nil {
		return nil, fmt.Errorf("error marshalling DeviceInfo: %w", err)
	}

	return buf.Bytes(), nil
}
