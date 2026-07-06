package pac

import (
	"errors"

	"github.com/hstern/krb5/types"
)

// Builder assembles and signs a PAC from individual info buffers. It is a thin
// convenience layer over PACType.SignAndMarshal.
type Builder struct {
	pac PACType
}

// NewPAC returns a new PAC Builder.
func NewPAC() *Builder {
	return &Builder{}
}

// WithKerbValidationInfo sets the logon information buffer.
func (b *Builder) WithKerbValidationInfo(k *KerbValidationInfo) *Builder {
	b.pac.KerbValidationInfo = k
	return b
}

// WithClientInfo sets the client information buffer.
func (b *Builder) WithClientInfo(c *ClientInfo) *Builder {
	b.pac.ClientInfo = c
	return b
}

// WithUPNDNSInfo sets the UPN and DNS information buffer.
func (b *Builder) WithUPNDNSInfo(u *UPNDNSInfo) *Builder {
	b.pac.UPNDNSInfo = u
	return b
}

// WithS4UDelegationInfo sets the S4U delegation information buffer.
func (b *Builder) WithS4UDelegationInfo(s *S4UDelegationInfo) *Builder {
	b.pac.S4UDelegationInfo = s
	return b
}

// WithClientClaimsInfo sets the client claims information buffer.
func (b *Builder) WithClientClaimsInfo(c *ClientClaimsInfo) *Builder {
	b.pac.ClientClaimsInfo = c
	return b
}

// WithDeviceInfo sets the device information buffer.
func (b *Builder) WithDeviceInfo(d *DeviceInfo) *Builder {
	b.pac.DeviceInfo = d
	return b
}

// WithDeviceClaimsInfo sets the device claims information buffer.
func (b *Builder) WithDeviceClaimsInfo(d *DeviceClaimsInfo) *Builder {
	b.pac.DeviceClaimsInfo = d
	return b
}

// SignAndMarshal validates the required buffers, then signs and marshals the
// PAC. The Server and KDC signature buffers are added and computed
// automatically.
func (b *Builder) SignAndMarshal(serverKey, kdcKey types.EncryptionKey) ([]byte, error) {
	if b.pac.KerbValidationInfo == nil {
		return nil, errors.New("a PAC requires a KerbValidationInfo")
	}

	if b.pac.ClientInfo == nil {
		return nil, errors.New("a PAC requires a ClientInfo")
	}

	return b.pac.SignAndMarshal(serverKey, kdcKey)
}
