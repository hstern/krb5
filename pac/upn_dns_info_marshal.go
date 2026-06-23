package pac

import "encoding/binary"

// upnDNSHeaderLen is the fixed size of the UPN_DNS_INFO header fields: four
// uint16 length/offset fields plus a uint32 Flags.
const upnDNSHeaderLen = 12

// Marshal encodes the base UPN_DNS_INFO structure (UPN, DNS domain, Flags). The
// UPN and DNS-domain strings are each placed at the next 8-byte-aligned offset
// (matching the Windows layout), and the offset/length header fields are
// recomputed to point at them.
func (k *UPNDNSInfo) Marshal() ([]byte, error) {
	uw := newPACWriter()
	uw.writeUTF16(k.UPN)
	upn := uw.bytes()

	dw := newPACWriter()
	dw.writeUTF16(k.DNSDomain)
	dns := dw.bytes()

	upnOffset := align8(upnDNSHeaderLen)
	dnsOffset := align8(upnOffset + len(upn))
	total := align8(dnsOffset + len(dns))

	out := make([]byte, total)
	binary.LittleEndian.PutUint16(out[0:2], uint16(len(upn)))
	binary.LittleEndian.PutUint16(out[2:4], uint16(upnOffset))
	binary.LittleEndian.PutUint16(out[4:6], uint16(len(dns)))
	binary.LittleEndian.PutUint16(out[6:8], uint16(dnsOffset))
	binary.LittleEndian.PutUint32(out[8:12], k.Flags)
	copy(out[upnOffset:], upn)
	copy(out[dnsOffset:], dns)

	return out, nil
}
