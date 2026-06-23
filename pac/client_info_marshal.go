package pac

// Marshal encodes the ClientInfo into its (non-NDR) byte representation, the
// inverse of Unmarshal. NameLength is recomputed from Name (two bytes per
// rune).
func (k *ClientInfo) Marshal() ([]byte, error) {
	w := newPACWriter()
	w.writeFileTime(k.ClientID)
	w.writeUint16(uint16(len([]rune(k.Name)) * 2))
	w.writeUTF16(k.Name)

	return w.bytes(), nil
}
