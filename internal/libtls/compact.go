package libtls

import "fmt"

// Clone returns a deep copy so fake-SNI transformations cannot modify the
// ClientHello which will subsequently be forwarded to the real server.
func (t *TLSRecord) Clone() *TLSRecord {
	clone := *t
	clone.Message.SessionID = append([]byte(nil), t.Message.SessionID...)
	clone.Message.CipherSuites = append([]uint16(nil), t.Message.CipherSuites...)
	clone.Message.CompressionMethods = append([]byte(nil), t.Message.CompressionMethods...)
	clone.Message.Extensions = make([]HelloExtension, len(t.Message.Extensions))
	for i, ext := range t.Message.Extensions {
		clone.Message.Extensions[i] = ext
		clone.Message.Extensions[i].Data = append([]byte(nil), ext.Data...)
	}
	return &clone
}

// EncodeCompact produces a syntactically valid ClientHello no larger than
// maxSize. It first removes padding and ECH, then drops large post-quantum key
// shares while retaining X25519 (or the smallest available key share).
func (t *TLSRecord) EncodeCompact(maxSize int) ([]byte, error) {
	if maxSize <= 0 {
		return nil, fmt.Errorf("invalid compact ClientHello limit: %d", maxSize)
	}
	if data, err := t.EncodeTLS(); err != nil || len(data) <= maxSize {
		return data, err
	}

	t.Message.RemoveExtensionByType(TLS_EXTENSION_PADDING)
	t.Message.RemoveExtensionByType(TLS_EXTENSION_ECH)

	if ok, id, _ := t.Message.FindExtension(TLS_EXTENSION_KEY_SHARE); ok {
		keyShares, err := t.Message.Extensions[id].DecodeKeyShare()
		if err != nil {
			return nil, fmt.Errorf("compact key_share: %w", err)
		}
		if len(keyShares.Extensions) > 1 {
			selected := keyShares.Extensions[0]
			for _, candidate := range keyShares.Extensions {
				if candidate.Group == TLS_KEY_SHARE_x25519 {
					selected = candidate
					break
				}
				if len(candidate.KeyExchange) < len(selected.KeyExchange) {
					selected = candidate
				}
			}
			keyShares.Extensions = []KeyShareExtension{selected}
			_, compact := keyShares.Encode()
			t.Message.Extensions[id] = compact
		}
	}

	data, err := t.EncodeTLS()
	if err != nil {
		return nil, err
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("compact ClientHello is %d bytes, limit is %d", len(data), maxSize)
	}
	return data, nil
}
