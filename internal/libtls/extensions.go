package libtls

import (
	"encoding/binary"
	"fmt"
)

// DECODE Extension type = 0 (server_name)
func decodeSNI(data []byte) (domain string, t int, err error) {
	if len(data) < 6 {
		return "", 0, fmt.Errorf("TOO_SHORT")
	}
	listLen := int(data[0])*256 + int(data[1])
	if len(data) != listLen+2 {
		return "", 0, fmt.Errorf("INVALID_LIST_LEN")
	}
	t = int(data[2])
	l := int(data[3])*256 + int(data[4])

	if len(data) != l+5 {
		return "", 0, fmt.Errorf("INVALID_NAME_LEN")
	}
	return string(data[5:]), t, nil
}

func encodeSNI(domain string) []byte {
	// Extension type = 0 (server_name)
	// Structure:
	// [0-1]: List length (2 bytes)
	// [2]: Type (1 byte)
	// [3-4]: Name length (2 bytes)
	// [5:]: Domain name

	domainBytes := []byte(domain)
	nameLen := len(domainBytes)

	// Calculate list length (type(1) + name_len(2) + name(nameLen))
	listLen := 1 + 2 + nameLen

	data := make([]byte, 2+listLen) // Total length = list_len(2) + listLen

	// Set list length (2 bytes)
	data[0] = byte(listLen >> 8) // High byte
	data[1] = byte(listLen)      // Low byte

	// Set type = 0 (server_name)
	data[2] = 0

	// Set name length (2 bytes)
	data[3] = byte(nameLen >> 8) // High byte
	data[4] = byte(nameLen)      // Low byte

	// Copy domain name
	copy(data[5:], domainBytes)

	return data
}

func (h *ClientHello) FindExtension(t uint16) (ok bool, id int, data []byte) {
	for id, e := range h.Extensions {
		if e.Type == t {
			return true, id, e.Data
		}
	}
	return false, 0, nil
}

func (h *ClientHello) FindSNI() (ok bool, hostname string) {
	ok, _, data := h.FindExtension(0)
	if !ok {
		return false, ""
	}
	hostname, nameType, err := decodeSNI(data)
	if err != nil || nameType != 0 || hostname == "" {
		return false, ""
	}
	return true, hostname
}

func (h *ClientHello) ReplaceSNI(hostname string) (ok bool, id int) {
	// Search for SNI
	ok, id, _ = h.FindExtension(0)
	sniBody := encodeSNI(hostname)
	extension := HelloExtension{
		Type:   0,
		Length: uint16(len(sniBody)),
		Data:   sniBody,
	}
	if ok {
		h.Extensions[id] = extension
	} else {
		h.Extensions = append(h.Extensions, extension)
	}

	return
}

func (h *ClientHello) RemoveExtension(id int) (ok bool) {
	if id < 0 || id >= len(h.Extensions) {
		return false
	}

	if id == 0 {
		h.Extensions = h.Extensions[1:]
	} else if id == len(h.Extensions)-1 {
		h.Extensions = h.Extensions[:len(h.Extensions)-1]
	} else {
		h.Extensions = append(h.Extensions[:id], h.Extensions[id+1:]...)
	}

	return true
}

func (h *ClientHello) RemoveExtensionByType(t uint16) (ok bool) {
	ok, id, _ := h.FindExtension(t)
	if ok {
		return h.RemoveExtension(id)
	}

	return false
}

func (h *ClientHello) RemoveSNI() (ok bool) {
	return h.RemoveExtensionByType(0)
}

type KeyShareExtension struct {
	Group       uint16
	KeyExchange []byte
}
type KeyShare struct {
	KeyShareLength uint16
	Extensions     []KeyShareExtension
}

func (he *HelloExtension) DecodeKeyShare() (ks *KeyShare, err error) {
	if he.Type != TLS_EXTENSION_KEY_SHARE {
		return nil, fmt.Errorf("WRONG_EXTENSION_TYPE")
	}

	if len(he.Data) < 2 || int(he.Length) != len(he.Data) {
		return nil, fmt.Errorf("TOO_SHORT")
	}
	ks = &KeyShare{
		KeyShareLength: binary.BigEndian.Uint16(he.Data[0:2]),
	}
	if ks.KeyShareLength != he.Length-2 {
		return nil, fmt.Errorf("INVALID_LIST_LEN")
	}

	// Empty list
	if ks.KeyShareLength == 0 {
		return
	}
	ksp := uint16(2)
	limit := ks.KeyShareLength + 2
	for ksp < limit {
		if ksp+4 > limit {
			return nil, fmt.Errorf("SHORT_EXTENSION")
		}

		llen := binary.BigEndian.Uint16(he.Data[ksp+2 : ksp+4])
		if ksp+4+llen > limit {
			return nil, fmt.Errorf("INVALID_EXT_LEN")
		}

		keyData := make([]byte, llen)
		copy(keyData, he.Data[ksp+4:ksp+llen+4])

		e := KeyShareExtension{
			Group:       binary.BigEndian.Uint16(he.Data[ksp : ksp+2]),
			KeyExchange: keyData,
		}
		ks.Extensions = append(ks.Extensions, e)
		ksp += llen + 4
	}
	if ksp != limit {
		return nil, fmt.Errorf("EXTENSION_EARLY_END")
	}

	return ks, err
}

func (k *KeyShare) Encode() (ok bool, he HelloExtension) {
	// Calculate total length
	tl := 2
	for _, e := range k.Extensions {
		tl += 4 + len(e.KeyExchange)
	}

	data := make([]byte, tl)
	binary.BigEndian.PutUint16(data[0:2], uint16(tl-2))

	tp := 2
	for _, e := range k.Extensions {
		binary.BigEndian.PutUint16(data[tp:tp+2], e.Group)
		binary.BigEndian.PutUint16(data[tp+2:tp+4], uint16(len(e.KeyExchange)))
		copy(data[tp+4:], e.KeyExchange)
		tp += 4 + len(e.KeyExchange)
	}

	he = HelloExtension{
		Type:   TLS_EXTENSION_KEY_SHARE,
		Length: uint16(tl),
		Data:   data,
	}

	return true, he
}

func (k *KeyShare) FindExtension(t uint16) (ok bool, id int, data []byte) {
	for id, e := range k.Extensions {
		if e.Group == t {
			return true, id, e.KeyExchange
		}
	}
	return false, 0, nil
}

func (k *KeyShare) RemoveExtension(id int) (ok bool) {
	if id < 0 || id >= len(k.Extensions) {
		return false
	}

	if id == 0 {
		k.Extensions = k.Extensions[1:]
	} else if id == len(k.Extensions)-1 {
		k.Extensions = k.Extensions[:len(k.Extensions)-1]
	} else {
		k.Extensions = append(k.Extensions[:id], k.Extensions[id+1:]...)
	}

	return true
}

func (k *KeyShare) RemoveExtensionByType(t uint16) (ok bool) {
	ok, id, _ := k.FindExtension(t)
	if ok {
		return k.RemoveExtension(id)
	}

	return false
}
