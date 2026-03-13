package libtls

import "fmt"

func DecodeSSLHandshake(data []byte) (ok bool, sni string, pos int) {
	if len(data) < 4 {
		return
	}

	// SSL Magic Key
	if !(data[0] == 0x16) && (data[1] == 0x03) && (data[2] == 0x01) {
		// Not SSL magic header
		return
	}

	// SSL magic key is found
	// TODO: Deep client Hello analysis
	pktLen := int(data[3])*256 + int(data[4])

	offset := int(5)

	// Process only Client Hello
	if data[offset] != 0x01 {
		return
	}

	offset++
	handshakeLen := int(data[offset])*256*256 + int(data[offset+1])*256 + int(data[offset+2])
	offset += 3

	tlsVersion := int(data[offset])*256 + int(data[offset+1])
	offset += 2

	// Random
	offset += 32

	if len(data) < offset+6 {
		return
	}

	sessionIdLength := int(data[offset])
	offset += 1 + sessionIdLength

	if len(data) < offset+5 {
		return
	}

	csLength := int(data[offset])*256 + int(data[offset+1])
	offset += 2 + csLength

	if len(data) < offset {
		return
	}

	cmLength := int(data[offset])
	offset += 1 + cmLength

	if len(data) < offset+2 {
		return
	}

	extLen := int(data[offset])*256 + int(data[offset])
	offset += 2

	if offset+extLen > len(data) {
		// INVALID Extensions len
		return
	}

	if false {
		fmt.Println(pktLen, handshakeLen, tlsVersion)
	}

	ox := 0
	for {
		ext, extType, ox2, isLast := getNextExtension(data[offset+ox:], ox)
		oxOrig := ox
		ox = ox2

		if extType == 0 {
			d, _, e := decodeSNI(ext)
			if e == nil {
				//fmt.Println("SNI: ", d)
				sni = d

				return true, sni, offset + oxOrig + 9
			}
		}

		if false {
			fmt.Println(ext, extType, offset)
		}

		if isLast {
			break
		}
	}

	return true, sni, offset
}
