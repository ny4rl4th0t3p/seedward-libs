package gentxvalidate

// Minimal protobuf wire-format writer for sign-bytes reconstruction. Fields
// must be appended in ascending field-number order to match gogoproto output
// byte for byte.

const (
	wireVarint uint64 = 0
	wireBytes  uint64 = 2

	varintMSB = 0x80 // varint continuation bit
)

func appendUvarint(b []byte, v uint64) []byte {
	for v >= varintMSB {
		b = append(b, byte(v)|varintMSB)
		v >>= 7
	}
	return append(b, byte(v))
}

func appendTag(b []byte, field, wire uint64) []byte {
	return appendUvarint(b, field<<3|wire)
}

func appendVarintField(b []byte, field, v uint64) []byte {
	b = appendTag(b, field, wireVarint)
	return appendUvarint(b, v)
}

func appendBytesField(b []byte, field uint64, v []byte) []byte {
	b = appendTag(b, field, wireBytes)
	b = appendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func appendStringField(b []byte, field uint64, s string) []byte {
	b = appendTag(b, field, wireBytes)
	b = appendUvarint(b, uint64(len(s)))
	return append(b, s...)
}
