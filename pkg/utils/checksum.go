package utils

// calculates the Internet Checksum (RFC 1071)
// used for IPv4, ICMP, TCP, and UDP headers
func Checksum(data []byte) uint16 {
	var sum uint32

	// sum all 16-bit words
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	// if odd length, pad with a zero byte at the end
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// add carry bits (wrap around)
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// one's complement
	return uint16(^sum)
}
