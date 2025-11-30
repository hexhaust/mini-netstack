package packets

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/hexhaust/mini-netstack/pkg/utils"
)

// UDP header is 8 bytes fixed
// [SrcPort(2)][DstPort(2)][Length(2)][Checksum(2)]
type UDPPacket struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
	Data     []byte
}

func ParseUDP(data []byte) (*UDPPacket, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("packet too short for UDP: %d bytes", len(data))
	}

	return &UDPPacket{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
		Data:     data[8:],
	}, nil
}

// serializes the UDP packet
// IMPORTANT: UDP checksum requires the "IP Pseudo Header" to be calculated
// need to pass srcIP and dstIP here to build that context
func (u *UDPPacket) Bytes(srcIP, dstIP net.IP) []byte {
	totalLen := 8 + len(u.Data)
	buf := make([]byte, totalLen)

	binary.BigEndian.PutUint16(buf[0:2], u.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], u.DstPort)
	binary.BigEndian.PutUint16(buf[4:6], uint16(totalLen))
	// checksum placeholder
	buf[6] = 0
	buf[7] = 0
	copy(buf[8:], u.Data)

	// pseudo header checksum calc
	// to calc the checksum correctly, we must sum:
	// 1 - IP pseudo header (SrcIP, DstIP, Proto, Len)
	// 2 - UDP header itself
	// 3 - the data
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = ProtocolUDP
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(totalLen))

	// join everything for checksum calc
	chkBuf := append(pseudoHeader, buf...)
	csum := utils.Checksum(chkBuf)

	// UDP checksum of 0 means "no checksum", so if result is 0, use 0xFFFF
	if csum == 0 {
		csum = 0xFFFF
	}

	binary.BigEndian.PutUint16(buf[6:8], csum)

	return buf
}

func (u *UDPPacket) String() string {
	return fmt.Sprintf("[UDP] Port %d -> %d | Len: %d | Sum: 0x%04x",
		u.SrcPort, u.DstPort, u.Length, u.Checksum)
}
