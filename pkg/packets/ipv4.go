package packets

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/hexhaust/mini-netstack/pkg/utils"
)

// IP protocols
const (
	ProtocolICMP = 1
	ProtocolTCP  = 6
	ProtocolUDP  = 17
)

// IPv4Header assuming no Options
type IPv4Header struct {
	Version        uint8
	IHL            uint8
	TOS            uint8
	TotalLength    uint16
	Identification uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SrcIP          net.IP
	DstIP          net.IP
}

func ParseIPv4(data []byte) (*IPv4Header, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("packet too short for IPv4: %d bytes", len(data))
	}

	return &IPv4Header{
		Version:        data[0] >> 4,
		IHL:            data[0] & 0x0F,
		TOS:            data[1],
		TotalLength:    binary.BigEndian.Uint16(data[2:4]),
		Identification: binary.BigEndian.Uint16(data[4:6]),
		Flags:          data[6] >> 5,
		FragmentOffset: binary.BigEndian.Uint16(data[6:8]) & 0x1FFF,
		TTL:            data[8],
		Protocol:       data[9],
		Checksum:       binary.BigEndian.Uint16(data[10:12]),
		SrcIP:          net.IP(data[12:16]),
		DstIP:          net.IP(data[16:20]),
	}, nil
}

// encodes IPv4 header and calculates the checksum
func (ip *IPv4Header) Bytes() []byte {
	// standard header size = 20 bytes (no options)
	buf := make([]byte, 20)

	buf[0] = (ip.Version << 4) | (ip.IHL & 0x0F)
	buf[1] = ip.TOS
	binary.BigEndian.PutUint16(buf[2:4], ip.TotalLength)
	binary.BigEndian.PutUint16(buf[4:6], ip.Identification)

	flagsAndOffset := (uint16(ip.Flags) << 13) | (ip.FragmentOffset & 0x1FFF)
	binary.BigEndian.PutUint16(buf[6:8], flagsAndOffset)

	buf[8] = ip.TTL
	buf[9] = ip.Protocol
	// checksum set to 0 initially
	buf[10] = 0
	buf[11] = 0

	copy(buf[12:16], ip.SrcIP.To4())
	copy(buf[16:20], ip.DstIP.To4())

	// calculate header checksum
	csum := utils.Checksum(buf)
	binary.BigEndian.PutUint16(buf[10:12], csum)

	return buf
}

func (ip *IPv4Header) String() string {
	proto := "Unknown"
	switch ip.Protocol {
	case ProtocolICMP:
		proto = "ICMP"
	case ProtocolTCP:
		proto = "TCP"
	case ProtocolUDP:
		proto = "UDP"
	}
	return fmt.Sprintf("[IPv4] %s -> %s | Proto: %s | Len: %d | TTL: %d",
		ip.SrcIP, ip.DstIP, proto, ip.TotalLength, ip.TTL)
}
