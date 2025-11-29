package frames

import (
	"encoding/binary"
	"fmt"
)

// common EtherTypes (Big Endian)
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806
	EtherTypeIPv6 = 0x86DD
)

// constant for Ethernet II
const EthernetHeaderSize = 14

// represents the L2 header + payload
type EthernetFrame struct {
	DstMAC    [6]byte
	SrcMAC    [6]byte
	EtherType uint16
	Payload   []byte
}

// parses raw bytes read from the TAP interface
func ParseEthernet(data []byte) (*EthernetFrame, error) {
	if len(data) < EthernetHeaderSize {
		return nil, fmt.Errorf("frame too short: %d bytes (min %d)", len(data), EthernetHeaderSize)
	}

	frame := &EthernetFrame{}

	// copy the first 6 bytes to DstMAC
	copy(frame.DstMAC[:], data[0:6])

	// copy the next 6 bytes to SrcMAC
	copy(frame.SrcMAC[:], data[6:12])

	// reads the EtherType (bytes 12 and 13)
	// network is BigEndian, our CPU (x86/ARM) is LittleEndian.
	// binary.BigEndian.Uint16 does the correct conversion.
	frame.EtherType = binary.BigEndian.Uint16(data[12:14])

	// (L3 header + data)
	frame.Payload = data[14:]

	return frame, nil
}

// returns a human-readable representation of the frame (useful for logging)
func (e *EthernetFrame) String() string {
	typeStr := "Unknown"
	switch e.EtherType {
	case EtherTypeIPv4:
		typeStr = "IPv4"
	case EtherTypeIPv6:
		typeStr = "IPv6"
	case EtherTypeARP:
		typeStr = "ARP"
	}

	return fmt.Sprintf("[Eth] %x -> %x | Type: 0x%04x (%s) | Payload: %d bytes",
		e.SrcMAC, e.DstMAC, e.EtherType, typeStr, len(e.Payload))
}
