package packets

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ARP operation codes
const (
	ARPRequest = 1
	ARPReply   = 2
)

// ARPHeader represents an ARP packet (specifically for Ethernet+IPv4)
// structure: [HWType(2)][ProtoType(2)][HWLen(1)][ProtoLen(1)][Op(2)][SrcMAC(6)][SrcIP(4)][DstMAC(6)][DstIP(4)]
type ARPHeader struct {
	HardwareType uint16
	ProtocolType uint16
	HWAddrLen    uint8
	ProtoAddrLen uint8
	Operation    uint16
	SrcMAC       net.HardwareAddr
	SrcIP        net.IP
	DstMAC       net.HardwareAddr
	DstIP        net.IP
}

// parses a raw byte slice into an ARPHeader
func ParseARP(data []byte) (*ARPHeader, error) {
	// basic length check (28 bytes is standard for Eth/IPv4 ARP)
	if len(data) < 28 {
		return nil, fmt.Errorf("packet too short for ARP: %d bytes", len(data))
	}

	arp := &ARPHeader{
		HardwareType: binary.BigEndian.Uint16(data[0:2]),
		ProtocolType: binary.BigEndian.Uint16(data[2:4]),
		HWAddrLen:    data[4],
		ProtoAddrLen: data[5],
		Operation:    binary.BigEndian.Uint16(data[6:8]),
	}

	// extract addresses
	// note: we use net.IP and net.HardwareAddr here because they have nice String() methods
	arp.SrcMAC = net.HardwareAddr(data[8:14])
	arp.SrcIP = net.IP(data[14:18])
	arp.DstMAC = net.HardwareAddr(data[18:24])
	arp.DstIP = net.IP(data[24:28])

	return arp, nil
}

// returns a readable representation
func (a *ARPHeader) String() string {
	op := "Unknown"
	if a.Operation == ARPRequest {
		op = "Request"
	} else if a.Operation == ARPReply {
		op = "Reply"
	}

	return fmt.Sprintf("[ARP] Op=%s | Who has %s? Tell %s (%s)",
		op, a.DstIP, a.SrcIP, a.SrcMAC)
}

// creates a byte slice representing an ARP reply answering this request
func (a *ARPHeader) ReplyAs(myMAC net.HardwareAddr, myIP net.IP) ([]byte, error) {
	// validate input
	if len(myMAC) != 6 || len(myIP) != 4 {
		return nil, fmt.Errorf("invalid MAC or IP length")
	}

	reply := make([]byte, 28)

	// hardware type (Ethernet = 1)
	binary.BigEndian.PutUint16(reply[0:2], 1)
	// protocol type (IPv4 = 0x0800)
	binary.BigEndian.PutUint16(reply[2:4], 0x0800)
	// addr lengths
	reply[4] = 6
	reply[5] = 4
	// operation (reply = 2)
	binary.BigEndian.PutUint16(reply[6:8], ARPReply)

	// srcMAC (me) -> bytes 8..14
	copy(reply[8:14], myMAC)
	// srcIP (me) -> bytes 14..18
	copy(reply[14:18], myIP)

	// dstMAC (the requester) -> bytes 18..24
	copy(reply[18:24], a.SrcMAC)
	// dstIP (the requester) -> bytes 24..28
	copy(reply[24:28], a.SrcIP)

	return reply, nil
}
