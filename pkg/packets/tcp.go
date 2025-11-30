package packets

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/hexhaust/mini-netstack/pkg/utils"
)

// TCP flags
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
)

// TCPHeader structure (20 bytes min)
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8 // size of header in 32-bit words (min 5)
	Flags      uint8 // (FIN, SYN, RST, PSH, ACK, URG)
	Window     uint16
	Checksum   uint16
	UrgentPtr  uint16
	Data       []byte
}

func ParseTCP(data []byte) (*TCPHeader, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("packet too short for TCP: %d bytes", len(data))
	}

	// data offset is the top 4 bits of byte 12
	offsetRaw := data[12]
	dataOffset := offsetRaw >> 4
	headerLen := int(dataOffset) * 4

	if len(data) < headerLen {
		return nil, fmt.Errorf("packet too short for TCP header len: %d", headerLen)
	}

	return &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: dataOffset,
		Flags:      data[13] & 0x3F, // We only care about lower 6 bits
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		UrgentPtr:  binary.BigEndian.Uint16(data[18:20]),
		Data:       data[headerLen:],
	}, nil
}

// serializes the TCP packet
// requires srcIP and dstIP for pseudo-header checksum (same as UDP)
func (t *TCPHeader) Bytes(srcIP, dstIP net.IP) []byte {
	// if offset is 0 (not set), default to min size (5 words = 20 bytes)
	if t.DataOffset == 0 {
		t.DataOffset = 5
	}

	headerLen := int(t.DataOffset) * 4
	totalLen := headerLen + len(t.Data)
	buf := make([]byte, totalLen)

	binary.BigEndian.PutUint16(buf[0:2], t.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], t.DstPort)
	binary.BigEndian.PutUint32(buf[4:8], t.SeqNum)
	binary.BigEndian.PutUint32(buf[8:12], t.AckNum)

	// byte 12: data offset (4 bits) + reserved (4 bits)
	buf[12] = (t.DataOffset << 4)
	// byte 13: flags (we focus on the lower 6 bits)
	buf[13] = t.Flags

	binary.BigEndian.PutUint16(buf[14:16], t.Window)
	// checksum placeholder at 16..18
	binary.BigEndian.PutUint16(buf[18:20], t.UrgentPtr)

	// copy payload
	copy(buf[headerLen:], t.Data)

	// pseudo-header checksum calc
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = ProtocolTCP
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(totalLen))

	chkBuf := append(pseudoHeader, buf...)
	csum := utils.Checksum(chkBuf)
	binary.BigEndian.PutUint16(buf[16:18], csum)

	return buf
}

func (t *TCPHeader) String() string {
	var flags []string
	if t.Flags&TCPFlagSYN != 0 {
		flags = append(flags, "SYN")
	}
	if t.Flags&TCPFlagACK != 0 {
		flags = append(flags, "ACK")
	}
	if t.Flags&TCPFlagFIN != 0 {
		flags = append(flags, "FIN")
	}
	if t.Flags&TCPFlagRST != 0 {
		flags = append(flags, "RST")
	}
	if t.Flags&TCPFlagPSH != 0 {
		flags = append(flags, "PSH")
	}

	return fmt.Sprintf("[TCP] %d -> %d | Seq: %d | Ack: %d | Flags: %v",
		t.SrcPort, t.DstPort, t.SeqNum, t.AckNum, flags)
}
