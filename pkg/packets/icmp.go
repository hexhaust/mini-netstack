package packets

import (
	"encoding/binary"
	"fmt"

	"github.com/hexhaust/mini-netstack/pkg/utils"
)

const (
	ICMPEchoReply   = 0
	ICMPEchoRequest = 8
)

// represents the header + payload
// structure: [Type(1)][Code(1)][Checksum(2)][ID(2)][Seq(2)][Data...]
type ICMPMessage struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
	Data     []byte
}

func ParseICMP(data []byte) (*ICMPMessage, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("packet too short for ICMP: %d bytes", len(data))
	}

	return &ICMPMessage{
		Type:     data[0],
		Code:     data[1],
		Checksum: binary.BigEndian.Uint16(data[2:4]),
		ID:       binary.BigEndian.Uint16(data[4:6]),
		Seq:      binary.BigEndian.Uint16(data[6:8]),
		Data:     data[8:],
	}, nil
}

// serializes the ICMP message and calculates checksum automatically
func (i *ICMPMessage) Bytes() []byte {
	length := 8 + len(i.Data)
	buf := make([]byte, length)

	buf[0] = i.Type
	buf[1] = i.Code
	// checksum starts at 0 for calculation
	buf[2] = 0
	buf[3] = 0
	binary.BigEndian.PutUint16(buf[4:6], i.ID)
	binary.BigEndian.PutUint16(buf[6:8], i.Seq)
	copy(buf[8:], i.Data)

	// calculate checksum over the whole packet
	csum := utils.Checksum(buf)
	binary.BigEndian.PutUint16(buf[2:4], csum)

	return buf
}

func (i *ICMPMessage) String() string {
	typeStr := "Unknown"
	if i.Type == ICMPEchoRequest {
		typeStr = "Echo Request"
	} else if i.Type == ICMPEchoReply {
		typeStr = "Echo Reply"
	}

	return fmt.Sprintf("[ICMP] Type=%d (%s) | ID=%d Seq=%d", i.Type, typeStr, i.ID, i.Seq)
}
