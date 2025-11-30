package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/hexhaust/mini-netstack/pkg/device"
	"github.com/hexhaust/mini-netstack/pkg/frames"
	"github.com/hexhaust/mini-netstack/pkg/packets"
)

const (
	DevName = "tap0"
	MTU     = 1500
)

// ANSI colors
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[90m"
)

var (
	MyIP  = net.IPv4(192, 168, 1, 10)
	MyMAC = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
)

func main() {
	fmt.Printf(ColorCyan+"Initializing interface %s...\n"+ColorReset, DevName)
	iface, err := device.NewTAP(DevName)
	if err != nil {
		log.Fatalf("Error creating TAP: %v", err)
	}
	defer iface.Close()
	fmt.Printf(ColorCyan+"Interface %s ready.\n"+ColorReset, DevName)
	fmt.Printf(ColorCyan+"I am %s (MAC: %s)\nWaiting for packets...\n"+ColorReset, MyIP, MyMAC)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		buf := make([]byte, MTU)
		for {
			n, err := iface.Read(buf)
			if err != nil {
				log.Printf("Read error: %v", err)
				return
			}

			frame, err := frames.ParseEthernet(buf[:n])
			if err != nil {
				continue
			}

			switch frame.EtherType {
			case frames.EtherTypeARP:
				handleARP(iface, frame)
			case frames.EtherTypeIPv4:
				handleIPv4(iface, frame)
			}
		}
	}()

	<-sigCh
	fmt.Println("\nShutting down netstack...")
}

func handleARP(iface *device.Interface, frame *frames.EthernetFrame) {
	arp, err := packets.ParseARP(frame.Payload)
	if err != nil {
		return
	}

	if arp.Operation == packets.ARPRequest && arp.DstIP.Equal(MyIP) {
		fmt.Printf(ColorYellow+"[ARP] Who is %s? It's me! Sending reply...\n"+ColorReset, MyIP)

		replyPayload, _ := arp.ReplyAs(MyMAC, MyIP.To4())
		ethReply := frames.EthernetFrame{
			DstMAC:    [6]byte(arp.SrcMAC),
			SrcMAC:    [6]byte(MyMAC),
			EtherType: frames.EtherTypeARP,
			Payload:   replyPayload,
		}
		iface.Write(ethReply.Bytes())
	}
}

func handleIPv4(iface *device.Interface, frame *frames.EthernetFrame) {
	ipPacket, err := packets.ParseIPv4(frame.Payload)
	if err != nil {
		return
	}

	if !ipPacket.DstIP.Equal(MyIP) {
		return
	}

	switch ipPacket.Protocol {
	case packets.ProtocolICMP:
		handleICMP(iface, frame, ipPacket)
	case packets.ProtocolUDP:
		handleUDP(iface, frame, ipPacket)
	case packets.ProtocolTCP:
		handleTCP(iface, frame, ipPacket)
	}
}

func handleICMP(iface *device.Interface, frame *frames.EthernetFrame, ipPacket *packets.IPv4Header) {
	icmpPacket, err := packets.ParseICMP(frame.Payload[20:])
	if err != nil {
		return
	}
	if icmpPacket.Type == packets.ICMPEchoRequest {
		fmt.Printf(ColorPurple+"[ICMP] Ping Request (ID=%d Seq=%d). Sending Pong!\n"+ColorReset, icmpPacket.ID, icmpPacket.Seq)
		pong := packets.ICMPMessage{
			Type: packets.ICMPEchoReply, Code: 0, ID: icmpPacket.ID, Seq: icmpPacket.Seq, Data: icmpPacket.Data,
		}
		sendIPv4(iface, frame.SrcMAC, ipPacket.SrcIP, packets.ProtocolICMP, pong.Bytes())
	}
}

func handleUDP(iface *device.Interface, frame *frames.EthernetFrame, ipPacket *packets.IPv4Header) {
	udpPacket, err := packets.ParseUDP(frame.Payload[20:])
	if err != nil {
		return
	}

	fmt.Printf(ColorBlue+"[UDP] %d -> %d: %q\n"+ColorReset, udpPacket.SrcPort, udpPacket.DstPort, string(udpPacket.Data))

	replyUDP := packets.UDPPacket{
		SrcPort: udpPacket.DstPort, DstPort: udpPacket.SrcPort, Data: udpPacket.Data,
	}
	sendIPv4(iface, frame.SrcMAC, ipPacket.SrcIP, packets.ProtocolUDP, replyUDP.Bytes(MyIP, ipPacket.SrcIP))
}

func handleTCP(iface *device.Interface, frame *frames.EthernetFrame, ipPacket *packets.IPv4Header) {
	tcpPacket, err := packets.ParseTCP(frame.Payload[20:])
	if err != nil {
		log.Printf("TCP Error: %v", err)
		return
	}

	// logs raw TCP details in gray to reduce noise
	fmt.Printf(ColorGray+"%s\n"+ColorReset, tcpPacket.String())

	// handle closed ports (send RST to stop retries)
	if tcpPacket.DstPort != 80 {
		fmt.Printf(ColorRed+"   -> Port %d closed. Sending RST.\n"+ColorReset, tcpPacket.DstPort)
		rst := packets.TCPHeader{
			SrcPort:    tcpPacket.DstPort,
			DstPort:    tcpPacket.SrcPort,
			SeqNum:     0,
			AckNum:     tcpPacket.SeqNum + 1,
			DataOffset: 5,
			Flags:      packets.TCPFlagRST | packets.TCPFlagACK,
			Window:     0,
		}
		sendIPv4(iface, frame.SrcMAC, ipPacket.SrcIP, packets.ProtocolTCP, rst.Bytes(MyIP, ipPacket.SrcIP))
		return
	}

	// handshake step 1: client sends SYN
	if (tcpPacket.Flags & packets.TCPFlagSYN) != 0 {
		fmt.Printf(ColorGreen + "   -> Connection Request (SYN). Sending SYN-ACK...\n" + ColorReset)

		synAck := packets.TCPHeader{
			SrcPort:    tcpPacket.DstPort,
			DstPort:    tcpPacket.SrcPort,
			SeqNum:     1000,
			AckNum:     tcpPacket.SeqNum + 1,
			DataOffset: 5,
			Flags:      packets.TCPFlagSYN | packets.TCPFlagACK,
			Window:     65535,
			UrgentPtr:  0,
		}

		sendIPv4(iface, frame.SrcMAC, ipPacket.SrcIP, packets.ProtocolTCP, synAck.Bytes(MyIP, ipPacket.SrcIP))
		return
	}

	// handle FIN (client wants to close)
	if (tcpPacket.Flags & packets.TCPFlagFIN) != 0 {
		fmt.Printf(ColorYellow + "   -> Client sent FIN. Sending FIN-ACK.\n" + ColorReset)

		// respond with FIN-ACK to ack closure
		// SeqNum 1001 (assuming we sent SYN-ACK at 1000 previously)
		finAck := packets.TCPHeader{
			SrcPort:    tcpPacket.DstPort,
			DstPort:    tcpPacket.SrcPort,
			SeqNum:     1001,
			AckNum:     tcpPacket.SeqNum + 1,
			DataOffset: 5,
			Flags:      packets.TCPFlagFIN | packets.TCPFlagACK,
			Window:     65535,
			UrgentPtr:  0,
		}
		sendIPv4(iface, frame.SrcMAC, ipPacket.SrcIP, packets.ProtocolTCP, finAck.Bytes(MyIP, ipPacket.SrcIP))
		return
	}

	// handshake step 3: client sends ACK
	if (tcpPacket.Flags & packets.TCPFlagACK) != 0 {
		if tcpPacket.AckNum == 1001 {
			fmt.Printf(ColorGreen + "   -> Connection ESTABLISHED! (Client Acked our SYN)\n" + ColorReset)
		}
	}
}

func sendIPv4(iface *device.Interface, dstMAC [6]byte, dstIP net.IP, protocol uint8, data []byte) {
	ipHeader := packets.IPv4Header{
		Version: 4, IHL: 5, TotalLength: uint16(20 + len(data)), TTL: 64, Protocol: protocol, SrcIP: MyIP, DstIP: dstIP,
	}
	ethFrame := frames.EthernetFrame{
		DstMAC: dstMAC, SrcMAC: [6]byte(MyMAC), EtherType: frames.EtherTypeIPv4, Payload: append(ipHeader.Bytes(), data...),
	}
	iface.Write(ethFrame.Bytes())
}
