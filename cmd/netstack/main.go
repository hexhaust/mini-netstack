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

// virtual identity
var (
	MyIP  = net.IPv4(192, 168, 1, 10)
	MyMAC = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
)

func main() {
	// start TAP interface
	fmt.Printf("Initializing interface %s...\n", DevName)
	iface, err := device.NewTAP(DevName)
	if err != nil {
		log.Fatalf("Error creating TAP: %v", err)
	}
	defer iface.Close()
	fmt.Printf("Interface %s ready.\n", DevName)
	fmt.Printf("I am %s (MAC: %s)\nWaiting for packets...\n", MyIP, MyMAC)

	// setup graceful shutdown (Ctrl+C)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// read loop
	go func() {
		buf := make([]byte, MTU)
		for {
			n, err := iface.Read(buf)
			if err != nil {
				log.Printf("Read error: %v", err)
				return
			}

			// parse L2 (ethernet)
			frame, err := frames.ParseEthernet(buf[:n])
			if err != nil {
				// too noisy to log every bad frame
				continue
			}

			// L3 switch
			switch frame.EtherType {
			case frames.EtherTypeARP:
				handleARP(iface, frame)

			case frames.EtherTypeIPv4:
				handleIPv4(iface, frame)

			case frames.EtherTypeIPv6:
				// silence
			}
		}
	}()

	<-sigCh
	fmt.Println("\nShutting down netstack...")
}

// handlers organized

func handleARP(iface *device.Interface, frame *frames.EthernetFrame) {
	arp, err := packets.ParseARP(frame.Payload)
	if err != nil {
		return
	}

	if arp.Operation == packets.ARPRequest && arp.DstIP.Equal(MyIP) {
		fmt.Printf("[ARP] Who is %s? It's me! Sending reply...\n", MyIP)

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

	// filter: only packets for me
	if !ipPacket.DstIP.Equal(MyIP) {
		return
	}

	fmt.Println(ipPacket.String())

	// L4 switch (ICMP is actually L3.5 but sits inside IP payload)
	if ipPacket.Protocol == packets.ProtocolICMP {
		icmpPacket, err := packets.ParseICMP(frame.Payload[20:]) // skip 20 bytes IP header
		if err != nil {
			log.Printf("ICMP Parse error: %v", err)
			return
		}

		if icmpPacket.Type == packets.ICMPEchoRequest {
			fmt.Printf("   -> Ping Request (ID=%d Seq=%d). Sending Pong!\n", icmpPacket.ID, icmpPacket.Seq)

			// create ICMP reply
			pong := packets.ICMPMessage{
				Type: packets.ICMPEchoReply, // change type to 0
				Code: 0,
				ID:   icmpPacket.ID,   // copy ID
				Seq:  icmpPacket.Seq,  // copy seq
				Data: icmpPacket.Data, // echo back the data payload
			}
			pongBytes := pong.Bytes()

			// create IPv4 header
			// src = me, dst = sender
			replyIP := packets.IPv4Header{
				Version:        4,
				IHL:            5, // 20 bytes
				TOS:            0,
				TotalLength:    uint16(20 + len(pongBytes)),
				Identification: 0, // not fragmenting, so 0 is fine
				Flags:          0,
				FragmentOffset: 0,
				TTL:            64,
				Protocol:       packets.ProtocolICMP,
				SrcIP:          MyIP,
				DstIP:          ipPacket.SrcIP,
			}
			ipBytes := replyIP.Bytes()

			// encapsulate in Ethernet
			ethReply := frames.EthernetFrame{
				DstMAC:    frame.SrcMAC,
				SrcMAC:    [6]byte(MyMAC),
				EtherType: frames.EtherTypeIPv4,
				Payload:   append(ipBytes, pongBytes...), // IP header + ICMP payload
			}

			// send
			iface.Write(ethReply.Bytes())
		}
	}
}
