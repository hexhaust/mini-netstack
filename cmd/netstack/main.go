package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/hexhaust/mini-netstack/pkg/device"
	"github.com/hexhaust/mini-netstack/pkg/frames"
)

const (
	DevName = "tap0"
	MTU     = 1500
)

func main() {
	// start TAP interface
	fmt.Printf("Initializing interface %s...\n", DevName)
	iface, err := device.NewTAP(DevName)
	if err != nil {
		log.Fatalf("Error creating TAP: %v", err)
	}
	defer iface.Close()
	fmt.Printf("Interface %s ready. Waiting for Ethernet frames...\n", DevName)

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

			// parse L2 (Ethernet)
			frame, err := frames.ParseEthernet(buf[:n])
			if err != nil {
				log.Printf("Dropping invalid frame: %v", err)
				continue
			}

			// structured log
			fmt.Println(frame.String())
		}
	}()

	// block until signal
	<-sigCh
	fmt.Println("\nShutting down netstack...")
}
