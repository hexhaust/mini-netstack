package device

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Linux Kernel constants (if_tun.h)
const (
	IFF_TAP      = 0x0002
	IFF_NO_PI    = 0x1000
	TUNSETIFF    = 0x400454ca
	SysCallIoctl = 16 // ioctl syscall ID for linux amd64
)

// struct used to pass parameters via ioctl (man netdevice)
type ifReq struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte // padding to complete the C struct size
}

// represents our network device
type Interface struct {
	File *os.File
	Name string
}

// opens or creates a TAP interface
func NewTAP(devName string) (*Interface, error) {
	// open the "main" driver file
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %v", err)
	}

	var req ifReq
	req.Flags = IFF_TAP | IFF_NO_PI
	copy(req.Name[:], devName)

	// syscall magic to transform the file descriptor into a network interface
	// USANDO SYSCALL CLÁSSICA (Linux)
	_, _, errno := syscall.Syscall(
		uintptr(SysCallIoctl),
		file.Fd(),
		uintptr(TUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("ioctl failed: %v", errno)
	}

	return &Interface{
		File: file,
		Name: devName,
	}, nil
}

// reads raw bytes from the interface (Ethernet frames)
func (iface *Interface) Read(buf []byte) (int, error) {
	return iface.File.Read(buf)
}

// writes bytes to the interface
func (iface *Interface) Write(buf []byte) (int, error) {
	return iface.File.Write(buf)
}

// closes the file descriptor
func (iface *Interface) Close() error {
	return iface.File.Close()
}
