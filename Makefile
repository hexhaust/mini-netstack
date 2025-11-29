# project vars
BINARY_NAME=netstack
CMD_PATH=./cmd/netstack/main.go
INTERFACE=tap0
IP_ADDR=192.168.1.1/24

# Go vars
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin

.PHONY: all build run clean setup teardown help

all: build

## binary build
build:
	@echo "  >  Building binary..."
	@go build -o $(GOBIN)/$(BINARY_NAME) $(CMD_PATH)

## setup: create the TAP interface (requires sudo)
setup:
	@echo "  >  Setting up TAP interface $(INTERFACE)..."
	-sudo ip tuntap add mode tap user $(USER) name $(INTERFACE)
	-sudo ip link set $(INTERFACE) up
	-sudo ip addr add $(IP_ADDR) dev $(INTERFACE)

## teardown: remove TAP interface
teardown:
	@echo "  >  Cleaning up interface $(INTERFACE)..."
	-sudo ip link del $(INTERFACE)

## run: build and run the app (automatically manages setup/teardown)
run: build setup
	@echo "  >  Running $(BINARY_NAME)..."
	@# Run with sudo as we need to open /dev/net/tun or raw sockets
	@# In production, we would use setcap cap_net_admin+ep, but sudo is ok for dev.
	sudo $(GOBIN)/$(BINARY_NAME)
	@$(MAKE) teardown

## clean: remove build cache
clean:
	@echo "  >  Cleaning build cache..."
	@go clean
	@rm -rf $(GOBIN)

help: Makefile
	@echo
	@echo " Choose a command to run in $(BINARY_NAME):"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo