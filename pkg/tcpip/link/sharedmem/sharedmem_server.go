// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package sharedmem

import (
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type serverEndpoint struct {
	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu uint32

	// bufferSize is the size of each individual buffer.
	bufferSize uint32

	// addr is the local address of this endpoint.
	addr tcpip.LinkAddress

	// rx is the receive queue.
	rx serverRx

	// stopRequested is to be accessed atomically only, and determines if
	// the worker goroutines should stop.
	stopRequested uint32

	// Wait group used to indicate that all workers have stopped.
	completed sync.WaitGroup

	// mu protects the following fields.
	mu sync.Mutex

	// tx is the transmit queue.
	tx serverTx

	// workerStarted specifies whether the worker goroutine was started.
	workerStarted bool

	// peerFD is an fd to the peer that can be used to detect when the
	// peer is gone.
	peerFD int
}

// NewServerEndpoint creates a new shared-memory-based endpoint. Buffers will be broken up
// into buffers of "bufferSize" bytes.
func NewServerEndpoint(mtu, bufferSize uint32, addr tcpip.LinkAddress, tx, rx QueueConfig, peerFD int, ClosedFunc func()) (stack.LinkEndpoint, error) {
	e := &serverEndpoint{
		mtu:        mtu,
		bufferSize: bufferSize,
		addr:       addr,
		peerFD:     peerFD,
	}

	if err := e.tx.init(&rx); err != nil {
		return nil, err
	}

	if err := e.rx.init(&tx); err != nil {
		e.tx.cleanup()
		return nil, err
	}
	if ClosedFunc != nil {
		// Spin up a goroutine to monitor for peer shutdown.
		go func() {
			defer ClosedFunc()
			b := make([]byte, 1)
			n, err := rawfile.BlockingRead(peerFD, b)
			if n <= 0 || err != nil {
				return
			}
		}()
	}
	return e, nil
}

// Close frees all resources associated with the endpoint.
func (e *serverEndpoint) Close() {
	// Tell dispatch goroutine to stop, then write to the eventfd so that
	// it wakes up in case it's sleeping.
	atomic.StoreUint32(&e.stopRequested, 1)
	unix.Write(e.rx.eventFD, []byte{1, 0, 0, 0, 0, 0, 0, 0})

	// Cleanup the queues inline if the worker hasn't started yet; we also
	// know it won't start from now on because stopRequested is set to 1.
	e.mu.Lock()
	workerPresent := e.workerStarted
	e.mu.Unlock()

	if !workerPresent {
		e.tx.cleanup()
		e.rx.cleanup()
	}
}

// Wait implements stack.LinkEndpoint.Wait. It waits until all workers have
// stopped after a Close() call.
func (e *serverEndpoint) Wait() {
	e.completed.Wait()
}

// Attach implements stack.LinkEndpoint.Attach. It launches the goroutine that
// reads packets from the rx queue.
func (e *serverEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	if !e.workerStarted && atomic.LoadUint32(&e.stopRequested) == 0 {
		e.workerStarted = true
		e.completed.Add(1)
		// Link endpoints are not savable. When transportation endpoints
		// are saved, they stop sending outgoing packets and all
		// incoming packets are rejected.
		go e.dispatchLoop(dispatcher) // S/R-SAFE: see above.
	}
	e.mu.Unlock()
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *serverEndpoint) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.workerStarted
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *serverEndpoint) MTU() uint32 {
	return e.mtu - header.EthernetMinimumSize
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (*serverEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload | stack.CapabilityTXChecksumOffload
}

// MaxHeaderLength implements stack.LinkEndpoint.MaxHeaderLength. It returns th0e
// ethernet frame header size.
func (*serverEndpoint) MaxHeaderLength() uint16 {
	return header.EthernetMinimumSize
}

// LinkAddress implements stack.LinkEndpoint.LinkAddress. It returns the local
// link address.
func (e *serverEndpoint) LinkAddress() tcpip.LinkAddress {
	return e.addr
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *serverEndpoint) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	// Add ethernet header if needed.
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	ethHdr := &header.EthernetFields{
		DstAddr: remote,
		Type:    protocol,
	}

	// Preserve the src address if it's set in the route.
	if local != "" {
		ethHdr.SrcAddr = local
	} else {
		ethHdr.SrcAddr = e.addr
	}
	eth.Encode(ethHdr)
}

// WriteRawPacket implements stack.LinkEndpoint.
func (*serverEndpoint) WriteRawPacket(*stack.PacketBuffer) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (e *serverEndpoint) writePacketLocked(r stack.RouteInfo, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	e.AddHeader(r.LocalLinkAddress, r.RemoteLinkAddress, protocol, pkt)

	views := pkt.Views()
	ok := e.tx.transmit(views)
	if !ok {
		return &tcpip.ErrWouldBlock{}
	}

	return nil
}

// WritePacket writes outbound packets to the file descriptor. If it is not
// currently writable, the packet is dropped.
func (e *serverEndpoint) WritePacket(r stack.RouteInfo, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	// Transmit the packet.
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.writePacketLocked(r, protocol, pkt); err != nil {
		return err
	}
	e.tx.notify()
	return nil
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (e *serverEndpoint) WritePackets(r stack.RouteInfo, pkts stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	n := 0
	var err tcpip.Error
	e.mu.Lock()
	defer e.mu.Unlock()
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		if err = e.writePacketLocked(r, pkt.NetworkProtocolNumber, pkt); err != nil {
			break
		}
		n++
	}
	// WritePackets never returns an error if it successfully transmitted at least
	// one packet.
	if err != nil && n == 0 {
		return 0, err
	}
	e.tx.notify()
	return n, nil
}

// dispatchLoop reads packets from the rx queue in a loop and dispatches them
// to the network stack.
func (e *serverEndpoint) dispatchLoop(d stack.NetworkDispatcher) {
	for atomic.LoadUint32(&e.stopRequested) == 0 {
		b := e.rx.receive()
		if b == nil {
			e.rx.waitForPackets()
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: buffer.View(b).ToVectorisedView(),
		})

		hdr, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
		if !ok {
			continue
		}
		eth := header.Ethernet(hdr)
		// Send packet up the stack.
		d.DeliverNetworkPacket(eth.SourceAddress(), eth.DestinationAddress(), eth.Type(), pkt)
	}

	// Clean state.
	e.tx.cleanup()
	e.rx.cleanup()

	e.completed.Done()
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType
func (*serverEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}
