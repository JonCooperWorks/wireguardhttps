package wireguardhttps

import (
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	snapshotLen = 1024
	promiscuous = false
	timeout     = 30 * time.Second
)

// Flow is a source, dest pair from a packet used to route packets to subscribers.
type Flow struct {
	Src net.IP
	Dst net.IP
}

// SubscriberSet implements a Set data type for unique entries and O(1) deletion.
type SubscriberSet map[string]bool

// PacketStream allows for recording traffic sent over the VPN interface.
// It maintains a one-to-many mapping of device IP addresses to listener key IDs, and a one-to-one mapping of listener key IDs to subscription channels.
// It is intended to quickly sort traffic intended for listeners only when there is an active listener, and do nothing otherwise.
type PacketStream struct {
	DeviceName         string
	subscriberRegistry map[string]SubscriberSet
	subscribers        map[string]chan gopacket.Packet
}

// NewPacketStream returns a PacketStream configured to stream packets from the named device.
func NewPacketStream(deviceName string) *PacketStream {
	return &PacketStream{
		DeviceName:         deviceName,
		subscriberRegistry: map[string]SubscriberSet{},
		subscribers:        map[string]chan gopacket.Packet{},
	}
}

// Capture is meant to be run in a background goroutine from the main thread.
// It listens on the VPN interface and passes packets back to subscribers.
func (p *PacketStream) Capture() {
	handle, err := pcap.OpenLive(p.DeviceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Only receive IP packets from the VPN
	err = handle.SetBPFFilter("ip")
	if err != nil {
		log.Fatal(err)
	}

	// Past this point is performance crtiical code.
	// Billions of packets per second may pass through the PacketSource depending on where this server is deployed.
	// Do not do any more work than necessary in the loop on the Capture goroutine.
	// Speed up packet parsing by pre-allocating memory for packets.
	var eth layers.Ethernet
	var ip4 layers.IPv4
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		flow := sourceIP(parser, packet, ip4)
		if flow != nil {
			// Process packet in the background and move to the next packet
			go p.sendPacketToSubscribers(flow, packet)
		}
	}
}

func (p *PacketStream) sendPacketToSubscribers(flow *Flow, packet gopacket.Packet) {
	// If traffic is going to or from a subscriber, send the packet to that subscriber.
	srcSubscribers, ok := p.subscriberRegistry[flow.Src.String()]
	if ok {
		for subscriberUUID := range srcSubscribers {
			subscriber := p.subscribers[subscriberUUID]
			subscriber <- packet
		}
	}

	dstSubscribers, ok := p.subscriberRegistry[flow.Dst.String()]
	if ok {
		for subscriberUUID := range dstSubscribers {
			subscriber := p.subscribers[subscriberUUID]
			subscriber <- packet
		}
	}

}

// Subscribe adds a callback to our internal registry of callbacks.
func (p *PacketStream) Subscribe(ip net.IP, nonce string) <-chan gopacket.Packet {
	address := ip.String()
	subscription := make(chan gopacket.Packet)
	p.subscriberRegistry[address] = SubscriberSet{}
	p.subscriberRegistry[address][nonce] = true
	p.subscribers[nonce] = subscription
	return subscription
}

// Unsubscribe removes a callback from the registry.
func (p *PacketStream) Unsubscribe(ip net.IP, nonce string) {
	address := ip.String()
	close(p.subscribers[nonce])
	delete(p.subscriberRegistry[address], nonce)
	delete(p.subscribers, nonce)
}

func sourceIP(parser *gopacket.DecodingLayerParser, rawPacket gopacket.Packet, ip4 layers.IPv4) *Flow {
	decoded := []gopacket.LayerType{}
	if err := parser.DecodeLayers(rawPacket.Data(), &decoded); err != nil {
		return nil
	}

	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeIPv4:
			return &Flow{
				Src: ip4.SrcIP,
				Dst: ip4.DstIP,
			}
		}
	}

	return nil
}
