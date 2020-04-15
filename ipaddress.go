package wireguardhttps

import (
	"encoding/binary"
	"fmt"
	"net"
)

type IPNotInSubnetError struct {
	Network net.IPNet
	IP      net.IP
}

func (i *IPNotInSubnetError) Error() string {
	return fmt.Sprintf("%v is not in subnet %v", i.IP, i.Network)
}

type IPsExhaustedError struct {
	Network net.IPNet
}

func (i *IPsExhaustedError) Error() string {
	return fmt.Sprintf("%v is out of IP addresses", i.Network)
}

// AddressRange provides methods for assigning IP addresses within a subnet.
type AddressRange struct {
	Network net.IPNet
}

func (a *AddressRange) Start() net.IP {
	return a.Network.IP
}

// Next returns the next IP address within a subnet given the last IP address.
// It will fail with an error if the IP address in not within the subnet, or if the subnet has run out of IP addresses.
// Callers should prevent IP address conflicts, by ensuring only one IP address can be assigned at a time in a subnet, such as by using a `sync.Mutex`.
func (a *AddressRange) Next(current net.IP) (net.IP, error) {
	if !a.Network.Contains(current) {
		return nil, &IPNotInSubnetError{
			Network: a.Network,
			IP:      current,
		}
	}

	if current.Equal(a.Finish()) {
		return nil, &IPsExhaustedError{
			Network: a.Network,
		}
	}

	ip := make(net.IP, 4)
	next := binary.BigEndian.Uint32(current) + 1
	binary.BigEndian.PutUint32(ip, next)
	return ip, nil
}

func (a *AddressRange) Finish() net.IP {
	mask := binary.BigEndian.Uint32(a.Network.Mask)
	start := binary.BigEndian.Uint32(a.Start())
	finish := (start & mask) | (mask ^ 0xffffffff)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, finish)
	return ip
}
