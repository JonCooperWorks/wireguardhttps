package wireguardhttps

import (
	"encoding/binary"
	"errors"
	"net"
)

// AddressRange provides methods for managing IP addresses within a
type AddressRange struct {
	Network net.IPNet
}

func (a *AddressRange) Start() net.IP {
	return a.Network.IP
}

func (a *AddressRange) Next(currentIP net.IPNet) (*net.IP, error) {
	current := currentIP.IP

	// TODO: specific error for IP not in range
	if !a.Network.Contains(current) {
		return nil, errors.New("")
	}

	// TODO: specific error for out of IP addresses
	if current.Equal(a.Finish()) {
		return nil, errors.New("")
	}

	ip := make(net.IP, 4)
	next := binary.BigEndian.Uint32(current) + 1
	binary.BigEndian.PutUint32(ip, next)
	return &ip, nil
}

func (a *AddressRange) Finish() net.IP {
	mask := binary.BigEndian.Uint32(a.Network.Mask)
	start := binary.BigEndian.Uint32(a.Start())
	finish := (start & mask) | (mask ^ 0xffffffff)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, finish)
	return ip
}
