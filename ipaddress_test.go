package wireguardhttps

import (
	"net"
	"testing"
)

func TestAddressRangeStart(t *testing.T) {
	network := mustParseCIDR("10.0.0.0/24")
	addressRange := &AddressRange{network}
	expectedStart := net.ParseIP("10.0.0.0")
	if !addressRange.Start().Equal(expectedStart) {
		t.Errorf("Expected %v, got %v", expectedStart, addressRange.Start())
	}
}

func TestAddressRangeFinish(t *testing.T) {
	network := mustParseCIDR("10.0.0.0/24")
	addressRange := &AddressRange{network}
	expectedFinish := net.ParseIP("10.0.0.255")
	if !addressRange.Finish().Equal(expectedFinish) {
		t.Errorf("Expected %v, got %v", expectedFinish, addressRange.Finish())
	}
}

func TestNextAddressAddressInRange(t *testing.T) {
	network := mustParseCIDR("10.0.0.0/24")
	addressRange := &AddressRange{network}
	currentIP := mustParseCIDR("10.0.0.1/32")
	expectedNext := net.ParseIP("10.0.0.2")
	actualNext, err := addressRange.Next(currentIP.IP)
	if err != nil {
		t.Errorf("Error getting next IP: %v", err)
	}

	if !actualNext.Equal(expectedNext) {
		t.Errorf("Expected %v, got %v", expectedNext, actualNext)
	}
}

func TestErrorReturnedIPNotInNetwork(t *testing.T) {
	network := mustParseCIDR("10.0.0.0/24")
	addressRange := &AddressRange{network}
	incorrectIP := mustParseCIDR("192.168.1.1/32")
	_, err := addressRange.Next(incorrectIP.IP)
	if err == nil {
		t.Errorf("Expected error: %v is not in subnet %v", incorrectIP, network)
	}

	if _, ok := err.(*IPNotInSubnetError); !ok {
		t.Errorf("Expected IPNotInSubneterror, got %v", err)
	}
}

func TestErrorReturnedEndOfSubnet(t *testing.T) {
	network := mustParseCIDR("10.0.0.0/24")
	addressRange := &AddressRange{network}
	finalIP := mustParseCIDR("10.0.0.255/32")
	_, err := addressRange.Next(finalIP.IP)
	if err == nil {
		t.Errorf("Expected error: %v is the last address in subnet %v", finalIP, network)
	}

	if _, ok := err.(*IPsExhaustedError); !ok {
		t.Errorf("Expected IPsExhaustedError, got %v", err)
	}
}

func mustParseCIDR(cidr string) net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}

	return *network
}
