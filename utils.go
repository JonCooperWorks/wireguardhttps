package wireguardhttps

import (
	"net"
)

func ipNetsToStrings(nets []net.IPNet) []string {
	rv := []string{}
	for _, n := range nets {
		rv = append(rv, n.String())
	}

	return rv
}

func ipsToStrings(ips []net.IP) []string {
	rv := []string{}
	for _, n := range ips {
		rv = append(rv, n.String())
	}

	return rv
}
