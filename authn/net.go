package authn

import (
	"net"
	"net/netip"
	"strings"
)

func splitHost(hostport string) (string, string, error) {
	return net.SplitHostPort(hostport)
}

func addrLoopback(host string) bool {
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.Unmap().IsLoopback()
}
