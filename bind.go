package mailbox

import (
	"errors"
	"net"
	"strconv"
)

// ErrPublicBind means the address is not a private LAN address or loopback.
// The mailbox refuses it and does not listen.
var ErrPublicBind = errors.New("mailbox: refusing public bind")

// ValidateAddr allows loopback (for tests), private LAN addresses, and
// link-local addresses. It refuses public addresses, unspecified addresses
// such as 0.0.0.0, hostnames, and anything that is not an IP literal.
// The mailbox does not resolve names and does not advertise the listener.
func ValidateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return ErrPublicBind
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return ErrPublicBind
	}
	if !hostAllowed(host) {
		return ErrPublicBind
	}
	return nil
}

func hostAllowed(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func sourceAllowed(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	return hostAllowed(host)
}
