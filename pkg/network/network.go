// Package network provides a set of interfaces shared by multiple modules.
package network

import (
	"context"
	"net"
	"net/netip"
)

type Network int

const (
	NetworkTCP Network = iota
	NetworkUDP
)

func (n Network) String() string {
	switch n {
	case NetworkTCP:
		return "tcp"
	case NetworkUDP:
		return "udp"
	}
	return ""
}

type Handler interface {
	Handle(ctx context.Context, c net.Conn, network Network, laddr, raddr netip.AddrPort)
}

type HandlerFunc func(ctx context.Context, c net.Conn, network Network, laddr, raddr netip.AddrPort)

func (f HandlerFunc) Handle(ctx context.Context, c net.Conn, network Network, laddr, raddr netip.AddrPort) {
	f(ctx, c, network, laddr, raddr)
}

type Dialer interface {
	Dial(ctx context.Context, network Network, laddr, raddr netip.AddrPort) (net.Conn, error)
}
