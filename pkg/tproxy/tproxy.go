// Package tproxy provides a Linux transparent proxy implementation
// that can be used both to receive and send traffic with any address.
package tproxy

import (
	"context"
	"net"
	"net/netip"

	"github.com/go-logr/logr"
	"github.com/tillycode/anytunnel/pkg/network"
	"go4.org/netipx"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

type TProxy interface {
	network.Dialer

	// The channel is closed when the TPROXY is ready to accept connections.
	Ready() <-chan struct{}

	// Run blocks until the context is done.
	Run(ctx context.Context) error
}

type TProxyOptions struct {
	// Port for the TPROXY listener.
	// If zero, a random port will be picked
	TCPPort uint16
	UDPPort uint16

	// Whether to setup nftables and routing rules.
	// If true, CAP_NET_ADMIN is required.
	SetupRoute   bool
	SetupNFTable bool
	Priority     int
	Table        int
	Mark         uint32
	NFTableName  string
	RouteIPSet   *netipx.IPSet
}

type tproxy struct {
	handler network.Handler
	options *TProxyOptions
	ready   chan struct{}
}

func NewTProxy(
	handler network.Handler,
	options *TProxyOptions,
) (TProxy, error) {
	return &tproxy{
		handler: handler,
		options: options,
		ready:   make(chan struct{}),
	}, nil
}

func (t *tproxy) Dial(
	ctx context.Context,
	network network.Network,
	laddr,
	raddr netip.AddrPort,
) (net.Conn, error) {
	return nil, nil
}

func (t *tproxy) Ready() <-chan struct{} {
	return t.ready
}

func (t *tproxy) Run(ctx context.Context) (err error) {
	eg, ctx := errgroup.WithContext(ctx)
	tcpReady := make(chan struct{})
	udpReady := make(chan struct{})
	eg.Go(func() error {
		return handleIncomingTCP(ctx, t.handler, &t.options.TCPPort, tcpReady)
	})
	eg.Go(func() error {
		return handleIncomingUDP(ctx, t.handler, &t.options.UDPPort, udpReady)
	})
	eg.Go(func() error {
		// wait for both listeners to be ready
		select {
		case <-ctx.Done():
			return nil
		case <-tcpReady:
		}
		select {
		case <-ctx.Done():
			return nil
		case <-udpReady:
		}

		logger := logr.FromContextOrDiscard(ctx).WithName("network-admin")
		if t.options.SetupRoute {
			options := routeOptions{
				Priority: t.options.Priority,
				Table:    t.options.Table,
				Mark:     t.options.Mark,
			}
			defer func() {
				if err := cleanupRoute(&options, unix.AF_INET); err != nil {
					logger.Error(err, "failed to cleanup ipv4 route")
				}
			}()
			if err := setupRoute(&options, unix.AF_INET); err != nil {
				return err
			}
			defer func() {
				if err := cleanupRoute(&options, unix.AF_INET6); err != nil {
					logger.Error(err, "failed to cleanup ipv6 route")
				}
			}()
			if err := setupRoute(&options, unix.AF_INET6); err != nil {
				return err
			}
		}
		if t.options.SetupNFTable {
			defer func() {
				if err := cleanupNFTable(t.options.NFTableName); err != nil {
					logger.Error(err, "failed to cleanup NF table")
				}
			}()
			if err := cleanupNFTable(t.options.NFTableName); err != nil {
				logger.Error(err, "failed to cleanup NF table")
			}
			if err := setupNFTable(&nfTableOptions{
				Name:       t.options.NFTableName,
				TProxyMark: t.options.Mark,
				TProxyPort: t.options.TCPPort,
				RouteIPSet: t.options.RouteIPSet,
			}); err != nil {
				return err
			}
		}
		close(t.ready)
		<-ctx.Done()
		return nil
	})
	return eg.Wait()
}
