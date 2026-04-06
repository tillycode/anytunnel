package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/tillycode/anytunnel/pkg/network"
	"github.com/tillycode/anytunnel/pkg/tproxy"
	"go.uber.org/zap"
	"go4.org/netipx"
)

func main() {
	_logger, _ := zap.NewDevelopmentConfig().Build()
	defer func() { _ = _logger.Sync() }()
	logger := zapr.NewLogger(_logger)
	defer logger.V(1).Info("gracefully shutdown")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx = logr.NewContext(ctx, logger)

	var builder netipx.IPSetBuilder
	builder.AddPrefix(netip.MustParsePrefix("192.168.10.0/24"))
	builder.AddPrefix(netip.MustParsePrefix("fcfe:fcfe::/48"))
	set, err := builder.IPSet()
	if err != nil {
		panic(err)
	}

	tproxy, err := tproxy.NewTProxy(network.HandlerFunc(func(ctx context.Context, c net.Conn, n network.Network, laddr, raddr netip.AddrPort) {
		defer func() { _ = c.Close() }()
		logger.V(1).Info("accepted connection", "network", n, "laddr", laddr, "raddr", raddr)
		if n == network.NetworkUDP {
			return
		}
		reader := bufio.NewReader(c)
		_, err := http.ReadRequest(reader)
		if err != nil {
			log.Println("failed to read request", err)
			return
		}
		_, err = c.Write([]byte(`HTTP/1.1 200 OK
Content-Length: 13

Hello, World!`))
		if err != nil {
			log.Println("failed to write response", err)
			return
		}
		_, err = io.Copy(io.Discard, reader)
		if err != nil {
			log.Println("failed to discard request body", err)
			return
		}
	}), &tproxy.TProxyOptions{
		TCPPort:      20333,
		UDPPort:      20333,
		SetupRoute:   true,
		SetupNFTable: true,
		Priority:     233,
		Table:        233,
		Mark:         0x1996,
		NFTableName:  "anytunnel",
		RouteIPSet:   set,
	})
	if err != nil {
		panic(err)
	}

	if err := tproxy.Run(ctx); err != nil {
		panic(err)
	}
}
