package tproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/go-logr/logr"
	"github.com/tillycode/anytunnel/pkg/network"
	"golang.org/x/sys/unix"
)

func unmapAddrPort(addr netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
}

func handleIncomingTCP(
	ctx context.Context,
	handler network.Handler,
	port *uint16,
	ready chan<- struct{},
) error {
	logger := logr.FromContextOrDiscard(ctx)
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var innerErr error
			err := c.Control(func(fd uintptr) {
				innerErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			})
			return errors.Join(err, innerErr)
		},
	}
	l, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("failed to create TPROXY TCP listener: %w", err)
	}
	if *port == 0 {
		*port = uint16(l.Addr().(*net.TCPAddr).Port)
	}
	logger.V(1).Info("TPROXY TCP listener started", "port", *port)
	close(ready)
	c := make(chan error, 1)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					c <- nil
					return
				}
				c <- err
				return
			}
			laddr := conn.LocalAddr().(*net.TCPAddr).AddrPort()
			raddr := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
			go handler.Handle(ctx, conn, network.NetworkTCP, unmapAddrPort(laddr), unmapAddrPort(raddr))
		}
	}()
	select {
	case <-ctx.Done():
		_ = l.Close()
		logger.V(1).Info("TPROXY TCP listener stopped")
		return <-c
	case err := <-c:
		_ = l.Close()
		return err
	}
}

func handleIncomingUDP(
	ctx context.Context,
	handler network.Handler,
	port *uint16,
	ready chan<- struct{},
) error {
	logger := logr.FromContextOrDiscard(ctx)
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var innerErr error
			err := c.Control(func(fd uintptr) {
				innerErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, unix.IP_TRANSPARENT, 1)
				if innerErr == nil {
					innerErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1)
				}
				if innerErr == nil {
					innerErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
				}
			})
			return errors.Join(err, innerErr)
		},
	}
	_conn, err := lc.ListenPacket(ctx, "udp", fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("failed to create TPROXY UDP listener: %w", err)
	}
	conn := _conn.(*net.UDPConn)
	if *port == 0 {
		*port = uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	}
	logger.V(1).Info("TPROXY UDP listener started", "port", *port)
	close(ready)
	c := make(chan error, 1)
	// TODO: use connection tracking to persist the connection
	go func() {
		b := make([]byte, 1024)
		oob := make([]byte, 1024)
		for {
			n, oobn, _, addr, err := conn.ReadMsgUDPAddrPort(b, oob)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					c <- nil
					return
				}
				c <- err
				return
			}
			controlMessages, err := unix.ParseSocketControlMessage(oob[:oobn])
			if err != nil {
				logger.Error(err, "failed to parse socket control message")
				continue
			}
			var dstAddr unix.Sockaddr
			for _, controlMessage := range controlMessages {
				if origDstAddr, err := unix.ParseOrigDstAddr(&controlMessage); err == nil {
					logger.V(1).Info("original destination address found", "origDstAddr", origDstAddr)
					dstAddr = origDstAddr
				}
			}
			if dstAddr == nil {
				logger.Info("no original destination address found", "addr", addr, "n", n, "oobn", oobn, "controlMessages", controlMessages)
				continue
			}
			var laddr netip.AddrPort
			switch v := dstAddr.(type) {
			case *unix.SockaddrInet4:
				laddr = netip.AddrPortFrom(netip.AddrFrom4(v.Addr), uint16(v.Port))
			case *unix.SockaddrInet6:
				laddr = netip.AddrPortFrom(netip.AddrFrom16(v.Addr), uint16(v.Port))
			}
			// TODO: use a buffered connection
			go handler.Handle(ctx, conn, network.NetworkUDP, unmapAddrPort(laddr), unmapAddrPort(addr))
		}
	}()
	select {
	case <-ctx.Done():
		_ = conn.Close()
		logger.V(1).Info("TPROXY UDP listener stopped")
		return <-c
	case err := <-c:
		_ = conn.Close()
		return err
	}
}
