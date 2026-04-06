package tproxy

import (
	"errors"
	"net"
	"net/netip"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
)

type routeOptions struct {
	Mark     uint32
	Priority int
	Table    int
}

func routeRule(options *routeOptions, family int) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Priority = options.Priority
	rule.Table = options.Table
	rule.Mark = options.Mark
	rule.Family = family
	return rule
}

func routeRoute(options *routeOptions, family int) (*netlink.Route, error) {
	link, err := netlink.LinkByName("lo")
	if err != nil {
		return nil, err
	}
	var dst *net.IPNet
	if family == unix.AF_INET {
		dst = &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		}
	} else {
		dst = &net.IPNet{
			IP:   net.IPv6zero,
			Mask: net.CIDRMask(0, 128),
		}
	}
	return &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Table:     options.Table,
		Family:    family,
		Dst:       dst,
		Type:      unix.RTN_LOCAL,
		Scope:     netlink.SCOPE_HOST,
	}, nil
}

func setupRoute(options *routeOptions, family int) error {
	rule := routeRule(options, family)
	if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	route, err := routeRoute(options, family)
	if err != nil {
		return err
	}
	if err := netlink.RouteAppend(route); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	return nil
}

func cleanupRoute(options *routeOptions, family int) error {
	rule := routeRule(options, family)
	if err := netlink.RuleDel(rule); err != nil && !errors.Is(err, syscall.ENOENT) {
		return err
	}
	route, err := routeRoute(options, family)
	if err != nil {
		return err
	}
	if err := netlink.RouteDel(route); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

type nfTableOptions struct {
	Name       string
	TProxyMark uint32
	TProxyPort uint16
	RouteIPSet *netipx.IPSet
}

func nftablesIfname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}

func nftablesCreateIPSet(
	set *netipx.IPSet,
	family nftables.TableFamily,
) []nftables.SetElement {
	ranges := set.Ranges()
	elements := make([]nftables.SetElement, 0, len(ranges)*2)
	for _, r := range ranges {
		if (family == nftables.TableFamilyIPv4) != r.From().Is4() {
			continue
		}
		endAddr := r.To().Next()
		if !endAddr.IsValid() {
			if family == nftables.TableFamilyIPv4 {
				endAddr = netip.IPv4Unspecified()
			} else {
				endAddr = netip.IPv6Unspecified()
			}
		}
		elements = append(elements, nftables.SetElement{Key: r.From().AsSlice()})
		elements = append(elements, nftables.SetElement{Key: endAddr.AsSlice(), IntervalEnd: true})
	}
	return elements
}

func setupNfTableOutputChain(
	nft *nftables.Conn,
	table *nftables.Table,
	options *nfTableOptions,
	interceptedIPv4Addrs *nftables.Set,
	interceptedIPv6Addrs *nftables.Set,
) error {
	chain := nft.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeRoute,
	})
	ipProto := &nftables.Set{
		Table:     table,
		Anonymous: true,
		Constant:  true,
		KeyType:   nftables.TypeInetProto,
	}
	if err := nft.AddSet(ipProto, []nftables.SetElement{
		{Key: []byte{unix.IPPROTO_TCP}},
		{Key: []byte{unix.IPPROTO_UDP}},
	}); err != nil {
		return err
	}
	// meta l4proto != { tcp, udp } return
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ lookup reg 1 set __set%d ]
			&expr.Lookup{SourceRegister: 1, SetID: ipProto.ID, SetName: ipProto.Name, Invert: true},
			// [ immediate reg 0 return ]
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})
	// oifname "lo" return
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load oifname => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			// [ cmp eq reg 1 "lo" ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nftablesIfname("lo")},
			// [ immediate reg 0 return ]
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})
	// meta mark 0x00001996 return
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load mark => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			// [ cmp neq reg 1 $TPROXY_MARK ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(options.TProxyMark)},
			// [ immediate reg 0 return ]
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})
	// socket transparent 1 return
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ socket load transparent => reg 1 ]
			&expr.Socket{Key: expr.SocketKeyTransparent, Register: 1},
			// [ cmp eq reg 1 0x00000000 ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
			// [ immediate reg 0 return ]
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})
	// ip daddr @intercepted_ipv4_addrs counter packets 0 bytes 0 meta mark set 0x00001996 accept
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load nfproto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			// [ cmp eq reg 1 0x00000002 ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(unix.NFPROTO_IPV4)}},
			// [ payload load 4b @ network header + 16 => reg 1 ]
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4, DestRegister: 1},
			// [ lookup reg 1 set intercepted_addrs ]
			&expr.Lookup{SourceRegister: 1, SetID: interceptedIPv4Addrs.ID, SetName: interceptedIPv4Addrs.Name},
			// [ counter pkts 0 bytes 0 ]
			&expr.Counter{},
			// [ immediate reg 1 0x00001996 ]
			&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(options.TProxyMark)},
			// [ meta set mark with reg 1 ]
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
			// [ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	// ip6 daddr @intercepted_ipv6_addrs counter packets 0 bytes 0 meta mark set 0x00001996 accept
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load nfproto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			// [ cmp eq reg 1 0x0000000a ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(unix.NFPROTO_IPV6)}},
			// [ payload load 16b @ network header + 24 => reg 1 ]
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16, DestRegister: 1},
			// [ lookup reg 1 set intercepted_ipv6_addrs ]
			&expr.Lookup{SourceRegister: 1, SetID: interceptedIPv6Addrs.ID, SetName: interceptedIPv6Addrs.Name},
			// [ counter pkts 0 bytes 0 ]
			&expr.Counter{},
			// [ immediate reg 1 0x00001996 ]
			&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(options.TProxyMark)},
			// [ meta set mark with reg 1 ]
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
			// [ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	return nil
}

func setupNfTablePreRoutingChain(
	nft *nftables.Conn,
	table *nftables.Table,
	options *nfTableOptions,
	interceptedIPv4Addrs *nftables.Set,
	interceptedIPv6Addrs *nftables.Set,
) error {
	chain := nft.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeFilter,
	})
	ipProto := &nftables.Set{
		Table:     table,
		Anonymous: true,
		Constant:  true,
		KeyType:   nftables.TypeInetProto,
	}
	if err := nft.AddSet(ipProto, []nftables.SetElement{
		{Key: []byte{unix.IPPROTO_TCP}},
		{Key: []byte{unix.IPPROTO_UDP}},
	}); err != nil {
		return err
	}
	// meta l4proto != { tcp, udp } return
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ lookup reg 1 set __set%d ]
			&expr.Lookup{SourceRegister: 1, SetID: ipProto.ID, SetName: ipProto.Name, Invert: true},
			// [ immediate reg 0 return ]
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})
	// ip daddr @intercepted_ipv4_addrs counter packets 0 bytes 0 tproxy to :20333 meta mark set 0x00001996 accept
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ socket load transparent => reg 1 ]
			&expr.Socket{Key: expr.SocketKeyTransparent, Register: 1},
			// [ cmp eq reg 1 0x00000001 ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
			// [ socket load wildcard => reg 1 ]
			&expr.Socket{Key: expr.SocketKeyWildcard, Register: 1},
			// [ cmp eq reg 1 0x00000000 ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
			// [ counter pkts 0 bytes 0 ]
			&expr.Counter{},
			// [ immediate reg 1 $TPROXY_MARK ]
			&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(options.TProxyMark)},
			// [ meta set mark with reg 1 ]
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
			// [ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	// ip6 daddr @intercepted_ipv6_addrs counter packets 0 bytes 0 tproxy to :20333 meta mark set 0x00001996 accept
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load nfproto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			// [ cmp eq reg 1 0x00000002 ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(unix.NFPROTO_IPV4)}},
			// [ payload load 4b @ network header + 16 => reg 1 ]
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4, DestRegister: 1},
			// [ lookup reg 1 set route_ips ]
			&expr.Lookup{SourceRegister: 1, SetID: interceptedIPv4Addrs.ID, SetName: interceptedIPv4Addrs.Name},
			// [ counter pkts 0 bytes 0 ]
			&expr.Counter{},
			// [ immediate reg 1 $TPROXY_PORT ]
			&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(options.TProxyPort)},
			// [ tproxy ip port reg 1 ]
			&expr.TProxy{RegPort: 1},
			// [ immediate reg 1 $TPROXY_MARK ]
			&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(options.TProxyMark)},
			// [ meta set mark with reg 1 ]
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
			// [ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load nfproto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			// [ cmp eq reg 1 0x0000000a ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(unix.NFPROTO_IPV6)}},
			// [ payload load 16b @ network header + 24 => reg 1 ]
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16, DestRegister: 1},
			// [ lookup reg 1 set intercepted_ipv6_addrs ]
			&expr.Lookup{SourceRegister: 1, SetID: interceptedIPv6Addrs.ID, SetName: interceptedIPv6Addrs.Name},
			// [ counter pkts 0 bytes 0 ]
			&expr.Counter{},
			// [ immediate reg 1 $TPROXY_PORT ]
			&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(options.TProxyPort)},
			// [ tproxy ip port reg 1 ]
			&expr.TProxy{RegPort: 1},
			// [ immediate reg 1 $TPROXY_MARK ]
			&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(options.TProxyMark)},
			// [ meta set mark with reg 1 ]
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
			// [ immediate reg 0 accept ]
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	return nil
}

func setupNFTable(options *nfTableOptions) error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	table := &nftables.Table{
		Name:   options.Name,
		Family: nftables.TableFamilyINet,
	}
	nft.AddTable(table)
	interceptedIPv4Addrs := &nftables.Set{
		Table:    table,
		Name:     "intercepted_ipv4_addrs",
		Interval: true,
		KeyType:  nftables.TypeIPAddr,
	}
	if err := nft.AddSet(interceptedIPv4Addrs, nftablesCreateIPSet(options.RouteIPSet, nftables.TableFamilyIPv4)); err != nil {
		return err
	}
	interceptedIPv6Addrs := &nftables.Set{
		Table:    table,
		Name:     "intercepted_ipv6_addrs",
		Interval: true,
		KeyType:  nftables.TypeIP6Addr,
	}
	if err := nft.AddSet(interceptedIPv6Addrs, nftablesCreateIPSet(options.RouteIPSet, nftables.TableFamilyIPv6)); err != nil {
		return err
	}
	if err := setupNfTableOutputChain(nft, table, options, interceptedIPv4Addrs, interceptedIPv6Addrs); err != nil {
		return err
	}
	if err := setupNfTablePreRoutingChain(nft, table, options, interceptedIPv4Addrs, interceptedIPv6Addrs); err != nil {
		return err
	}
	return nft.Flush()
}

func cleanupNFTable(name string) error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	nft.DelTable(&nftables.Table{
		Name:   name,
		Family: nftables.TableFamilyINet,
	})
	err = nft.Flush()
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		return err
	}
	return nil
}
