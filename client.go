package main

import (
	"bytes"
	"context"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	pb "github.com/tibordp/ndp/proto"
	"google.golang.org/grpc"

	klog "k8s.io/klog/v2"
)

type client struct {
	wg                     *wgctrl.Client
	conn                   *grpc.ClientConn
	link                   netlink.Link
	privateKey             wgtypes.Key
	address                string
	lastResponse           *pb.RegisterResponse
	lastSuccessfulResponse *time.Time
	closed                 chan struct{}
}

func makeDefaultRoute() *net.IPNet {
	_, defaultRoute, _ := net.ParseCIDR("2000::/3")
	return defaultRoute
}

func (c *client) reconcileAddresses() error {
	existingAddresses, err := netlink.AddrList(c.link, nl.FAMILY_V6)
	if err != nil {
		return err
	}

	redundant := make(map[string]netlink.Addr)
	for _, addr := range existingAddresses {
		redundant[addr.IPNet.String()] = addr
	}

	missing := make([]netlink.Addr, 0)
	if c.lastResponse != nil {
		ipNet := netlink.NewIPNet(c.lastResponse.IpAddress)
		if _, ok := redundant[ipNet.String()]; ok {
			delete(redundant, ipNet.String())
		} else {
			missing = append(missing, netlink.Addr{
				IPNet: ipNet,
			})
		}
	}

	for _, v := range missing {
		klog.Infof("adding address %v", v)
		if err := netlink.AddrAdd(c.link, &v); err != nil {
			return err
		}
	}

	for _, v := range redundant {
		klog.Infof("removing address %v", v)
		if netlink.AddrDel(c.link, &v); err != nil {
			return err
		}
	}

	return nil
}

func (c *client) reconcileRoutes() error {
	existingRoutes, err := netlink.RouteListFiltered(nl.FAMILY_V6, &netlink.Route{LinkIndex: c.link.Attrs().Index}, netlink.RT_FILTER_OIF)
	if err != nil {
		return err
	}

	var defaultRoute *netlink.Route = nil
	for _, route := range existingRoutes {
		actualDefaultRoute := makeDefaultRoute()
		if route.Dst != nil && route.Dst.IP.Equal(actualDefaultRoute.IP) && bytes.Equal(route.Dst.Mask, actualDefaultRoute.Mask) {
			defaultRoute = &route
		}
	}

	if c.lastResponse != nil && defaultRoute == nil {
		klog.Infof("adding default route")

		r := netlink.Route{
			Dst:       makeDefaultRoute(),
			LinkIndex: c.link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
		}
		if netlink.RouteAdd(&r); err != nil {
			return err
		}
	} else if c.lastResponse == nil && defaultRoute != nil {
		klog.Infof("removing default route")
		if netlink.RouteDel(defaultRoute); err != nil {
			return err
		}
	}

	return nil
}

func (c *client) applySettings() error {
	if err := c.reconcileAddresses(); err != nil {
		return err
	}
	if err := c.reconcileRoutes(); err != nil {
		return err
	}

	serverEndpoint, err := net.ResolveUDPAddr("udp", c.address)
	if err != nil {
		return err
	}

	peers := make([]wgtypes.PeerConfig, 0)
	if c.lastResponse != nil {
		key, _ := wgtypes.NewKey(c.lastResponse.PublicKey)
		peers = append(peers, wgtypes.PeerConfig{
			PublicKey: key,
			AllowedIPs: []net.IPNet{
				*makeDefaultRoute(),
			},
			Endpoint: serverEndpoint,
		})
	}

	if err := c.wg.ConfigureDevice(c.link.Attrs().Name, wgtypes.Config{
		PrivateKey:   &c.privateKey,
		ReplacePeers: true,
		Peers:        peers,
	}); err != nil {
		return err
	}

	return nil
}

func newClient(address string, wg *wgctrl.Client, wgLink netlink.Link, privateKey wgtypes.Key) (*client, error) {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	cl := client{
		wg:         wg,
		link:       wgLink,
		address:    address,
		conn:       conn,
		privateKey: privateKey,
		closed:     make(chan struct{}),
	}

	return &cl, nil
}

func (c *client) Close() {
	c.closed <- struct{}{}
	c.conn.Close()
}

func (c *client) poll() {
	client := pb.NewNdpClient(c.conn)

	now := time.Now()
	publicKey := c.privateKey.PublicKey()
	response, err := client.Register(context.Background(), &pb.RegisterRequest{
		PublicKey: publicKey[:],
	})

	if err != nil {
		klog.Warningf("error while calling Register: %v", err)
		if c.lastSuccessfulResponse != nil && now.Sub(*c.lastSuccessfulResponse) > 30*time.Second {
			c.lastResponse = nil
		}
	} else {
		c.lastSuccessfulResponse = &now
		c.lastResponse = response
	}

	if err := c.applySettings(); err != nil {
		klog.Warningf("failed to sync settings: %v", err)
	}
}

func (c *client) Run() {
	c.poll()

outer:
	for {
		select {
		case <-c.closed:
			break outer
		case <-time.After(15 * time.Second):
			c.poll()
		}
	}

	klog.Info("finished")
}
