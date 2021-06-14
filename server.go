package main

import (
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	klog "k8s.io/klog/v2"
)

const (
	listenPort int = 24601
)

type peer struct {
	ip            net.IP
	publicKey     wgtypes.Key
	lastHeartbeat time.Time
}

type server struct {
	ndp        *ndpResponder
	wg         *wgctrl.Client
	netPrefix  net.IP
	link       *netlink.Link
	privateKey wgtypes.Key
	peers      []peer
	mu         sync.Mutex
	closed     chan struct{}
}

func newServer(upstream *net.Interface, wg wgctrl.Client, wgLink *netlink.Link, privateKey wgtypes.Key) (*server, error) {
	netPrefix, err := getInterfacePrefix(upstream)
	if err != nil {
		return nil, fmt.Errorf("could not determine prefix: %w", err)
	}

	server := server{
		wg:         &wg,
		privateKey: privateKey,
		link:       wgLink,
		netPrefix:  netPrefix,
		peers:      make([]peer, 0),
		mu:         sync.Mutex{},
	}

	ndpResponder, err := newNDPResponder(upstream, server.shouldAdvertise)
	if err != nil {
		return nil, fmt.Errorf("could not start responder: %w", err)
	}
	server.ndp = ndpResponder
	go server.Heartbeat()

	return &server, nil
}

func (c *server) Heartbeat() {
outer:
	for {
		select {
		case <-c.closed:
			break outer
		case <-time.After(15 * time.Second):
			currentTime := time.Now()
			c.mutatePeers(func() error {
				i := 0
				for _, peer := range c.peers {
					if currentTime.Sub(peer.lastHeartbeat) < 30*time.Second {
						c.peers[i] = peer
						i++
					} else {
						klog.Info("removing stale peer: %v", peer)
					}
				}
				c.peers = c.peers[:i]
				return nil
			})
		}
	}
}

func (c *server) Close() {
	c.closed <- struct{}{}
	c.ndp.Close()
}

func (c *server) shouldAdvertise(i net.IP) dropReason {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, peer := range c.peers {
		if peer.ip.Equal(i) {
			return dropReasonNone
		}
	}

	return dropReasonAnnounceIP
}

func (c *server) reconcileRoutes() error {
	// Find all directly attached routes to the wireguard interface
	existingRoutes, err := netlink.RouteListFiltered(nl.FAMILY_V6, &netlink.Route{LinkIndex: (*c.link).Attrs().Index}, netlink.RT_FILTER_OIF)
	if err != nil {
		return err
	}

	redundant := make(map[string]netlink.Route)
	for _, route := range existingRoutes {
		redundant[route.Dst.String()] = route
	}

	missing := make([]netlink.Route, 0)
	for _, peer := range c.peers {
		cidr := netlink.NewIPNet(peer.ip)
		if _, ok := redundant[cidr.String()]; ok {
			delete(redundant, cidr.String())
		} else {
			cidr := cidr
			missing = append(missing, netlink.Route{
				Dst:       cidr,
				LinkIndex: (*c.link).Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
			})
		}
	}

	for _, v := range missing {
		klog.Infof("adding route %v", v)
		if err := netlink.RouteAdd(&v); err != nil {
			return err
		}
	}

	for _, v := range redundant {
		klog.Infof("removing route %v", v)
		if netlink.RouteDel(&v); err != nil {
			return err
		}
	}

	return nil
}

func (c *server) applyPeerConfiguration() error {
	peerConfigs := make([]wgtypes.PeerConfig, len(c.peers))
	for i, v := range c.peers {
		peerConfigs[i].AllowedIPs = []net.IPNet{
			*netlink.NewIPNet(v.ip),
		}
		peerConfigs[i].PublicKey = v.publicKey
	}

	listenPort := listenPort
	if err := c.wg.ConfigureDevice((*c.link).Attrs().Name, wgtypes.Config{
		PrivateKey:   &c.privateKey,
		ListenPort:   &listenPort,
		ReplacePeers: true,
		Peers:        peerConfigs,
	}); err != nil {
		return err
	}

	return nil
}

func (c *server) mutatePeers(f func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldPeers := make([]peer, len(c.peers))
	copy(oldPeers, c.peers)

	if err := f(); err != nil {
		return err
	}

	if reflect.DeepEqual(oldPeers, c.peers) {
		return nil
	}

	for _, peer := range c.peers {
		c.ndp.Watch(peer.ip)
	}
	for _, peer := range oldPeers {
		c.ndp.Unwatch(peer.ip)
	}

	c.applyPeerConfiguration()
	c.reconcileRoutes()

	return nil
}

func getInterfacePrefix(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPNet:
			ones, bits := v.Mask.Size()
			if ones == 64 && bits == 128 && v.IP.IsGlobalUnicast() {
				return v.IP, nil
			}
		default:
			continue
		}

	}

	return nil, fmt.Errorf("could not find a suitable ip address")
}
