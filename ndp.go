package main

import (
	"fmt"
	"io"
	"net"

	"github.com/mdlayher/ndp"

	klog "k8s.io/klog/v2"
)

type announceFunc func(net.IP) dropReason

type dropReason int

// Various reasons why a packet was dropped.
const (
	dropReasonNone dropReason = iota
	dropReasonClosed
	dropReasonError
	dropReasonARPReply
	dropReasonMessageType
	dropReasonNoSourceLL
	dropReasonEthernetDestination
	dropReasonAnnounceIP
)

type ndpResponder struct {
	intf         string
	hardwareAddr net.HardwareAddr
	conn         *ndp.Conn
	closed       chan struct{}
	announce     announceFunc
	// Refcount of how many watchers for each solicited node
	// multicast group.
	solicitedNodeGroups map[string]int64
}

func newNDPResponder(ifi *net.Interface, ann announceFunc) (*ndpResponder, error) {
	// Use link-local address as the source IPv6 address for NDP communications.
	conn, _, err := ndp.Dial(ifi, ndp.LinkLocal)
	if err != nil {
		return nil, fmt.Errorf("creating NDP responder for %q: %s", ifi.Name, err)
	}

	ret := &ndpResponder{
		intf:                ifi.Name,
		hardwareAddr:        ifi.HardwareAddr,
		conn:                conn,
		closed:              make(chan struct{}),
		announce:            ann,
		solicitedNodeGroups: map[string]int64{},
	}
	go ret.run()
	return ret, nil
}

func (n *ndpResponder) Interface() string { return n.intf }

func (n *ndpResponder) Close() error {
	close(n.closed)
	return n.conn.Close()
}

func (n *ndpResponder) Gratuitous(ip net.IP) error {
	err := n.advertise(net.IPv6linklocalallnodes, ip, true)
	return err
}

func (n *ndpResponder) Watch(ip net.IP) error {
	if ip.To4() != nil {
		return nil
	}
	group, err := ndp.SolicitedNodeMulticast(ip)
	if err != nil {
		return fmt.Errorf("looking up solicited node multicast group for %q: %s", ip, err)
	}
	if n.solicitedNodeGroups[group.String()] == 0 {
		if err = n.conn.JoinGroup(group); err != nil {
			return fmt.Errorf("joining solicited node multicast group for %q: %s", ip, err)
		}
	}
	n.solicitedNodeGroups[group.String()]++
	return nil
}

func (n *ndpResponder) Unwatch(ip net.IP) error {
	if ip.To4() != nil {
		return nil
	}
	group, err := ndp.SolicitedNodeMulticast(ip)
	if err != nil {
		return fmt.Errorf("looking up solicited node multicast group for %q: %s", ip, err)
	}
	n.solicitedNodeGroups[group.String()]--
	if n.solicitedNodeGroups[group.String()] == 0 {
		if err = n.conn.LeaveGroup(group); err != nil {
			return fmt.Errorf("leaving solicited node multicast group for %q: %s", ip, err)
		}
	}
	return nil
}

func (n *ndpResponder) run() {
	for n.processRequest() != dropReasonClosed {
	}
}

func (n *ndpResponder) processRequest() dropReason {
	msg, _, src, err := n.conn.ReadFrom()
	if err != nil {
		select {
		case <-n.closed:
			return dropReasonClosed
		default:
		}
		if err == io.EOF {
			return dropReasonClosed
		}
		return dropReasonError
	}

	ns, ok := msg.(*ndp.NeighborSolicitation)
	if !ok {
		return dropReasonMessageType
	}

	// Retrieve sender's source link-layer address
	var nsLLAddr net.HardwareAddr
	for _, o := range ns.Options {
		// Ignore other options, including target link-layer address instead of source.
		lla, ok := o.(*ndp.LinkLayerAddress)
		if !ok {
			continue
		}
		if lla.Direction != ndp.Source {
			continue
		}

		nsLLAddr = lla.Addr
		break
	}
	if nsLLAddr == nil {
		return dropReasonNoSourceLL
	}

	// Ignore NDP requests that the announcer tells us to ignore.
	if reason := n.announce(ns.TargetAddress); reason != dropReasonNone {
		return reason
	}

	klog.InfoS("got NDP request for service IP, sending response", "interface", n.intf, "ip", ns.TargetAddress, "senderIP", src, "senderLLAddr", nsLLAddr, "responseMAC", n.hardwareAddr)
	if err := n.advertise(src, ns.TargetAddress, false); err != nil {
		klog.ErrorS(err, "failed to send NDP reply", "op", "arpReply", "interface", n.intf, "ip", ns.TargetAddress, "senderIP", src, "senderLLAddr", nsLLAddr, "responseMAC", n.hardwareAddr)
	}

	return dropReasonNone
}

func (n *ndpResponder) advertise(dst, target net.IP, gratuitous bool) error {
	m := &ndp.NeighborAdvertisement{
		Solicited:     !gratuitous, // <Adam Jensen> I never asked for this...
		Override:      gratuitous,  // Should clients replace existing cache entries
		TargetAddress: target,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Target,
				Addr:      n.hardwareAddr,
			},
		},
	}
	return n.conn.WriteTo(m, nil, dst)
}
