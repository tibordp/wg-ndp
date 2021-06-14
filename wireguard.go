package main

import (
	"fmt"

	"github.com/vishvananda/netlink"

	klog "k8s.io/klog/v2"
)

type wireguardLink struct {
	netlink.LinkAttrs
}

func (wg *wireguardLink) Attrs() *netlink.LinkAttrs {
	return &wg.LinkAttrs
}

func (wg *wireguardLink) Type() string {
	return "wireguard"
}

func ensureWgLink(name string) (*netlink.Link, error) {
	link, err := netlink.LinkByName(name)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		klog.Infof("device %q does not exist, creating it", name)
		newLink := wireguardLink{LinkAttrs: netlink.LinkAttrs{Name: name}}
		if err := netlink.LinkAdd(&newLink); err != nil {
			return nil, err
		}
		link, _ = netlink.LinkByName(name)
	} else if err != nil {
		return nil, err
	} else if link.Type() != "wireguard" {
		return nil, fmt.Errorf("interface %q is not of wireguard type", name)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, err
	}

	return &link, nil
}
