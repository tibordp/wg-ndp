package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"os/signal"
	"syscall"
	"time"

	sysctl "github.com/lorenzosaino/go-sysctl"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	pb "github.com/tibordp/ndp/proto"
	"google.golang.org/grpc"

	klog "k8s.io/klog/v2"
)

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/ndp.proto

type listener struct {
	pb.UnimplementedNdpServer
	serv *server
}

func (l *listener) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	ip := make(net.IP, 16)
	copy(ip, l.serv.netPrefix[:8])
	copy(ip[8:], req.PublicKey[:8])

	err := l.serv.mutatePeers(func() error {
		for i, _ := range l.serv.peers {
			if bytes.Equal(l.serv.peers[i].publicKey[:], req.PublicKey) {
				l.serv.peers[i].ip = ip
				l.serv.peers[i].lastHeartbeat = time.Now()
				return nil
			}
		}

		key, err := wgtypes.NewKey(req.PublicKey)
		if err != nil {
			return err
		}

		klog.Infof("creating new peer %v", key.String())
		l.serv.peers = append(l.serv.peers, peer{
			ip:            ip,
			publicKey:     key,
			lastHeartbeat: time.Now(),
		})

		return nil
	})
	if err != nil {
		return nil, err
	}

	pubKey := l.serv.privateKey.PublicKey()
	return &pb.RegisterResponse{
		PublicKey: pubKey[:],
		IpAddress: ip,
	}, nil
}

func runServer(ctx context.Context, ifaceName string, target string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("could not get interface: %w", err)
	}

	link, err := ensureWgLink(target)
	if err != nil {
		return fmt.Errorf("could not create wireguard link: %w", err)
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("could not create wireguard client: %w", err)
	}

	privateKey, _ := wgtypes.GeneratePrivateKey()
	server, err := newServer(iface, *client, link, privateKey)
	if err != nil {
		return fmt.Errorf("could not create server: %w", err)
	}
	defer server.Close()

	lis, err := net.Listen("tcp", ":24601")
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	s := grpc.NewServer()
	pb.RegisterNdpServer(s, &listener{
		serv: server,
	})

	go func() {
		<-ctx.Done()
		s.GracefulStop()
	}()

	klog.Infof("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		return err
	}

	return nil
}

func runClient(ctx context.Context, server string, target string) error {
	link, err := ensureWgLink(target)
	if err != nil {
		return fmt.Errorf("could not start responder: %w", err)
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("could not create wireguard client: %w", err)
	}

	privateKey, _ := wgtypes.GeneratePrivateKey()
	cl, err := newClient(server, client, *link, privateKey)
	if err != nil {
		return fmt.Errorf("could not create client: %w", err)
	}

	go func() {
		<-ctx.Done()
		cl.Close()
	}()

	cl.Run(ctx)

	return nil
}

func main() {
	clientFlag := flag.Bool("client", false, "run as a client")
	serverAddress := flag.String("server", "", "server address")
	ifaceFlag := flag.String("interface", "eth0", "interface to bind on")
	targetFlag := flag.String("target", "wg0", "wireguard interface")

	klog.InitFlags(nil)
	flag.Parse()

	err := sysctl.Set("net.ipv6.conf.all.forwarding", "1")
	if err != nil {
		klog.Fatalf("could set ipv6 forwarding %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *clientFlag {
		if err := runClient(ctx, *serverAddress, *targetFlag); err != nil {
			klog.Fatal(err)
		}
	} else {
		if err := runServer(ctx, *ifaceFlag, *targetFlag); err != nil {
			klog.Fatal(err)
		}
	}

	klog.Infof("finished")
}
