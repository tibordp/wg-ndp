# "How to get IPv6 connectivity in WSL2?"

This is a bad and overengineered hack to get IPv6 connectivity in WSL2 using another Linux device on the home network (e.g. a Raspberry Pi).

`wg-ndp` consists of two parts, a client and a server. Server is meant to run on the Raspberry Pi and the client runs inside WSL2. Server advertises an additional IPv6 address using NDP and routes all the traffic for that IP to the client via an automatically managed Wireguard tunnel.

## How it works

1. Client generates a Wireguard private key and a public key.
2. Client calls the `Register` gRPC method with the public key
3. Server generates an IPv6 address using the upstream interface's network prefix and the client's public key.
4. Server starts advertises the IPv6 address using NDP and sets up a Wireguard interface routing all traffic for that address to the client.
5. Client sets up the Wireguard interface based on the parameters of the response and sets up the Wireguard tunnel and default route.
6. Client regularly heartbeats, if the server is no longer there, the IP address and default route are removed.

NB, the server can actually run anywhere, doesn't have to be a local network, as `ndp` sets up a bona fide VPN which doesn't actually care where the server is.

## Installation

Have a Go toolchain installed

```bash
go install github.com/tibordp/wg-ndp@latest 
sudo cp $(go env GOPATH)/bin/wg-ndp /usr/local/bin/
```

WSL2 does not run systemd, so in order for the client to always be running, it can be daemonized with something like [god](https://github.com/fiorix/go-daemon).

Put this into your favorite shell's rc file:

```bash 
if [ ! -f /var/run/wg-ndp.pid ]; then
  sudo god \
        --pidfile /var/run/wg-ndp.pid \
        --nohup \
        --logfile /var/log/wg-ndp.log -- \
        /usr/local/bin/wg-ndp -client -server <raspberry pi ipv4 url>:24601
fi
```

On the Raspberry Pi, simply use the provided systemd unit file

```bash
sudo cp ./wg-ndp.service /etc/systemd/system/
sudo systemctl enable wg-ndp
```

The default unit file assumes that your upstream interface is called `eth0`. If that is not so, change the line in it

```diff
< ExecStart=/usr/local/bin/wg-ndp
> ExecStart=/usr/local/bin/wg-ndp --interface <whatever>
```

