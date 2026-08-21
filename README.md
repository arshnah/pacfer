# pacfer

Live network traffic sniffer with a full-screen live dashboard. Linux only
(uses raw `AF_PACKET` sockets, no libpcap dependency).

## Disclaimer

Only sees traffic your own machine sends/receives. Promiscuous mode does
not make a normal home network show other devices' traffic; a switch only
forwards frames addressed to you. Real whole-network visibility needs this
running on the router/gateway itself or a switch with port-mirroring.

SNI/Host/DNS sniffing only reveals which hostname a connection is talking
to. It does not decrypt HTTPS content.

## Build

```
zig build
```

## Run

Raw sockets need `CAP_NET_RAW`. Interface binding + promiscuous mode also
need `CAP_NET_ADMIN`:

```
sudo setcap cap_net_raw,cap_net_admin+ep ./zig-out/bin/pacfer
```

```
./zig-out/bin/pacfer --help
./zig-out/bin/pacfer wlan0 --dashboard
./zig-out/bin/pacfer wlan0 --domains-only
./zig-out/bin/pacfer wlan0 --pcap capture.pcap
```

Or run under `sudo` directly instead of `setcap`.
