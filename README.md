# pingtun #
**pingtun** is a well-written, well-structured icmp tunnel.

In short, it tunnels ipv4 traffic over icmp echo requests and replies (pings).
Thus, bypassing badly configured firewalls and captive portals.

##### Some of pingtun's distinguished features: ####
* no need to configure iptables/proc/tun/anything
* peer-to-peer and client-server mode
* periodic echo requests (bypass firewalls which prevent unsolicited replies)
* single-threaded event driven architecture
* user-space zero copy
* echo request timer adjustments according to congestion
* reply to non-tunneling pings
* DNS resolution
* [FUTURE] strong authentication
* [FUTURE] MTU discovery

## Dependencies ##
* libevent2
* tun driver
* linux socket filter


## Build ##
```
cmake .
make
sudo make install
```

## Run ##
on the server:
```
sudo pingtun 10.9.0.1 255.255.255.252
```
on the client:
```
sudo pingtun --client-only --server $SERVER_IP 10.9.0.1 255.255.255.252
```

## Platforms ##
* GNU/Linux
* [FUTURE] android

