# pingtun #
**pingtun** is a new implementation of ICMP tunnel which aims for usability and simplicity.

In short, it tunnels ipv4 traffic over icmp echo requests and replies (pings).
Thus, bypassing badly configured firewalls and captive portals.

**pingtun** focus is real-world use, not POC. It tries to implement only features which make it easy to set up, maintain and use.
It intentionally does not implement features which are better taken care of by other tools, such as authentication and encryption.

##### Some of pingtun's distinguished features: ####
* no need to configure iptables/proc/tun/anything
* peer-to-peer and client-server mode
* periodic echo requests (bypass firewalls which prevent unsolicited replies)
* echo request timer adjustments according to congestion
* reply to non-tunneling pings
* DNS resolution
* single-threaded event driven architecture
* user-space zero copy

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
sudo pingtun --client-only --server $SERVER 10.9.0.1 255.255.255.252
```

## Platforms ##
* GNU/Linux
* [FUTURE] android
* [FUTURE] mac (client only)

