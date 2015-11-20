pingtun - The *Best* ICMP tunnel
==================================

## Build ##
```
cmake . && make
```

## Run  ##

on the server:
```
sudo pingtun 10.9.0.1 255.255.255.252
```
on the client:
```
sudo pingtun --server $SERVER_IP 10.9.0.1 255.255.255.252
```

## Platforms ##
* GNU/Linux

## TODO ##

* make it work
* add magic & BPF
* reply to normal pings
* code documentation
* tests (valgrind? utests?)
* android
* MTU discovery
* parse dns
* timer adjustments
* real authentication
* increase speed using rx/tx rings and zero-copy (will it improve anything at all? what's my bottleneck?)
