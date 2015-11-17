pingtun - The *Best* ICMP tunnel
==================================

** Build **
```
mkdir build
cd build
cmake ..
make
```

** Run  **

on the server:
```
sudo pingtun 10.9.0.1 255.255.255.252
```
on the client:
```
sudo pingtun --server $SERVER_IP 10.9.0.1 255.255.255.252
```

** Platforms **
* GNU/Linux

** TODO **

* make it work
* code documentation
* tests (valgrind? utests?)
* reply to normal pings
* android
* add magic & BPF
* MTU discovery
* parse dns
* timer adjustments
* real authentication
* increase speed using rx/tx rings and zero-copy
