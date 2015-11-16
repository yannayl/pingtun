pingtun -- The *Best* ICMP tunnel
======================

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

** TODO **

* make it work
* reply to normal pings
* parse dns
* timer adjustments
* real authentication
