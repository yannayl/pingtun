#include "pingtun.h"
#include "tun.h"
#include "ping.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <event2/event.h>

#define PINGTUN_POS_ARGS_NUM (2)

typedef struct {
	struct {
		int	has_server:1;
	} flags;
	struct	in_addr server;
	struct	in_addr address;
	struct 	in_addr	netmask;
} pingtun_opts_t;

typedef struct {
	pingtun_opts_t opts;
	pingtun_tun_t *tun;
	pingtun_ping_t *ping;
	struct event *ping_snd_ev;
	struct event *ping_rcv_ev;
	struct event *tun_read_ev;
	struct event *tun_write_ev;
	struct event_base *base_ev;
} pingtun_t;

static void usage() {
	fprintf(stderr, 
"usage:\t"	"pingtun [-s|--server <address>] <address> <netmask>\n"
	"\t-s|--server <address>\t"	"sets the adress of the ping tunnel\n"
	);

	exit(EXIT_FAILURE);
}

static void parse_opt_server(pingtun_opts_t *opts) {
	if (0 == inet_aton(optarg, &(opts->server))) {
		ERR("invalid server address %s", optarg);
		usage();
	}
	opts->flags.has_server = 1;
}

static void parse_opt_netmask(pingtun_opts_t *opts, char *arg) {
	if (0 == inet_aton(arg, &opts->netmask)) {
		ERR("invalid netmask: %s", arg);
		usage();
	}
}

static void parse_opt_address(pingtun_opts_t *opts, char *arg) {
	if (0 == inet_aton(arg, &opts->address)) {
		ERR("invalid address: %s", arg);
		usage();
	}
}

static void parse_opts(pingtun_opts_t *opts, int argc, char **argv) {
	int c = -1;
	static const struct option long_options[] = {
		{"server", required_argument, 0, 's'},
		{"ping-reply", required_argument, 0, 'p'},
		{0,0,0,0}
	};

	c = getopt_long(argc, argv, "s:", long_options,  NULL);
	while (-1 != c) {
		switch (c) {
			case 's':
				parse_opt_server(opts);
				break;
			default:
				ERR("unknown options: %d", c);
				usage();
		}

		c = getopt_long(argc, argv, "s:", long_options,  NULL);
	}

	if (argc < optind + PINGTUN_POS_ARGS_NUM) {
		ERR("missing arguments");
		usage();
	} else if (argc > optind + PINGTUN_POS_ARGS_NUM){
		ERR("too many arguments");
		usage();
	}

	parse_opt_address(opts, argv[optind]);
	parse_opt_netmask(opts, argv[optind+1]);
}

static void ping_ev_cb(evutil_socket_t fd, short events, void *handle) {
	return;
}

static void tun_ev_cb(evutil_socket_t fd, short events, void *handle) {
	return;
}

static int init_base_ev(pingtun_t *handle) {
	handle->base_ev = event_base_new();
	if (NULL == handle->base_ev) {
		ERR("initializing event base failed");
		return -1;
	}

	return 0;
}

static int init_ping(pingtun_t *handle) {
	if (0 != pingtun_ping_init(&handle->ping)) {
		ERR("initializing ping socket failed.");
		return -1;
	}

	handle->ping_rcv_ev = event_new(handle->base_ev,
			pingtun_ping_fd(handle->ping), EV_READ, ping_ev_cb, handle);
	if (NULL == handle->ping_rcv_ev) {
		ERR("initializing event failed");
		return -1;
	}
	handle->ping_snd_ev = event_new(handle->base_ev,
			pingtun_ping_fd(handle->ping), EV_WRITE, ping_ev_cb, handle);
	if (NULL == handle->ping_snd_ev) {
		ERR("initializing event failed");
		return -1;
	}

	return 0;
}

static int init_tun(pingtun_t *handle) {
	short events;
	size_t mtu = pingtun_ping_mtu(handle->ping);

	if (0 != pingtun_tun_init(&handle->tun, &handle->opts.address,
				&handle->opts.netmask, mtu)) {
		ERR("initializing tun device failed.");
		return -1;
	}

	events = EV_READ;
	if (handle->opts.flags.has_server) {
		events |= EV_PERSIST;
	}
	handle->tun_read_ev = event_new(handle->base_ev,
			pingtun_tun_fd(handle->tun), events, tun_ev_cb, handle);
	if (NULL == handle->tun_read_ev) {
		ERR("initializing event failed");
		return -1;
	}
	
	handle->tun_write_ev = event_new(handle->base_ev,
			pingtun_tun_fd(handle->tun), EV_WRITE, tun_ev_cb, handle);
	if (NULL == handle->tun_write_ev) {
		ERR("initializing event failed");
		return -1;
	}

	return 0;
}

int main(int argc, char **argv) {
	pingtun_t handle;
	memset(&handle, 0, sizeof(handle));

	DBG("parsing options");
	parse_opts(&handle.opts, argc, argv);
	
	//TODO: echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all
	//TODO:   (and save original value for restoration)
	DBG("initializing event base");
	if (0 != init_base_ev(&handle)) {
		return -1;
	}

	DBG("initializing ping socket");
	if (0 != init_ping(&handle)) {
		return -1;
	}

	DBG("initializing tun device");
	if (0 != init_tun(&handle)) {
		return -1;
	}

	event_base_dispatch(handle.base_ev);
	return 0;
}

