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

#define PINGTUN_POS_ARGS_NUM (2)

typedef struct {
	int		ping_reply;
	struct	in_addr server;
	struct	in_addr address;
	struct 	in_addr	netmask;

} pingtun_opts_t;

static void usage() {
	fprintf(stderr, 
"usage:\t"	"pingtun [-s|--server <address>] [-p|--ping-reply] <address> <netmask>\n"
	"\t-s|--server <address>\t"	"sets the adress of the ping tunnel\n"
	"\t-p|--ping-reply\t\t"		"reply to pings which are not from the tunnel\n"
	);

	exit(EXIT_FAILURE);
}

static void parse_opt_server(pingtun_opts_t *opts) {
	if (0 == inet_aton(optarg, &(opts->server))) {
		ERR("invalid server address %s", optarg);
		usage();
	}
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

	c = getopt_long(argc, argv, "s:p", long_options,  NULL);
	while (-1 != c) {
		switch (c) {
			case 's':
				parse_opt_server(opts);
				break;
			case 'p':
				opts->ping_reply = 1;
				break;
			default:
				ERR("unknown options: %d", c);
				usage();
		}

		c = getopt_long(argc, argv, "s:p", long_options,  NULL);
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

int main(int argc, char **argv) {
	pingtun_opts_t options = {0};
	pingtun_tun_t *tun = NULL;
	pingtun_ping_t *ping = NULL;
	size_t len = -1;
	size_t i = 0;
	ssize_t mtu = -1;
	const struct icmphdr *icmphdr_p = NULL;
	const void *data = NULL;
	struct sockaddr_in sockaddr = {0};

	DBG("parsing options");
	parse_opts(&options, argc, argv);
	
	//TODO: if no server set, ignore pings
	//TODO: echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all
	//TODO:   (and save original value for restoration)
	
	DBG("initializing ping socket");
	if (0 != pingtun_ping_init(&ping)) {
		ERR("initializing ping socket failed.");
		return -1;
	}
	mtu = pingtun_ping_mtu(ping);

	DBG("initializing tun device");
	if (0 != pingtun_tun_init(&tun, &options.address, &options.netmask, mtu)) {
		ERR("initializing tun device failed.");
		return -1;
	}
	
	while(1) {
		data = pingtun_ping_data(ping, &len);
		for (i = 0; i < len; i++) {
			*(uint8_t *)(data + i) = i;
		}
		sockaddr.sin_addr = options.server;
		pingtun_ping_req(ping, data, len, &sockaddr);
		sleep(1);
		pingtun_ping_rcv(ping, &icmphdr_p, &data, &sockaddr);
	}
	return 0;
}

