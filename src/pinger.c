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

#define PINGER_POS_ARGS_NUM (1)

typedef struct {
	struct	in_addr address;
} pinger_opts_t;

static void usage() {
	fprintf(stderr, 
"usage:\t"	"pinger <address>\n"
	);

	exit(EXIT_FAILURE);
}

static void parse_opt_address(pinger_opts_t *opts, char *arg) {
	if (0 == inet_aton(arg, &opts->address)) {
		ERR("invalid address: %s", arg);
		usage();
	}
}

static void parse_opts(pinger_opts_t *opts, int argc, char **argv) {
	int c = -1;
	static const struct option long_options[] = {
		{0,0,0,0}
	};

	c = getopt_long(argc, argv, "", long_options,  NULL);
	while (-1 != c) {
		switch (c) {
			default:
				ERR("unknown options: %d", c);
				usage();
		}

		c = getopt_long(argc, argv, "", long_options,  NULL);
	}

	if (argc < optind + PINGER_POS_ARGS_NUM) {
		ERR("missing arguments");
		usage();
	} else if (argc > optind + PINGER_POS_ARGS_NUM){
		ERR("too many arguments");
		usage();
	}

	parse_opt_address(opts, argv[optind]);
}

int main(int argc, char **argv) {
	pinger_opts_t options = {{0}};
	pingtun_ping_t *ping = NULL;
	size_t len = -1;
	size_t i = 0;
	const struct icmphdr *icmphdr_p = NULL;
	const void *data = NULL;
	struct sockaddr_in sockaddr = {0};

	DBG("parsing options");
	parse_opts(&options, argc, argv);
	
	DBG("initializing ping socket");
	if (0 != pingtun_ping_init(&ping)) {
		ERR("initializing ping socket failed.");
		return -1;
	}

	while(1) {
		data = pingtun_ping_data(ping, &len);
		for (i = 0; i < len; i++) {
			*(uint8_t *)(data + i) = i;
		}
		sockaddr.sin_addr = options.address;
		pingtun_ping_req(ping, data, len, &sockaddr);
		sleep(1);
		pingtun_ping_rcv(ping, &icmphdr_p, &data, &sockaddr);
	}
	return 0;
}

