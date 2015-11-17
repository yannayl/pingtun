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

#define PING_SERVER_POS_ARGS_NUM (0)

static void usage() {
	fprintf(stderr, 
"usage:\t"	"pingtun [-s|--server <address>] [-p|--ping-reply] <address> <netmask>\n"
	);

	exit(EXIT_FAILURE);
}

static void parse_opts(int argc, char **argv) {
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

	if (argc > optind + PING_SERVER_POS_ARGS_NUM) {
		ERR("missing address argument");
		usage();
	} else if (argc < optind + PING_SERVER_POS_ARGS_NUM){
		ERR("too many arguments");
		usage();
	}
}

int main(int argc, char **argv) {
	pingtun_ping_t *ping = NULL;
	ssize_t len = -1;
	const struct icmphdr *icmphdr_p = NULL;
	const void *data = NULL;
	struct sockaddr_in sockaddr = {0};

	DBG("parsing options");
	parse_opts(argc, argv);
	
	DBG("initializing ping socket");
	if (0 != pingtun_ping_init(&ping)) {
		ERR("initializing ping socket failed.");
		return -1;
	}
	
	while(1) {
		len = pingtun_ping_rcv(ping, &icmphdr_p, &data, &sockaddr);
		DBG("received %zd... replying", len);
		pingtun_ping_rpl(ping, data, len, &sockaddr);
	}
	return 0;
}

