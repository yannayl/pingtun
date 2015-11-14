#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG(format, ...)\
	do { fprintf(stderr, format "\n", ##__VA_ARGS__); } while (0)

#define ERR(format, ...)\
	LOG("ERR: " format, ##__VA_ARGS__)

#define DBG(format, ...)\
	LOG("DBG: " format, ##__VA_ARGS__)

typedef struct {
	int		ping_reply;
	struct	in_addr server;
} pingtun_opts_t;

void usage() {
	fprintf(stderr, 
"usage:\tpingtun [-s|--server <address>] [-p|--ping-reply]\n"
"\t\t-s|--server <address>\t\tsets the adress of the ping tunnel"
"\t\t-p|--ping-reply\t\treply to pings which are not from the tunnel"
	);

	exit(EXIT_FAILURE);
}

void parse_opts(pingtun_opts_t *opts, int argc, char **argv) {
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
				if (0 == inet_aton(optarg, &(opts->server))) {
					ERR("invalid server address %s", optarg);
					usage();
				}
				break;
			case 'p':
				opts->ping_reply = 1;
				break;
			default:
				usage();
		}

		c = getopt_long(argc, argv, "s:", long_options,  NULL);
	}
}

int main(int argc, char **argv) {
	pingtun_opts_t options = {0};
	DBG("parsing options");
	parse_opts(&options, argc, argv);
	DBG("TODO");
	return 0;
}

