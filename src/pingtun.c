/*
 *  pingtun
 *  Copyright (C) 2015 Yannay Livneh <yannayl@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "pingtun.h"
#include "pingtun_cb.h"
#include "tun.h"
#include "ping.h"
#include "log.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <event2/event.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#define PATH_ICMP_ECHO_IGNORE "/proc/sys/net/ipv4/icmp_echo_ignore_all"
#define PINGTUN_POS_ARGS_NUM (2)

static void usage() {
	fprintf(stderr, 
"usage:\t"	"pingtun [-c|--client-only] [-s|--server <address>] <address> <netmask>\n"
	"\t-s|--server <address>\t"	"sets the adress of the ping tunnel\n"
	"\t-c|--client-only\t"		"client mode only, don't list to echo requests\n"
	);

	exit(EXIT_FAILURE);
}

static void parse_opt_server(pingtun_t *handle) {
	struct in_addr server_addr = {0};
	if (0 == inet_aton(optarg, &server_addr)) {
		ERR("invalid server address %s", optarg);
		usage();
	}
	handle->server.sin_family = AF_INET;	
	handle->server.sin_addr = server_addr;
	handle->flags.is_client = 1;
}

static void parse_opt_netmask(pingtun_t *handle, char *arg) {
	if (0 == inet_aton(arg, &handle->netmask)) {
		ERR("invalid netmask: %s", arg);
		usage();
	}
}

static void parse_opt_address(pingtun_t *handle, char *arg) {
	if (0 == inet_aton(arg, &handle->address)) {
		ERR("invalid address: %s", arg);
		usage();
	}
}

static void parse_opts(pingtun_t *handle, int argc, char **argv) {
	int c = -1;
	const char shortopts[] = "s:c";
	static const struct option long_options[] = {
		{"server", required_argument, 0, 's'},
		{"client-only", required_argument, 0, 'c'},
		{0,0,0,0}
	};

	handle->flags.is_server = 1;

	c = getopt_long(argc, argv, shortopts, long_options,  NULL);
	while (-1 != c) {
		switch (c) {
			case 's':
				parse_opt_server(handle);
				break;
			case 'c':
				handle->flags.is_server = 0;
				break;
			default:
				ERR("unknown options: %d", c);
				usage();
		}

		c = getopt_long(argc, argv, shortopts, long_options,  NULL);
	}

	if (!handle->flags.is_client && !handle->flags.is_server) {
		ERR("neither client nor server. "
				"when using '--client-only' flage, "
				"one must specify '--server'");
		usage();
	}

	if (argc < optind + PINGTUN_POS_ARGS_NUM) {
		ERR("missing arguments");
		usage();
	} else if (argc > optind + PINGTUN_POS_ARGS_NUM){
		ERR("too many arguments");
		usage();
	}

	parse_opt_address(handle, argv[optind]);
	parse_opt_netmask(handle, argv[optind+1]);
}

static int set_ignore_echo(pingtun_t *handle) {
	int ret = -1;
	int fd = -1;
	char read_byte;

	fd = open(PATH_ICMP_ECHO_IGNORE, O_RDWR);
	if (0 > fd) {
		ERR("failed opening %s. error: %s", PATH_ICMP_ECHO_IGNORE,
				strerror(errno));
		goto exit;
	}

	if (1 != read(fd, &read_byte, sizeof(read_byte))) {
		ERR("failed reading %s. error: %s", PATH_ICMP_ECHO_IGNORE,
				strerror(errno));
		goto exit;
	}

	switch (read_byte) {
		case '0':
			break;
		case '1':
			handle->flags.ignore_pings = 1;
			break;
		default:
			ERR("unexpected icmp ignore value: %c", read_byte);
			goto exit;
	}

	if (!handle->flags.ignore_pings) {
		read_byte = '1';
		if (1 != write(fd, &read_byte, sizeof(read_byte))) {
			ERR("failed writing %s. error: %s", PATH_ICMP_ECHO_IGNORE,
					strerror(errno));
			goto exit;
		}
		handle->flags.changed_ignore_pings = 1;
	}

	ret = 0;
exit:
	close(fd);
	return ret;
}

static void reset_ignore_echo(pingtun_t *handle) {
	int fd = -1;
	char write_byte;

	if (!handle->flags.changed_ignore_pings) {
		return;
	}

	fd = open(PATH_ICMP_ECHO_IGNORE, O_RDWR);
	if (0 > fd) {
		return;
	}

	write_byte = '0';
	write(fd, &write_byte, sizeof(write_byte));
	close(fd);
}

static int init_base_ev(pingtun_t *handle) {
	handle->base_ev = event_base_new();
	if (NULL == handle->base_ev) {
		ERR("initializing event base failed");
		return -1;
	}

	if (0 != event_base_priority_init(handle->base_ev, PINGTUN_PRIO_MAX)) {
		ERR("failed to set base priority");
		return -1;
	}

	return 0;
}

static int init_ping(pingtun_t *handle, struct ping_struct *ping,
		pingtun_ping_filter_e filter, event_callback_fn write_cb,
		event_callback_fn read_cb) {
	if (0 != pingtun_ping_init(&ping->ping, filter)) {
		ERR("initializing ping socket failed.");
		return -1;
	}

	ping->rcv_ev = event_new(handle->base_ev, pingtun_ping_fd(ping->ping),
			EV_READ, read_cb, handle);
	if (NULL == ping->rcv_ev) {
		ERR("initializing event failed");
		return -1;
	}

	if (0 != event_priority_set(ping->rcv_ev, PINGTUN_PRIO_READ_NORMAL)) {
		ERR("event set priority failed");
		return -1;
	}
	
	ping->snd_ev = event_new(handle->base_ev, pingtun_ping_fd(ping->ping),
			EV_WRITE, write_cb, handle);
	if (NULL == ping->snd_ev) {
		ERR("initializing event failed");
		return -1;
	}
	
	if (0 != event_priority_set(ping->snd_ev, PINGTUN_PRIO_WRITE)) {
		ERR("event set priority failed");
		return -1;
	}

	return 0;
}

static int init_sping(pingtun_t *handle) {
	if (0 != init_ping(handle, &handle->sping, PINGTUN_PING_FILTER_ECHO,
				ptcb_sping_write, ptcb_sping_read)) {
		return -1;
	}

	if (0 != event_add(handle->sping.rcv_ev, NULL)) {
		ERR("failed adding event");
		return -1;
	}
	
	return 0;
}

static int init_echo_timer(pingtun_t *handle) {

	handle->echo_timer.interval.tv_sec = PING_TIMER_INTERVAL_MAX_SEC;
	handle->echo_timer.interval.tv_usec = PING_TIMER_INTERVAL_MAX_USEC;

	handle->echo_timer.ev = event_new(handle->base_ev, -1, EV_PERSIST,
			ptcb_echo_timer, handle);
	if (NULL == handle->echo_timer.ev) {
		ERR("initializing ping timer failed");
		return -1;
	}
	
	if (0 != event_priority_set(handle->echo_timer.ev, PINGTUN_PRIO_WRITE)) {
		ERR("event set priority failed");
		return -1;
	}

	if (0 != event_add(handle->echo_timer.ev, &(handle->echo_timer.interval))) {
		ERR("failed adding event");
		return -1;
	}

	return 0;
}

static int init_cping(pingtun_t *handle) {
	if (0 != init_ping(handle, &handle->cping, PINGTUN_PING_FILTER_ECHOREPLY,
				ptcb_cping_write, ptcb_cping_read)) {
		return -1;
	}

	if (0 != init_echo_timer(handle)) {
		return -1;
	}

	return 0;
}

static int init_tun(pingtun_t *handle) {
	size_t mtu = 0;
	
	if (handle->flags.is_client) {
		mtu = pingtun_ping_capacity(handle->cping.ping);
	} else {
		mtu = pingtun_ping_capacity(handle->sping.ping);
	}

	if (0 != pingtun_tun_init(&handle->tun.tun, &handle->address,
				&handle->netmask, mtu)) {
		ERR("initializing tun device failed.");
		return -1;
	}

	handle->tun.read_ev = event_new(handle->base_ev,
			pingtun_tun_fd(handle->tun.tun), EV_READ, ptcb_tun_read, handle);
	if (NULL == handle->tun.read_ev) {
		ERR("initializing event failed");
		return -1;
	}
	
	if (0 != event_priority_set(handle->tun.read_ev, PINGTUN_PRIO_READ_NORMAL)) {
		ERR("event set priority failed");
		return -1;
	}

	handle->tun.write_ev = event_new(handle->base_ev,
			pingtun_tun_fd(handle->tun.tun), EV_WRITE, ptcb_tun_write, handle);
	if (NULL == handle->tun.write_ev) {
		ERR("initializing event failed");
		return -1;
	}
	
	if (0 != event_priority_set(handle->tun.write_ev, PINGTUN_PRIO_WRITE)) {
		ERR("event set priority failed");
		return -1;
	}

	if (handle->flags.is_client) {
		if (0 != event_add(handle->tun.read_ev, NULL)) {
			ERR("failed adding event");
			return -1;
		}
	}

	return 0;
}

#ifdef PINGTUN_INIT_ADD_SIG
#	error "PINGTUN_INIT_ADD_SIG already defined, WTF?"
#endif
#define PINGTUN_INIT_ADD_SIG(hanle, sigev, sig, cb) \
	do { \
		(handle)->sigev = evsignal_new((handle)->base_ev, (sig), (cb), \
				(handle));\
		if (NULL == (handle)->sigev) {\
			ERR("initializing event failed");\
				return -1;\
		}\
		\
		if (0 != event_priority_set((handle)->sigev, PINGTUN_PRIO_SIGNAL)) {\
			ERR("failed adding event");\
			return -1;\
		}\
		\
		if (0 != evsignal_add((handle)->sigev, NULL)) {\
			ERR("failed adding event");\
			return -1;\
		}\
	} while(0)

static int init_signals(pingtun_t *handle) {
	PINGTUN_INIT_ADD_SIG(handle, sigint_ev, SIGINT, ptcb_break);
	PINGTUN_INIT_ADD_SIG(handle, sighup_ev, SIGHUP, ptcb_break);
	PINGTUN_INIT_ADD_SIG(handle, sigpipe_ev, SIGPIPE, ptcb_break);
	PINGTUN_INIT_ADD_SIG(handle, sigterm_ev, SIGTERM, ptcb_break);
	PINGTUN_INIT_ADD_SIG(handle, sigusr1_ev, SIGUSR1, ptcb_break);
	PINGTUN_INIT_ADD_SIG(handle, sigusr2_ev, SIGUSR2, ptcb_break);

	return 0;
}
#undef PINGTUN_INIT_ADD_SIG

int main(int argc, char **argv) {
	pingtun_t handle;

	handle.ret = -1;
	memset(&handle, 0, sizeof(handle));

	DBG("parsing options");
	parse_opts(&handle, argc, argv);

	if (handle.flags.is_server) {
		if (0 != set_ignore_echo(&handle)) {
			goto exit;
		}
	}
	
	DBG("initializing event base");
	if (0 != init_base_ev(&handle)) {
		goto exit;
	}

	DBG("initializing ping socket");
	if (handle.flags.is_server) {
		if (0 != init_sping(&handle)) {
			goto exit;
		}
	}
	if (handle.flags.is_client) {
		if (0 != init_cping(&handle)) {
			goto exit;
		}
	}

	DBG("initializing tun device");
	if (0 != init_tun(&handle)) {
		goto exit;
	}

	if (0 != init_signals(&handle)) {
		goto exit;
	}

	switch (event_base_dispatch(handle.base_ev)) {
		case 0:
			break;
		case -1:
			ERR("dispatch event loop failed");
			goto exit;
		case 1:
			ERR("no more active/pending events");
			goto exit;
	}

exit:
	if (handle.flags.is_server) {
		reset_ignore_echo(&handle);
	}
	//TODO: de-allocate all the shit. Do I really care?
	return handle.ret;
}

