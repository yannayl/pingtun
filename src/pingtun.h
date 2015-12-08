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
#ifndef PINGTUN_H
#define PINGTUN_H (1)

#ifdef __cplusplus
extern "C" {
#endif

#include "ping.h"
#include "tun.h"
#include "log.h"
#include <sys/time.h>
#include <netinet/in.h>

#define PING_TIMER_INTERVAL_MAX_SEC (3)
#define PING_TIMER_INTERVAL_MAX_USEC (0)

#define PING_TIMER_INTERVAL_MIN_SEC (0)
#define PING_TIMER_INTERVAL_MIN_USEC (1000)

#define PINGTUN_DFL_ICMPID	(0x8e2c)

typedef struct {
	int ret;

	struct {
		int	is_client:1;
		int is_server:1;
		int ignore_pings:1;
		int changed_ignore_pings:1;
		int ping_timer_expired:1;
		int received_data:1;
	} flags;

	struct	sockaddr_in server;
	struct	sockaddr_in reply_addr;
	struct	in_addr address;
	struct	in_addr	netmask;
	uint16_t	icmp_id;

	struct ping_struct {
		pingtun_ping_t *ping;
		struct event *snd_ev;
		struct event *rcv_ev;
		enum {
			STATE_NON,
			STATE_TO_TUN,
			STATE_FROM_TUN,
		} state;
	} sping, cping;

	struct {	
		pingtun_tun_t *tun;
		struct event *read_ev;
		struct event *write_ev;
	} tun;

	struct {
		struct event *ev;	
		struct timeval interval;
	} echo_timer;

	struct event *sigint_ev,
				 *sighup_ev,
				 *sigpipe_ev,
				 *sigterm_ev,
				 *sigusr1_ev,
				 *sigusr2_ev,
				 *sigstp_ev;

	struct event_base *base_ev;
} pingtun_t;

typedef enum {
	PINGTUN_PRIO_READ_LOW,
	PINGTUN_PRIO_READ_NORMAL,
	PINGTUN_PRIO_READ_HIGH,
	PINGTUN_PRIO_WRITE,
	PINGTUN_PRIO_SIGNAL,
	PINGTUN_PRIO_MAX
} pingtun_prio_e;

#ifdef __cplusplus
}
#endif

#endif
