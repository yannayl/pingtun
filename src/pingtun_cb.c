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

#include <event2/event.h>
#include <stdlib.h>
#include "pingtun.h"
#include "pingtun_cb.h"

static void echo_timer_interval_increase(pingtun_t *handle) {
	handle->echo_timer.interval.tv_sec *= 2;
	handle->echo_timer.interval.tv_usec *= 2;

	if (1000 * 1000 <= handle->echo_timer.interval.tv_usec) {
		handle->echo_timer.interval.tv_usec -= 1000 * 1000;
		handle->echo_timer.interval.tv_sec += 1;
	}

	if ((PING_TIMER_INTERVAL_MAX_SEC < handle->echo_timer.interval.tv_sec) ||
			((PING_TIMER_INTERVAL_MAX_SEC == handle->echo_timer.interval.tv_sec) &&
			(PING_TIMER_INTERVAL_MAX_USEC < handle->echo_timer.interval.tv_usec))) {
		handle->echo_timer.interval.tv_sec = PING_TIMER_INTERVAL_MAX_SEC;
		handle->echo_timer.interval.tv_usec = PING_TIMER_INTERVAL_MAX_USEC;
		return;
	}
}

static void echo_timer_interval_decrease(pingtun_t *handle) {
	handle->echo_timer.interval.tv_usec /= 2;
	handle->echo_timer.interval.tv_usec += 
		(handle->echo_timer.interval.tv_sec % 2) * 1000 * 1000 / 2;
	handle->echo_timer.interval.tv_sec /= 2;

	if ((PING_TIMER_INTERVAL_MIN_SEC > handle->echo_timer.interval.tv_sec) ||
			((PING_TIMER_INTERVAL_MIN_SEC == handle->echo_timer.interval.tv_sec) &&
			(PING_TIMER_INTERVAL_MIN_USEC > handle->echo_timer.interval.tv_usec))) {
		handle->echo_timer.interval.tv_sec = PING_TIMER_INTERVAL_MIN_SEC;
		handle->echo_timer.interval.tv_usec = PING_TIMER_INTERVAL_MIN_USEC;
		return;
	}
}

static void echo_timer_reset(pingtun_t *handle) {
	handle->flags.ping_timer_expired = 0;

	if (handle->flags.received_data) {
		echo_timer_interval_decrease(handle);
	} else {
		echo_timer_interval_increase(handle);
	}
	handle->flags.received_data = 0;

	if (0 != event_add(handle->echo_timer.ev, &handle->echo_timer.interval)) {
		ERR("event add failed");
		exit(EXIT_FAILURE);
	}
}

static void ptcb_ping_read(pingtun_t *handle, struct ping_struct *ping,
		struct sockaddr_in *sock_addr) {
	size_t len = 0;

	if (0 != pingtun_ping_rcv(ping->ping, sock_addr)) {
		ERR("read failed");
		exit(EXIT_FAILURE);
	}

	len = pingtun_ping_len(ping->ping);

	if (0 == len) {
		return;
	}

	ping->state = STATE_TO_TUN;
	
	if (0 != event_add(handle->tun.write_ev, NULL)) {
		ERR("event add failed");
		exit(EXIT_FAILURE);
	}
	
	if (0 != event_del(handle->tun.read_ev)) {
		ERR("event add failed");
		exit(EXIT_FAILURE);
	}
	
	if (0 != event_priority_set(ping->rcv_ev, PINGTUN_PRIO_READ_LOW)) {
		ERR("event set priority failed");
		exit(EXIT_FAILURE);
	}
}

void ptcb_sping_write(evutil_socket_t fd, short events, void *pt_handle) {
	pingtun_t *handle = (pingtun_t *) pt_handle;
	struct ping_struct *ping = &handle->sping;

	if (0 != pingtun_ping_rpl(ping->ping, &handle->reply_addr)) {
		ERR("write failed");
		exit(EXIT_FAILURE);
	}

	ping->state = STATE_NON;
	
	if (0 != event_add(ping->rcv_ev, NULL)) {
		ERR("event add failed");
		exit(EXIT_FAILURE);
	}
}

void ptcb_sping_read(evutil_socket_t fd, short events, void *pt_handle) {
	pingtun_t *handle = (pingtun_t *) pt_handle;
	struct ping_struct *ping = &handle->sping;
	ptcb_ping_read(handle, ping, &handle->reply_addr);

	if (STATE_NON != ping->state) {
		return;
	}

	if (0 != event_add(handle->tun.read_ev, NULL)) {
		ERR("event add failed");
		exit(EXIT_FAILURE);
	}

	if (0 != event_add(ping->rcv_ev, NULL)) {
		ERR("event add failed");
		exit(EXIT_FAILURE);
	}
}

void ptcb_cping_write(evutil_socket_t fd, short events, void *pt_handle) {
	pingtun_t *handle = (pingtun_t *) pt_handle;
	struct ping_struct *ping = &handle->cping;

	if (0 != pingtun_ping_req(ping->ping, &handle->server)) {
		ERR("write failed");
		exit(EXIT_FAILURE);
	}

	ping->state = STATE_NON;
	echo_timer_reset(handle);

	if (0 != event_add(ping->rcv_ev, NULL)) {
		ERR("event add failed");
		exit(EXIT_FAILURE);
	}
	
	if (0 != event_add(handle->tun.read_ev, NULL)) {
		ERR("event add failed");
		exit(EXIT_FAILURE);
	}
}

void ptcb_cping_read(evutil_socket_t fd, short events, void *pt_handle) {
	pingtun_t *handle = (pingtun_t *) pt_handle;
	ptcb_ping_read(handle, &handle->cping, NULL);
	if (STATE_TO_TUN == handle->cping.state) {
		handle->flags.received_data = 1;
	}
}

void ptcb_tun_write(evutil_socket_t fd, short events, void *pt_handle) {
	pingtun_t *handle = (pingtun_t *) pt_handle;
	struct ping_struct *ping = NULL;
	ssize_t len = -1;
	const void *data = NULL;

	if (STATE_TO_TUN == handle->cping.state) {
		ping = &handle->cping;
	} else if (STATE_TO_TUN == handle->sping.state) {
		ping = &handle->sping;
		if (0 != event_add(ping->rcv_ev, NULL)) {
			ERR("add event failed");
			exit(EXIT_FAILURE);
		}
	} else {
		ERR("write event cb invoked with no data");
		return;
	}

	len = pingtun_ping_len(ping->ping);
	data = pingtun_ping_data(ping->ping);
	len = pingtun_tun_write(handle->tun.tun, data, len);
	if (0 > len)	{
		ERR("write failed");
		exit(EXIT_FAILURE);
	}

	ping->state = STATE_NON;
	if (0 != pingtun_ping_len_set(ping->ping, 0)) {
		ERR("zero pingtun len failed");
		exit(EXIT_FAILURE);
	}

	if (handle->flags.ping_timer_expired && (ping == &handle->cping)) {
		ptcb_echo_timer(-1, EV_TIMEOUT, handle);
	}
	
	if (0 != event_add(handle->tun.read_ev, NULL)) {
		ERR("event add failed");
		exit(EXIT_FAILURE);
	}

}

void ptcb_tun_read(evutil_socket_t fd, short events, void *pt_handle) {
	pingtun_t *handle = (pingtun_t *) pt_handle;
	struct ping_struct *ping = NULL;
	ssize_t len = -1;

	if ((handle->flags.is_client) && (STATE_NON == handle->cping.state)) {
		ping = &handle->cping;
	} else if ((handle->flags.is_client) &&
			(handle->flags.ping_timer_expired) &&
			(STATE_FROM_TUN == handle->cping.state) && 
			(0 == pingtun_ping_len(handle->cping.ping))) {
		ping = &handle->cping;
	} else if ((handle->flags.is_server) &&
			(STATE_NON == handle->sping.state)) {
		ping = &handle->sping;
	} else {
		ERR("wat?");
		exit(EXIT_FAILURE);
	}

	len = pingtun_tun_read(handle->tun.tun, 
			pingtun_ping_data(ping->ping),
			pingtun_ping_capacity(ping->ping));

	if (0 > len) {
		ERR("read failed");
		exit(EXIT_FAILURE);
	}
	if (0 != pingtun_ping_len_set(ping->ping, len)) {
		ERR("failed set len");
		exit(EXIT_FAILURE);
	}
	
	ping->state = STATE_FROM_TUN;

	if (0 != event_add(ping->snd_ev, NULL)) {
		ERR("event add failed");
		exit(EXIT_FAILURE);
	}
	
	if (0 != event_del(ping->rcv_ev)) {
		ERR("event del failed");
		exit(EXIT_FAILURE);
	}

	if (0 != event_priority_set(ping->rcv_ev, PINGTUN_PRIO_READ_HIGH)) {
		ERR("event set priority failed");
		exit(EXIT_FAILURE);
	}
}

void ptcb_echo_timer(evutil_socket_t fd, short events, void *pt_handle) {
	pingtun_t *handle = (pingtun_t *) pt_handle;
	handle->flags.ping_timer_expired = 1;
	if (STATE_NON != handle->cping.state) {
		return;
	}

	if (0 != event_add(handle->cping.snd_ev, NULL)) {
		ERR("event add failed");
		exit(EXIT_FAILURE);
	}
	handle->cping.state = STATE_FROM_TUN;
	
	if (0 != event_del(handle->cping.rcv_ev)) {
		ERR("event del failed");
		exit(EXIT_FAILURE);
	}
}

void ptcb_break(evutil_socket_t signal, short events, void *pt_handle) {
	pingtun_t *handle = (pingtun_t *) pt_handle;
	if (0 != event_base_loopbreak(handle->base_ev)) {
		ERR("failed to break the loop!");
		exit(EXIT_FAILURE);
	}
	handle->ret = 0;
}
