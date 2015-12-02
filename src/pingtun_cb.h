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
#ifndef PINGTUN_CB_H
#define PINGTUN_CB_H (1)

#ifdef __cplusplus
extern "C" {
#endif

#include "pingtun.h"
#include <event2/event.h>

void ptcb_echo_timer(evutil_socket_t fd, short events, void *pt_handle);
void ptcb_sping_write(evutil_socket_t fd, short events, void *pt_handle);
void ptcb_sping_read(evutil_socket_t fd, short events, void *pt_handle);
void ptcb_cping_write(evutil_socket_t fd, short events, void *pt_handle);
void ptcb_cping_read(evutil_socket_t fd, short events, void *pt_handle);
void ptcb_tun_write(evutil_socket_t fd, short events, void *pt_handle);
void ptcb_tun_read(evutil_socket_t fd, short events, void *pt_handle);
void ptcb_break(evutil_socket_t signal, short events, void *pt_handle);

#ifdef __cplusplus
}
#endif

#endif
