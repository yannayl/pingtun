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
#ifndef PINGTUN_TUN_H
#define PINGTUN_TUN_H (1)

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

typedef struct {
	char name[IFNAMSIZ];
	int fd;
} pingtun_tun_t;

int pingtun_tun_init(pingtun_tun_t **handle, const struct in_addr *address,
		const struct in_addr *netmask, size_t mtu);
int pingtun_tun_fd(pingtun_tun_t *handle);
const char *pingtun_tun_name(pingtun_tun_t *handle);
ssize_t pingtun_tun_read(pingtun_tun_t *handle, void *buf, size_t len);
ssize_t pingtun_tun_write(pingtun_tun_t *handle, const void *buf, size_t len);
void pingtun_tun_fini(pingtun_tun_t **handle);

#ifdef __cplusplus
}
#endif

#endif
