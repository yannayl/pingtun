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
#include "tun.h"
#include "pingtun.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <linux/if_tun.h>

#define TUN_DEV	"/dev/net/tun"

static int set_if_params(pingtun_tun_t *tun, const struct in_addr *address,
		const struct in_addr *netmask, size_t mtu) {
	int ret = -1;
	struct sockaddr_in *addr = NULL;
	struct ifreq ifr;
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (0 > sock) {
		ERR("failed to open sock. error: %s.", strerror(errno));
		goto exit;
	}
	
	strncpy(ifr.ifr_name, tun->name, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;
	addr = (struct sockaddr_in *) &ifr.ifr_addr;

	addr->sin_addr = *address;
	if (0 != ioctl(sock, SIOCSIFADDR, &ifr)) {
		ERR("failed set ip address. error: %s.", strerror(errno));
		goto exit;
	}

	addr->sin_addr = *netmask; 
	if (0 != ioctl(sock, SIOCSIFNETMASK, &ifr)) {
		ERR("failed set ip address. error: %s.", strerror(errno));
		goto exit;
	}
	
	if (0 != ioctl(sock, SIOCGIFFLAGS, &ifr)) {
		ERR("failed get interface params. error: %s.", strerror(errno));
		goto exit;
	}
	
	ifr.ifr_mtu = mtu;
	if (0 != ioctl(sock, SIOCSIFMTU, &ifr)) {
		ERR("failed set mtu (%zu). error: %s.", mtu, strerror(errno));
		goto exit;
	}

	ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
	if (0 != ioctl(sock, SIOCSIFFLAGS, &ifr)) {
		ERR("failed set interface up & running. error: %s.", strerror(errno));
		goto exit;
	}
	
	ret = 0;
exit:
	close(sock);
	return ret;
}

int pingtun_tun_init(pingtun_tun_t **handle, const struct in_addr *address,
		const struct in_addr *netmask, size_t mtu) {
	int ret = -1;
	struct ifreq ifr;

	*handle = calloc(1, sizeof(pingtun_tun_t));
	if (NULL == *handle) {
		ERR("memory allocation failed");
		goto exit;
	}

	(*handle)->fd = open(TUN_DEV, O_RDWR);
	if (0 > (*handle)->fd) {
		ERR("open tun device: %s failed. error: %s.", TUN_DEV, strerror(errno));
		goto exit;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	if (0 != ioctl((*handle)->fd, TUNSETIFF, &ifr)) {
		ERR("ioctl failed. error: %s.", strerror(errno));
		goto exit;
	}

	strncpy((*handle)->name, ifr.ifr_name, IFNAMSIZ);

	if (0 != set_if_params(*handle, address, netmask, mtu)) {
		goto exit;
	}

	ret = 0;
exit:
	if (0 != ret) {
		pingtun_tun_fini(handle);
	}
	return ret;
}

int pingtun_tun_fd(pingtun_tun_t *handle) {
	return handle->fd;
}

const char *pingtun_tun_name(pingtun_tun_t *handle) {
	return handle->name;
}

ssize_t pingtun_tun_read(pingtun_tun_t *handle, void *buf, size_t len) {
	ssize_t ret = read(handle->fd, buf, len);
	if (0 > ret) {
		ERR("failed read tun. error: %s.", strerror(errno));
	}
	return ret;
}
ssize_t pingtun_tun_write(pingtun_tun_t *handle, const void *buf, size_t len) {
	ssize_t ret = write(handle->fd, buf, len);
	if (0 > ret) {
		ERR("failed write tun. error: %s.", strerror(errno));
	}
	return ret;
}

void pingtun_tun_fini(pingtun_tun_t **handle) {
	if (NULL == *handle) {
		return;
	}

	close((*handle)->fd);
	free(*handle);
	*handle = NULL;
}

