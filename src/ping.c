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
#include "ping.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>


#define pingtun_ping_icmphdr(handle) \
	((struct icmphdr *) ((handle)->packet + sizeof(struct iphdr)))

#define pingtun_ping_iphdr(handle) \
	((struct iphdr *) (handle)->packet)


static uint16_t checksum_rfc1701(void *data, size_t len) {
	/* copied from http://tools.ietf.org/html/rfc1071 */
	uint32_t sum = 0;
	uint16_t tmp = 0;
    while (len > 1) {
		sum += * (uint16_t *) data;
		data += sizeof(uint16_t);
		len -= 2;
	}

     /*  Add left-over byte, if any */
	if(len > 0) {
		*((uint8_t *) &tmp) = * (uint8_t *) data; 
		sum += tmp;
	}

	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	
	return ~sum;
}

static int pingtun_ping_sendto(pingtun_ping_t *handle,
		const struct sockaddr_in *dest_addr) {
	int ret = -1;
	
	handle->len += sizeof(struct icmphdr);
	pingtun_ping_icmphdr(handle)->checksum = 0;
	pingtun_ping_icmphdr(handle)->checksum = checksum_rfc1701(
			pingtun_ping_icmphdr(handle), handle->len);

	handle->len = sendto(handle->fd, pingtun_ping_icmphdr(handle), handle->len,
			0, (const struct sockaddr *) dest_addr, sizeof(*dest_addr));
	
	if (0 > handle->len) {
		ERR("sendto failed. error: %s.", strerror(errno));
		goto exit;
	}
	
	ret = 0;

exit:
	handle->len = 0;
	return ret;
}

static int set_filter(pingtun_ping_t *handle, pingtun_ping_filter_e fid) {
	int ret = -1;
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, 0), /* load IP data offset */
		BPF_STMT(BPF_LD|BPF_B|BPF_IND, 0), /* load icmp type */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ICMP_ECHOREPLY, 0, 3), /* correct type? */
		BPF_STMT(BPF_LD|BPF_H|BPF_IND, 4), /* load icmp echo identity */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ntohs(handle->id), 0, 1), /* ours? */
		BPF_STMT(BPF_RET|BPF_K, 0xffff), /* accept. */
		BPF_STMT(BPF_RET|BPF_K, 0), /* reject */
	};
	struct sock_fprog prog = {
		.len = sizeof(filter) / sizeof(*filter),
		.filter = filter
	};

	switch (fid) {
		case PINGTUN_PING_FILTER_ECHO:
			filter[2].k = ICMP_ECHO;
			break;
		default:
			break;
	}

	if (0 != setsockopt(handle->fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog,
				sizeof(prog))) {
		ERR("failed attaching filter");
		goto exit;
	}
	ret = 0;
exit:
	return ret;
}

int pingtun_ping_init(pingtun_ping_t **handle, pingtun_ping_filter_e filter,
		uint16_t id) {
	int ret = -1;

	*handle = calloc(1, sizeof(pingtun_ping_t));
	if (NULL == *handle) {
		ERR("handle memory allocation failed");
		goto exit;
	}
	
	(*handle)->packet = calloc(1, MTU);
	if (NULL == *handle) {
		ERR("packet memory allocation failed");
		goto exit;
	}
	(*handle)->packet_size = MTU;

	(*handle)->fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (0 > (*handle)->fd) {
		ERR("opening socket failed. error: %s.", strerror(errno));
		goto exit;
	}

	(*handle)->id = htons(id);
	(*handle)->seq = rand();
	
	if (0 != set_filter(*handle, filter)) {
		goto exit;
	}


	ret = 0;
exit:
	if (0 != ret) {
		pingtun_ping_fini(handle);
	}
	return ret;
}

int pingtun_ping_fd(pingtun_ping_t *handle) {
	return handle->fd;
}

void *pingtun_ping_data(pingtun_ping_t *handle) {
	void *data = handle->packet + sizeof(struct iphdr) + sizeof(struct icmphdr);
	return data;
}

int pingtun_ping_len_set(pingtun_ping_t *handle, size_t len) {
	if (len > pingtun_ping_capacity(handle)) {
		ERR("len out of buf");
		return -1;
	}
	handle->len = len;
	return 0;
}

size_t pingtun_ping_capacity(pingtun_ping_t *handle) {
	return handle->packet_size - sizeof(struct icmphdr) - sizeof(struct iphdr);
}

size_t pingtun_ping_len(pingtun_ping_t *handle) {
	return handle->len;
}

int pingtun_ping_rpl(pingtun_ping_t *handle) {
	struct sockaddr_in dest = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr = {
			.s_addr = pingtun_ping_iphdr(handle)->saddr,
		}
	};

	pingtun_ping_icmphdr(handle)->type = ICMP_ECHOREPLY;
	return pingtun_ping_sendto(handle, &dest);
}

int pingtun_ping_req(pingtun_ping_t *handle,
		const struct sockaddr_in *dest_addr) {
	pingtun_ping_icmphdr(handle)->type = ICMP_ECHO;
	pingtun_ping_icmphdr(handle)->un.echo.id = handle->id;
	pingtun_ping_icmphdr(handle)->un.echo.sequence = handle->seq;
	handle->seq += 1;
	return pingtun_ping_sendto(handle, dest_addr);
}

int pingtun_ping_rcv(pingtun_ping_t *handle) {
	int ret = -1;
	size_t ip_header_size = 0;
	
	handle->len = recvfrom(handle->fd, handle->packet, handle->packet_size, 0,
			NULL, 0);

	if (0 > handle->len) {
		ERR("failed receiving. error: %s.", strerror(errno));
		goto exit;
	}

	if (sizeof(struct iphdr) > handle->len) {
		ERR("received packet is too small for ip");
		goto exit;
	}
	
	ip_header_size = pingtun_ping_iphdr(handle)->ihl;
	ip_header_size <<= 2;
	if (ip_header_size > handle->len) {
		ERR("received packet is too small for ip header size");
		goto exit;
	}

	handle->len -= ip_header_size;

	if (sizeof(struct iphdr) < ip_header_size) {
		DBG("memmove");
		memmove(pingtun_ping_icmphdr(handle),
				handle->packet + ip_header_size, handle->len);
	}
	
	if (sizeof(struct icmphdr) > handle->len) {
		ERR("received packet is too small from icmp");
		goto exit;
	}

	handle->len -= sizeof(struct icmphdr);
	ret = 0;
exit:
	if (0 != ret) {
		handle->len = 0;
	}
	return ret;
}

void pingtun_ping_fini(pingtun_ping_t **handle) {
	if (NULL == *handle) {
		return;
	}

	close((*handle)->fd);
	free((*handle)->packet);
	free(*handle);
	*handle = NULL;
}

