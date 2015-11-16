#include "pingtun.h"
#include "ping.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

static uint16_t checksum_rfc1701(void *data, size_t len) {
	/* copied from http://tools.ietf.org/html/rfc1071 */
	uint32_t sum = 0;
    while (len > 1) {
		sum += * (uint16_t *) data;
		data += sizeof(uint16_t);
		len -= 2;
	}

     /*  Add left-over byte, if any */
	if(len > 0) {
		sum += * (uint8_t *) data;
	}

	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	
	return ~sum;
}

int pingtun_ping_init(pingtun_ping_t **handle) {
	int ret = -1;

	*handle = calloc(1, sizeof(pingtun_ping_t));
	if (NULL == *handle) {
		ERR("memory allocation failed");
		goto exit;
	}

	(*handle)->fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (0 > (*handle)->fd) {
		ERR("opening socket failed. error: %s.", strerror(errno));
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

ssize_t pingtun_ping_rpl(pingtun_ping_t *handle, const void *buf, size_t len,
		const struct sockaddr_in *dest_addr) {
	if (sizeof(handle->packet) - sizeof(struct icmphdr) < len) {
		len = sizeof(handle->packet) - sizeof(struct icmphdr);
	}

	if (buf != handle->data) {
		memmove(handle->packet, handle->icmp_header, sizeof(struct icmphdr));
		handle->icmp_header = (struct icmphdr *) handle->packet;
		handle->data = handle->packet + sizeof(struct icmphdr);
		memcpy(handle->data, buf, len);
	}

	len += sizeof(struct icmphdr);

	handle->icmp_header->type = ICMP_ECHOREPLY;
	handle->icmp_header->checksum = 0;
	
	handle->icmp_header->checksum = checksum_rfc1701(handle->icmp_header, len);

	return sendto(handle->fd, handle->packet, len, 0, (const struct sockaddr *) dest_addr,
			sizeof(*dest_addr));
}

ssize_t pingtun_ping_req(pingtun_ping_t *handle, const void *buf, size_t len,
		const struct sockaddr_in *dest_addr) {
	// TODO: implement
	return -1;
}
ssize_t pingtun_ping_rcv(pingtun_ping_t *handle, const struct icmphdr **header,
		const void **data, struct sockaddr_in *src_addr) {
	socklen_t size = sizeof(*src_addr);
	void *ptr = handle->packet;
	size_t ip_header_size = 0;
	ssize_t len = recvfrom(handle->fd, &(handle->packet), sizeof(handle->packet), 0,
			(struct sockaddr *) src_addr, &size);

	//TODO: verify the returned address is sockaddr_in
	if (0 > len) {
		ERR("failed receiving. error: %s.", strerror(errno));
		return len;
	}
	if (sizeof(struct iphdr) > len) {
		ERR("received packet is too small for ip");
		return -1;
	}
	handle->ip_header = (struct iphdr *) ptr;
	ip_header_size = handle->ip_header->ihl << 2;
	if (ip_header_size > len) {
		ERR("received packet is too small for ip header size");
		return -1;
	}
	len -= ip_header_size;
	ptr += ip_header_size;

	if (sizeof(struct icmphdr) > len) {
		ERR("received packet is too small from icmp");
		return -1;
	}
	*header = handle->icmp_header = ptr;
	len -= sizeof(struct icmphdr);
	ptr += sizeof(struct icmphdr);
	*data = ptr;

	return len;
}

void pingtun_ping_fini(pingtun_ping_t **handle) {
	if (NULL == *handle) {
		return;
	}

	close((*handle)->fd);
	free(*handle);
	*handle = NULL;
}

