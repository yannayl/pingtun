#include "pingtun.h"
#include "ping.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

static void icmp_header_init(struct icmphdr *header) {
	header->type = ICMP_ECHO;
	header->un.echo.id = rand();
	header->un.echo.sequence = rand();
}

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

static int ensure_buf_within_packet(const pingtun_ping_t *handle,
		const void *buf, size_t len) {

	if (buf < handle->packet + sizeof(struct icmphdr)) {
		ERR("start buf out of range. buf = %p, packet = %p.",
				buf, handle->packet);
		return -1;
	}
	
	if (buf + len >= handle->packet + handle->packet_size) {
		ERR("end buf out of range. end buf = %p, end packet = %p.",
				buf + len, handle->packet + handle->packet_size);
		return -1;
	}

	return 0;
}

static ssize_t pingtun_ping_sendto(pingtun_ping_t *handle, uint8_t icmp_type,
		const void *buf, size_t len, const struct sockaddr_in *dest_addr) {
	
	struct icmphdr *icmp_header_dest = NULL;

	if (0 != ensure_buf_within_packet(handle, buf, len)) {
		return -1;
	}
	icmp_header_dest = ((void *) buf) - sizeof(struct icmphdr);

	if (handle->packet_size - sizeof(struct icmphdr) < len) {
		len = handle->packet_size - sizeof(struct icmphdr);
	}

	memmove(icmp_header_dest, handle->icmp_header, sizeof(struct icmphdr));
	handle->icmp_header = icmp_header_dest;

	len += sizeof(struct icmphdr);

	handle->icmp_header->type = icmp_type;
	handle->icmp_header->checksum = 0;
	
	handle->icmp_header->checksum = checksum_rfc1701(handle->icmp_header, len);

	return sendto(handle->fd, handle->icmp_header, len, 0,
			(const struct sockaddr *) dest_addr, sizeof(*dest_addr));
}

int pingtun_ping_init(pingtun_ping_t **handle) {
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

	(*handle)->ip_header = (*handle)->packet;
	(*handle)->icmp_header = (*handle)->packet;
	(*handle)->data = (*handle)->packet + sizeof(struct icmphdr);

	icmp_header_init((*handle)->icmp_header);

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

size_t pingtun_ping_mtu(pingtun_ping_t *handle) {
	return handle->packet_size - sizeof(struct iphdr) - sizeof(struct icmphdr);
}

void *pingtun_ping_data(pingtun_ping_t *handle, size_t *len) {
	*len = handle->packet_size - sizeof(struct icmphdr);
	return handle->packet + sizeof(struct icmphdr);
}

ssize_t pingtun_ping_rpl(pingtun_ping_t *handle, const void *buf, size_t len,
		const struct sockaddr_in *dest_addr) {
	return pingtun_ping_sendto(handle, ICMP_ECHOREPLY, buf, len, dest_addr);
}

ssize_t pingtun_ping_req(pingtun_ping_t *handle, const void *buf, size_t len,
		const struct sockaddr_in *dest_addr) {
	handle->icmp_header->un.echo.sequence += 1;
	return pingtun_ping_sendto(handle, ICMP_ECHO, buf, len, dest_addr);
}
ssize_t pingtun_ping_rcv(pingtun_ping_t *handle, const struct icmphdr **header,
		const void **data, struct sockaddr_in *src_addr) {
	socklen_t size = sizeof(*src_addr);
	void *ptr = handle->packet;
	size_t ip_header_size = 0;
	ssize_t len = recvfrom(handle->fd, handle->packet, handle->packet_size,
			0, (struct sockaddr *) src_addr, &size);

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
	free((*handle)->packet);
	free(*handle);
	*handle = NULL;
}

