#ifndef PINGTUN_PING_H
#define PINGTUN_PING_H (1)

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/icmp.h>
#include <linux/ip.h>

#define MTU			(1500)

typedef struct {
	int 			fd;
	unsigned char 	*packet[MTU];
	struct iphdr 	*ip_header;
	struct icmphdr	*icmp_header;
	void			*data;
} pingtun_ping_t;

int pingtun_ping_init(pingtun_ping_t **handle);
int pingtun_ping_fd(pingtun_ping_t *handle);
ssize_t pingtun_ping_rpl(pingtun_ping_t *handle, const void *buf, size_t len,
		const struct sockaddr_in *dest_addr);
ssize_t pingtun_ping_req(pingtun_ping_t *handle, const void *buf, size_t len,
		const struct sockaddr_in *dest_addr);
ssize_t pingtun_ping_rcv(pingtun_ping_t *handle, const struct icmphdr **header,
		const void **data, struct sockaddr_in *src_addr);
void pingtun_ping_fini(pingtun_ping_t **handle);

#ifdef __cplusplus
}
#endif

#endif
