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
	void 			*packet;
	size_t 			packet_size;
	ssize_t			len;
} pingtun_ping_t;

typedef enum {
	PINGTUN_PING_FILTER_ECHO,
	PINGTUN_PING_FILTER_ECHOREPLY,
	PINGTUN_PING_FILTER_MAX,
} pingtun_ping_filter_e;

int pingtun_ping_init(pingtun_ping_t **handle, pingtun_ping_filter_e filter);
int pingtun_ping_fd(pingtun_ping_t *handle);
size_t pingtun_ping_mtu(pingtun_ping_t *handle);
void *pingtun_ping_data(pingtun_ping_t *handle);
size_t pingtun_ping_capacity(pingtun_ping_t *handle);
size_t pingtun_ping_len(pingtun_ping_t *handle);
int pingtun_ping_len_set(pingtun_ping_t *handle, size_t len);
int pingtun_ping_rpl(pingtun_ping_t *handle,
		const struct sockaddr_in *dest_addr);
int pingtun_ping_req(pingtun_ping_t *handle,
		const struct sockaddr_in *dest_addr);
int pingtun_ping_rcv(pingtun_ping_t *handle, struct sockaddr_in *src_addr);
void pingtun_ping_fini(pingtun_ping_t **handle);

#ifdef __cplusplus
}
#endif

#endif
