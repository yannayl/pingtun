#ifndef PINGTUN_TUN_H
#define PINGTUN_TUN_H (1)

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>

typedef struct {
	char name[IFNAMSIZ];
	int fd;
} pingtun_tun_t;

int pingtun_tun_init(pingtun_tun_t **handle);
int pingtun_tun_fd(pingtun_tun_t *handle);
const char *pingtun_tun_name(pingtun_tun_t *handle);
ssize_t pingtun_tun_read(pingtun_tun_t *handle, void *buf, size_t len);
ssize_t pingtun_tun_write(pingtun_tun_t *handle, const void *buf, size_t len);
void pingtun_tun_fini(pingtun_tun_t **handle);

#ifdef __cplusplus
}
#endif

#endif
