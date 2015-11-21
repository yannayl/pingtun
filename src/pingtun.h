#ifndef PINGTUN_H
#define PINGTUN_H (1)

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#define LOG(format, ...)\
	do { fprintf(stderr, "%s:%d: " format "\n", __FILE__, __LINE__, ##__VA_ARGS__); } while (0)

#define ERR(format, ...)\
	LOG("ERR: " format, ##__VA_ARGS__)

#define DBG(format, ...)\
	LOG("DBG: " format, ##__VA_ARGS__)

#define D() DBG("here")

#ifdef __cplusplus
}
#endif

#endif
