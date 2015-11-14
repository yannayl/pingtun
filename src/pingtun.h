#ifndef PINGTUN_H
#define PINGTUN_H (1)

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#define LOG(format, ...)\
	do { fprintf(stderr, format "\n", ##__VA_ARGS__); } while (0)

#define ERR(format, ...)\
	LOG("ERR: " format, ##__VA_ARGS__)

#define DBG(format, ...)\
	LOG("DBG: " format, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
