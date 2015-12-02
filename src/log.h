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
#ifndef LOG_H
#define LOG_H (1)

#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>

#define LOG(format, ...)\
	do { fprintf(stderr, "%s:%d:%s: " format "\n", __FILE__, __LINE__,\
			__func__, ##__VA_ARGS__); } while (0)

#define ERR(format, ...)\
	LOG("ERR: " format, ##__VA_ARGS__)

#define DBG(format, ...)\
	LOG("DBG: " format, ##__VA_ARGS__)

#define D() DBG("here")

#ifdef __cplusplus
}
#endif

#endif
