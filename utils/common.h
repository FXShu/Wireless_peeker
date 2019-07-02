#ifndef COMMON_H
#define CPMMON_H

#include "os.h"

#if defined(__linux__) || defined(__GLIBC__)
#include <endian.h>
#include <byteswap.h>
#endif /*  __linux__ */

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || \
	defined(__OpenBSD__)
#include <sys/type.h>
#include <sys/endian.h>

