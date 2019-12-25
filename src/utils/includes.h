/**
 * This header file is included into all C files so that commonly uesd header
 * files can be selected with OS specific ifdef blocks in one place instead of 
 * having to have OS/C library specific selection in many files.
 */
#ifndef UTILS_INCLUDES_H
#define UTILS_INCLUDES_H

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <linux/if_ether.h>
#ifndef _WIN32_WCE
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#endif /* _WIN_32_WCE */
#include <ctype.h>
#include <math.h>
#ifndef _MSC_VER  //use to define translater version in mircosoft 
#include <unistd.h>
#endif /* _MSC_VER */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#ifndef __vxworks
#include <sys/uio.h>
#include <sys/time.h>
#include <time.h>
#endif /* __vxworks */

#endif /* UTILS_INCLUDES_H */
