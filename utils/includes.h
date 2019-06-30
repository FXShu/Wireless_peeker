/**
 * This header file is included into all C files so that commonly uesd header
 * files can be selected with OS specific ifdef blocks in one place instead of 
 * having to have OS/C library specific selection in many files.
 */

#ifndef INCLUDES_H
#define INCLUDEs_H

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#ifndef _WIN32_WCE
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#endif /* _WIN_32_WCE */
#include <ctype.h>

#ifndef _MSC_VER  //use to define translater version in mircosoft 
#include <unistd.h>
#endif /* _MSC_VER */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef __vxworks
#include <sys/uio.h>
#include <sys/time.h>

#endif /* INCLUDES_H */
