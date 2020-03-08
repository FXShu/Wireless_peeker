#ifndef PRINTF_H
#define PRINTF_H
#include "includes.h"
#include "head.h"

#define CLEAR_SCREEN() printf("\033[2J")
#define RESET_CURSOR() printf("\033[H")
#define RED "\033[0;32;31m"
#define YELLOW "\033[1;33m"
#define NONE "\033[m"
#define SET_CURSOR_POSITION(x) printf("\033["#x";0H")
#define CLEAR_LINE_FROM_CURSOR_POSITION() printf("\033[K")
#define DELETE_MULTIPLE_LINE(x) printf("\033["#x"M")
#define STORE_CURSOR_POSITION() printf("\033[s")
#define RECOVER_CURSOR_POSITION() printf("\033[u")
#define CURSOR_UP_LINE(x) printf("\033["#x"A");
enum {
	MSG_EXCESSIVE,
	MSG_MSGDUMP,
	MSG_DEBUG,
	MSG_INFO,
	MSG_WARNING,
	MSG_ERROR
};

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif /* ETH_ALEN */

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#define IPv42STR(a) (a)[0], (a)[1], (a)[2], (a)[3]
#define IPv4STR "%d.%d.%d.%d"

#define PRINTF_MALLOC_ERROR log_printf(MSG_ERROR, "%s,%d: malloc failed by %s", \
					__func__, __LINE__, strerror(errno)); return NULL

//typedef unsigned char u_char;
char* ip4tostring(char*,unsigned char*);

char* mactostring(char*,unsigned char*);

void print_ip(unsigned char* ip);

void println_ip(unsigned char* ip);

void print_mac(unsigned char* mac);

void println_mac(unsigned char* mac);

void print_type(unsigned short type);

void print_protocol(unsigned char protocol_type);

void log_printf(int level,char* format,...);

void copy_mac_address(uint8_t *src, uint8_t *dst);

void lamont_hdump(int level, const char* title, const unsigned char *bp, unsigned int length);
#endif
