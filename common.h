#ifndef COMMON_H
#define COMMON_H
#define FAIL -1
#define SUCCESS 0

typedef enum{
	false =0,
	true =1
}bool;
#include "./src/utils/common.h"
#include "./src/utils/print.h"
#include "./src/utils/head.h"
#include "./src/utils/eloop.h"

#define MAX_IPV4_LEN 16
#define MAX_MAC_LEN 17
#endif
