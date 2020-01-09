#ifndef MITM_COMMON_H
#define MITM_COMMON_H
#define FAIL -1
#define SUCCESS 0

typedef enum{
	false =0,
	true =1
}bool;
#include <linux/if_ether.h>
#include "include.h"
#include "arp.h"
#include "sniffer.h"
#include "getif.h"
#include "./src/utils/common.h"
#include "./src/utils/eloop.h"
#include "./src/interface/iw_implement.h"
#include "./src/crypto/crypto.h"
#include "./src/l2_packet/l2_packet.h"
#define MAX_IPV4_LEN 16
#define MAX_MAC_LEN 17
#define BUFFER_LEN 2048

#endif /* MITM_COMMON_H */
