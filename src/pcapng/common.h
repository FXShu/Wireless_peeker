#ifndef PCAPNG_COMMON_H
#define PCAPNG_COMMON_H

#include "../utils/common.h"

#ifndef PCAP_VERSION_MINOR
#define PCAP_VERSION_MINOR 4
#endif

#ifndef PCAP_VERSION_MAJOR
#define PCAP_VERSION_MAJOR 2
#endif


#define DLT_IEEE802_11_RADIO 127
#define TCPDUMP_MAGIC 0xa1b2c3d4
#define ANSII_CHECK 0x0a0d0d0a
#define INTERFACE_BLOCK_TYPE 0x00000001
#define ENHANCED_BLOCK_TYPE 0x00000006
#define USER_APP_INFOMATION "WIRELESS_PEEK_MARK"

/* section option code */
#define SECTION_HW_CODE 0x0002
#define SECTION_OS_CODE 0x0003
#define SECTION_USER_APP_CODE 0x0004

/* interface option code */
#define INTERFACE_NAME 0x0002
#define INTERFACE_DESCRIPTION 0x0003
#define INTERFACE_IPV4_ADDR 0x0004
#define INTERFACE_IPV6_ADDR 0x0005
#define INTERFACE_MAC 0x0006
#define INTERFACE_EUI_ADDR 0x0007
#define INTERFACE_SPEED 0x0008
#define INTERFACE_TSACCUR 0x0009
#define INTERFACE_TZONE 0x000A
#define INTERFACE_FILTER 0x000B
#define INTERFACE_OS 0x000c
#define FILL_IN(x) (4 - (strlen((x))%4))

#endif /* PCAPNG_COMMON_H */
