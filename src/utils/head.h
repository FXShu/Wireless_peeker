#ifndef HEAD_H
#define HEAD_H

/* ethernet type */

#define EPT_IPv4 0x0800
#define EPT_IPv6 0x86dd
#define EPT_ARP  0x0806
#define EPT_RARP 0x8035

/* protocol type */
#define PROTOCOL_ICMP 0x01
#define PROTOCOL_IGMP 0x02
#define PROTOCOL_TCP  0x06
#define PROTOCOL_UDP  0x11

/* address length */
#define MAC_ADDR_LEN 6
#define IPv4_ADDR_LEN 4
#define IPv6_ADDR_LEN 8

/* arp option */
#define ARP_REPLY 2
#define ARP_REQURST 1

/* ethernet head */
typedef struct {
	unsigned char DST_mac[6];
	unsigned char SRC_mac[6];
	unsigned short eth_type;
} ethernet_header;
/* ARP packet head */
typedef struct {
	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char  hardware_len;
	unsigned char  protocol_len;
	unsigned short option;
	unsigned char src_mac[6];
	unsigned char src_ip[4];
	unsigned char dest_mac[6];
	unsigned char dest_ip[4];
} arp_header;

typedef struct {
	unsigned char  version_head;
	unsigned char  type_of_service;
	unsigned short packet_len;
	unsigned short packet_id;
	unsigned short slice_info;
	unsigned char  TTL;
	unsigned char  protocol_type;
	unsigned short check_sum;
	unsigned char  src_ip[4];
	unsigned char  dest_ip[4];
} ip_header;

typedef struct {
	unsigned short sour_port;
	unsigned short dest_port;
	unsigned int   sequ_num;
	unsigned int   ackn_num;
	unsigned short header_len_flag;
	unsigned short window;
	unsigned short check_sum;
	unsigned short surg_point;
} tcp_header;

/*this defined is come from netinet/udp.h */
typedef struct{
	unsigned short sour_port;
	unsigned short dest_port;
	unsigned short header_len_flag;
	unsigned short check_sum;
}udp_header;

#endif
