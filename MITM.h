#ifndef MITM_H
#define MITM_H

#include "include.h"
#include "common.h"

struct ap_list {
	struct ap_list *next;
	struct ap_list *prev;
	char *BSSID;
	u8 MAC[ETH_ALEN];
	u8 channel;
};

/***
 * struct MITM
 * the structure is used to stored the glabal data
 * dev_info
 * 	store IP address and MAC address of gateway, attacker and target
 * user_dev
 * 	capute packet on this interface
 * monitor_dev
 * 	derive from user_dev, use to capute any packet even not associate the AP,
 * 	only use if the user_dev is a wireless interface
 **/
struct MITM {
	sni_info dev_info;
	char errbuf[PCAP_ERRBUF_SIZE];
	char* usr_dev;
	char* monitor_dev;
	pcap_if_t* if_buf;
	pcap_if_t* monitor_buf;
	struct l2_packet_data *l2_packet;
	struct ap_list *ap_list;
};

int MITM_init(struct MITM *MITM);


int MITM_deinit(struct MITM *MITM);
#endif /* MITM_H */

