#ifndef MITM_H
#define MITM_H

#include "include.h"
#include "common.h"
#ifndef MITM_CTRL_DIR
#define MITM_CTRL_DIR "/tmp/MITM"
#endif /* MITM_CTRL_DIR */

#ifndef MITM_CTRL_IFNAME 
#define MITM_CTRL_IFNAME "MITM_server_local"
#endif /* MITM_CTRL_IFNAME */

#ifndef MITM_CTRL_PATH
#define MITM_CTRL_PATH MITM_CTRL_DIR "/" MITM_CTRL_IFNAME
#endif /* MITM_CTRL_PATH */

#ifndef MITM_CTRL_PATH
#define MITM_CTRL_PATH MITM_CTRL_DIR "/" MITM_CTRL_IFNAME
#endif /* MITM_CTRL_PATH */
enum usr_dev_type {
	ethernet,
	wireless,
};

enum MITM_state {
	MITM_state_idle = 0,
	MITM_state_ap_search,  /* Only use when device type is wireless. */
	MITM_state_capture_handshake, /* Only use when device type is wireless. */
	MITM_state_crash_PTK, /* Only use when device type is wireless. */
	MITM_state_ready,
	MITM_state_spoofing,
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
	enum usr_dev_type dev_type;
	char* monitor_dev;
	pcap_if_t* if_buf;
	pcap_if_t* monitor_buf;
	struct l2_packet_data *l2_packet;
	struct dl_list ap_list;  //used to foreach access_point_info array.
	struct encrypto_info encry_info;
	enum MITM_state state;
	char* dict_path;
};

struct MITM_info {
	enum MITM_state state;
};

int MITM_init(struct MITM *MITM);

int MITM_deinit(struct MITM *MITM);

#endif /* MITM_H */

