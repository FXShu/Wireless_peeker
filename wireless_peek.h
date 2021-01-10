#ifndef __WIRELESS_PEEK_HH__
#define __WIRELESS_PEEK_HH__

#include "common.h"
#include "crypto.h"

#ifndef WIRELESS_PEEK_CTRL_DIR
#define WIRELESS_PEEK_CTRL_DIR "/tmp/wireless_peek"
#endif /* WIRELESS_PEEK_CTRL_DIR */

#ifndef WIRELESS_PEEK_CTRL_IFNAME 
#define WIRELESS_PEEK_CTRL_IFNAME "wireless_peek_server_local"
#endif /* WIRELESS_PEEK_CTRL_IFNAME */

#ifndef WIRELESS_PEEK_CTRL_PATH
#define WIRELESS_PEEK_CTRL_PATH WIRELESS_PEEK_CTRL_DIR "/" WIRELESS_PEEK_CTRL_IFNAME
#endif /* WIRELESS_PEEK_CTRL_PATH */

enum wireless_peek_state {
	wireless_peek_state_idle = 0,
	wireless_peek_state_ap_search,  /* Only use when device type is wireless. */
	wireless_peek_state_capture_handshake, /* Only use when device type is wireless. */
	wireless_peek_state_crash_PTK, /* Only use when device type is wireless. */
	wireless_peek_state_ready,
	wireless_peek_state_spoofing,
};

/***
 * wireless_peek_config - wireless peeker configuration restore
 *
 * @member user_dev :
 * 	capute packet on this interface.
 * @member monitor_dev :
 * 	derive from user_dev, monitor type interface,
 * 	only use if the user_dev is a wireless interface
 * @member dict_path :
 *	path of password dictionary.
 * @member pcapng_path :
 *	path of decrypted packet restore (as pcapng format).
 */
struct wireless_peek_config {
	char* usr_dev;
	char* monitor_dev;
	char* dict_path;
	char *packet_path;
};

/***
 * genl_net - generic netlink family information.
 *
 * @member sock - socket of generic netlink
 * @member 80211_family - family ID of nl80211 module
 */
struct genl_net {
	int sock;
	int family_nl80211;
};

/***
 * peek_system - structure used to communicate with kernel
 *
 * @member ioctl: ioctl socket.
 * @member genl: communicate with kernel via generic netlink
 */
struct peek_system {
	int ioctl;
	struct genl_net genl;
}; 

/***
 * wireless_peek_comm_list - IPC list of wireless peeker
 *
 * @member ctrl: communicate with peeker ctrl.
 * @member kernel: communicate with kernel.
 */
struct wireless_peek_comm_list {
//	struct peek_ctrl ctrl;
	struct peek_system system;
};

struct wireless_peek_status {
	enum wireless_peek_state state;
	FILE *loots;
};

/***
 * struct wireless_peek
 * the structure is used to stored the glabal data
 * @member config: configuration restore.
 * @member comm_list: IPC list of wireless peeker
 * @member l2_packet :
 * @member ap_list :
 *	list of access pointer around.
 * @member encry_info :
 *	structure used to record target ap information.
 * @member state :
 *	state machine of wireless_peek
 **/
struct wireless_peek {
	struct wireless_peek_config config;
	struct wireless_peek_comm_list comm_list;
	struct wireless_peek_status status;
	struct l2_packet_data *l2_packet;
	struct dl_list ap_list;  //used to foreach access_point_info array.
	struct encrypto_info encry_info;
	enum wireless_peek_state state;

};

struct wireless_peek_info {
	enum wireless_peek_state state;
};

int wireless_peek_init(struct wireless_peek *this, char *iface, char *dict, char *database);

int wireless_peek_deinit(struct wireless_peek *this);

#endif /* __WIRELESS_PEEK_HH__ */

