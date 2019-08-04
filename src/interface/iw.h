#ifndef __IW_H
#define __IW_H

#include "include.h"
#include "nl80211.h"

#ifndef ETH_ALEN 
#define ETH_ALEN 6
#endif /* ETH_ALEN */

struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;	
};

enum command_identify_by {
	CIB_NONE,
	CIB_PHY,
	CIB_NETDEV,
	CIB_WDEV,
};

enum id_input {
	II_NONE,
	II_NETDEV,
	II_PHY_NAME,
	II_PHY_IDX,
	II_WDEV,
};

struct cmd {
	const char *name;
	const char *args;
	const enum nl80211_commands cmd;
	int nl_msg_flags;
	int hidden;
	const enum command_identify_by idby;

	int (*handler)(struct nl80211_state *state, struct nl_msg *msg,
			int argc, char **argv, enum id_input id);
	//const struct cmd *(*selector)(int argc, char **argv);
};
#endif /* __IW_H */
