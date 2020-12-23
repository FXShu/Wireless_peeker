#ifndef __WIRELESS_PEEK_NL80211_H__
#define __WIRELESS_PEEK_NL80211_H__
#include <string.h>
#include <errno.h>
#include "nl80211.h"

extern int debug_level;
struct nl80211_state *state;

int wireless_peeek_nl80211_change_beacon() {
	struct nl_msg *msg;
	msg = nlmsg_alloc();
	if (!msg) {
		log_printf(MSG_ERROR, "[%s] alloc memory fail, error %s\n", __func__, strerror(errno));
		return -1;
	}
	/* add generic netlink header */
	genlmsg_put(msg, 0, 0, )
}

static void wireless_peek_nl80211_recv_cb(int sock, void *eloop_ctx, void *sock_ctx) {

}

int wireless_peek_nl80211_init(struct MITM* this) {
	int sock;
	struct sockaddr_nl addr;

	memset(&addr, 0, sizeof(struct sockaddr_nl));
	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock) {
		log_printf(MSG_ERROR, "[%s]: create netlink socket fail, error %s\n",
			__func__, strerror(errno))
		return -1;
	}

	addr.nl_family = AF_NETLINK;
	addr.nl_groups = NL80211_MCGRP_MLME 
	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr))) {
		log_printf(MSG_ERROR, "[%s]: bind netlink fail, error %s\n", __func__, __LINE__);
		goto fail;
	}
	eloop_register_read_sock(sock, wireless_peek_nl80211_recv_cb, NULL, this);
	return 0;
fail:
	close(sock);
}

#endif /* __WIRELESS_PEEK_NL80211_H__ */
