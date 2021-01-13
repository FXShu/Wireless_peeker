#include <sys/types.h>
#include <sys/socket.h>

#include "common.h"
int peek_sniffer_init(struct wireless_peek *this) {
	struct sockaddr_ll addr;

	if (!this) {
		log_printf(MSG_ERROR, "[%s]: invalid parameter\n");
		return -1;
	}

	this->comm_list.sniffer_sock = socket(PF_PACKET, SOCK_RAW, ETH_P_ALL);
	if (this->comm_list.sniffer_sock < 0) {
		log_printf(MSG_ERROR, "[%s]: register raw socket to %s interface fail, error %s\n",
			__func__, this->config.monitor_dev, strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family = PF_PACKET;
	addr.sll_ifindex = ;
	addr.sll_protocol = htons(ETH_P_ALL);
}
