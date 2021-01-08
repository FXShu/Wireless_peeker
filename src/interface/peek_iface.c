#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include "print.h"

int peek_iface_setup_flags(struct wireless_peek *this, const char *iface, short flags) {
	struct ifreq ifr;

	if (!iface || this->comm_list.system.ioctl < 0) {
		log_printf(MSG_ERROR, "[%s]: invalid parameter\n", __func__);
		return -1;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ);
	ifr.ifr_flags = flags;
	if (ioctl(this->comm_list.system.ioctl, SIOCSIFFLAGS, &ifr) < 0) {
		log_printf(MSG_ERROR, "[%s]: %s setup flags fail\n", __func__, iface);
		return -1;
	}
	return 0;
}

int peek_iface_setup_flags(struct wireless_peek *this, const char *iface, short flags) {
	struct ifreq ifr;

	if (!iface || this->comm_list.system.ioctl < 0) {
		log_printf(MSG_ERROR, "[%s]: invalid parameter\n", __func__);
		return -1;
	}

	strncpy(ifr.ifr_name, iface, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		log_printf(MSG_ERROR, "[%s]: %s setup flags fail\n", __func__, iface);
		return -1;
	}

	strncpy(ifr.ifr_name, iface, IFNAMSIZ);
	ifr.ifr_flags &= ~flags;
	ifr.ifr_flags = flags;
	if (ioctl(this->comm_list.system.ioctl, SIOCSIFFLAGS, &ifr) < 0) {
		log_printf(MSG_ERROR, "[%s]: %s setup flags fail\n", __func__, iface);
		return -1;
	}
	return 0;
}

static int get_genetlink_family_id(struct wireless_peek *this) {
	struct nlmsghdr *hdr;
	struct genlmsghdr *ghdr;
	int len;
	struct msghdr message;

	hdr = malloc(NLMSG_SPACE(MAX_PAYLOAD));
	if (!hdr) {
		log_printf(MSG_ERROR, "[%s]: memory alloc fail\n", __func__);
		return -1;
	}
	memset(hdr, 0, NLMSG_SPACE(MAX_PAYLOAD));
	memset(&message, 0, sizeof(struct msghdr));
	len = MAX_PAYLOAD;
	/* get family id */
	hdr->nlmsg_type = GENL_ID_CTRL;
	hdr->nlmsg_flags = NLM_F_ROOT | NLM_F_ATOMIC; 
	hdr->nlmsg_seq = 0;
	hdr->nlmsg_pid = getpid();
	len -= NLMSG_HDRLEN;

	ghdr = NLMSG_DATA(hdr);
	ghdr->cmd = CTRL_CMD_GETFAMILY;
	ghdr->version = 1;
	len -= GENL_HDRLEN;
	peek_netlink_put_str((char *)(ghdr + GENL_HDRLEN), &len, CTRL_ATTR_FAMILY_NAME, "nl80211");
	hdr->nlmsg_len = MAX_PAYLOAD - len;
	if (peek_netlink_send(this, hdr))
		goto fail;
	/* TODO : receive kernel response and resolute family id from packet .*/
	recvmsg(this->comm_list.genl_net.sock, &message, sizeof(struct msghdr) < 0) {
		log_printf(MSG_ERROR, "[%s]: recv message fail, error %s\n",
			__func__, strerror(errno));
		goto fail;
	}

	if (hdr)
		free(hdr);
	return 0;
fail:
	if (hdr)
		free(hdr);
	return -1;
}

static int peek_genl_net_init(struct wireless_peek *this) {
	struct sockaddr_nl addr;

	memset(&addr, 0, sizeof(struct sockaddr_nl));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	addr.nl_groups = NETELINK_GENERIC;

	this->comm_list.genl_net.sock = socket(PF_NETLINK, SOCK_RAW, NTELINK_GENERIC);
	if (this->comm_list.genl_net.sock < 0) {
		log_printf(MSG_ERROR, "[%s]: create scoket to communicate with netlink kernel fail"
			",error: %s\n", __func__, strerror(errno));
		return -1;
	}
	/* release fd when global destory */
	if (bind(this->comm_list.genl_net.sock, &addr, sizeof(struct sockaddr_nl))) {
		log_printf(MSG_ERROR, "[%s]: bind socket fail, error %s\n", __func__, strerror(errno));
		return -1;
	}
	if (get_genetlink_family_id(this))
		return -1;
	return 0;
}

int peek_system_init(struct wireless_peek *this) {
	if (peek_genl_net_init(this))
		return -1;
	return 0;
}

static char *get_interface_type_name(enum peek_nl80211_iftype type) {
	switch(type) {
	case PEEK_NL80211_IFTYPE_ADHOC:
		return "adhoc";
	break;
	case PEEK_NL80211_IFTYPE_STATION:
		return "station";
	break;
	case PEEK_NL80211_IFTYPE_AP:
		return "ap";
	break;
	case PEEK_NL80211_IFTYPE_AP_VLAN:
		return "vlan";
	break;
	case PEEK_NL80211_IFTYPE_WDS:
		return "wds";
	break;
	case PEEK_NL80211_IFTYPE_MONITOR:
		return "monitor";
	break;
	case PEEK_NL80211_IFTYPE_MESH_POINT:
		return "mesh";
	break;
	case PEEK_NL80211_IFTYPE_P2P_CLIENT:
		return "p2p client";
	break;
	case PEEK_NL80211_IFTYPE_P2P_GO:
		return "p2p go";
	break;
	case PEEK_NL80211_IFTYPE_P2P_DEVICE:
		return "p2p device";
	break;
	case PEEK_NL80211_IFTYPE_UNSPECIFIED:
	default:
		return "unkonw";
	}
}

int peek_iface_add_by_dev(struct wireless_peek *this, const char *dev,
	const char *iface, enum peek_nl80211_iftype type) {
	struct nl_msg *msg;

	if (!dev || !iface) {
		log_printf(MSG_ERROR, "[%s]: invalid parameter\n", __func__);
		return -1;
	}
	log_printf(MSG_DEBUG, "[%s]: add new virtual interface %s, type %s\n",
		__func__, iface, get_interface_type_name(type));
	msg = nlmsg_alloc();
	if (!msg) {
		log_printf(MSG_ERROR, "[%s]: out of memory\n", __func__);
		return -1;
	}
	/* add netlink header */
	genlmsg_put(msg, 0, 0, this->comm_list.system.nl80211.id)
}

int peek_iface_add_by_phy(int phy, const char *iface, enum peek_nl80211_iftype type) {
