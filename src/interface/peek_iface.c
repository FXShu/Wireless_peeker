#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include "common.h"
#include "peek_iface.h"
#include "peek_netlink.h"
#include "peek_iface_common.h"

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

int peek_iface_clean_flags(struct wireless_peek *this, const char *iface, short flags) {
	struct ifreq ifr;

	if (!iface || this->comm_list.system.ioctl < 0) {
		log_printf(MSG_ERROR, "[%s]: invalid parameter\n", __func__);
		return -1;
	}

	strncpy(ifr.ifr_name, iface, IFNAMSIZ);
	if (ioctl(this->comm_list.system.ioctl, SIOCGIFFLAGS, &ifr) < 0) {
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

static int parse_family_id(struct nlattr **tb, void *user_data) {
	struct nl_family *family = (struct nl_family *)user_data;
	if (!tb || !tb[CTRL_ATTR_FAMILY_ID] || !tb[CTRL_ATTR_FAMILY_NAME]) {
		log_printf(MSG_WARNING, "[%s]: necessary attribute not available\n", __func__);
		return -1;
	}
	if (!strncmp(family->name, (char *)NLA_DATA(tb[CTRL_ATTR_FAMILY_NAME]), GENL_NAMSIZ)) {
		family->id = *(u16 *)NLA_DATA(tb[CTRL_ATTR_FAMILY_ID]);
		log_printf(MSG_DEBUG, "[%s]: generic netlink family %s, id %d\n",
			__func__, family->name, family->id);
	}

	return 0;
}

static int get_genetlink_family_id(struct wireless_peek *this, struct nl_family *family) {
	int ret = -1;
	struct nlmsghdr *hdr;
	struct nlattr* tb[CTRL_ATTR_MAX];
	char *payload;
	int len = MAX_PAYLOAD;

	memset(tb, 0, CTRL_ATTR_MAX);
	if (!this || !family) {
		log_printf(MSG_ERROR, "[%s]: invalid parameter\n", __func__);
	}
	hdr = peek_alloc_generic_packet(GENL_ID_CTRL, NLM_FLAG_ROOT,
		0, 0, CTRL_CMD_GETFAMILY);
	if (!hdr) {
		log_printf(MSG_ERROR, "[%s]: alloc netlink message header fail\n", __func__);
		return -1;
	}

	len -= (NLMSG_HDRLEN + GENL_HDRLEN);
	payload = GENL_DATA(NLMSG_DATA(hdr));
	peek_netlink_put_str(&payload, &len, CTRL_ATTR_FAMILY_NAME, family->name);

	hdr->nlmsg_len = MAX_PAYLOAD - len;
	if (peek_netlink_send(this->comm_list.system.genl_sock, hdr, NETLINK_GENERIC))
		goto fail;

	ret = peek_netlink_recv(this->comm_list.system.genl_sock, tb, parse_family_id, family);
//	ret = peek_netlink_recv(this->comm_list.system.genl_sock, tb, parse_family_id, family);
fail:
	if (hdr)
		free(hdr);
	return ret;
}

static int peek_genl_net_init(struct wireless_peek *this) {
	struct sockaddr_nl addr;

	memset(&addr, 0, sizeof(struct sockaddr_nl));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	addr.nl_groups = NETLINK_GENERIC;

	this->comm_list.system.genl_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (this->comm_list.system.genl_sock < 0) {
		log_printf(MSG_ERROR, "[%s]: create scoket to communicate with netlink kernel fail"
			",error: %s\n", __func__, strerror(errno));
		return -1;
	}
	/* release fd when global destory */
	if (bind(this->comm_list.system.genl_sock, (struct sockaddr *)&addr,
		sizeof(struct sockaddr_nl))) {
		log_printf(MSG_ERROR, "[%s]: bind socket fail, error %s\n", __func__, strerror(errno));
		return -1;
	}

	strcpy(this->info.nl80211.name, "nl80211");

	get_genetlink_family_id(this, &this->info.nl80211);
	if (this->info.nl80211.id < 0)
		return -1;
	return 0;
}

int peek_system_init(struct wireless_peek *this) {
	if (peek_genl_net_init(this))
		return -1;
	return 0;
}

static char *get_interface_type(enum nl80211_iftype type) {
	switch(type) {
	case NL80211_IFTYPE_ADHOC:
		return "adhoc";
	break;
	case NL80211_IFTYPE_STATION:
		return "station";
	break;
	case NL80211_IFTYPE_AP:
		return "ap";
	break;
	case NL80211_IFTYPE_AP_VLAN:
		return "vlan";
	break;
	case NL80211_IFTYPE_WDS:
		return "wds";
	break;
	case NL80211_IFTYPE_MONITOR:
		return "monitor";
	break;
	case NL80211_IFTYPE_MESH_POINT:
		return "mesh";
	break;
	case NL80211_IFTYPE_P2P_CLIENT:
		return "p2p client";
	break;
	case NL80211_IFTYPE_P2P_GO:
		return "p2p go";
	break;
	case NL80211_IFTYPE_P2P_DEVICE:
		return "p2p device";
	break;
	case NL80211_IFTYPE_UNSPECIFIED:
	default:
		return "unkonw";
	}
}

static int get_all_wiphy_cb(struct nlattr **tb, void *user_data) {
	struct wireless_peek *this = (struct wireless_peek *)user_data;
	struct wiphy *phys = this->info.phys;
	struct wiphy *previous = NULL;
	if (!tb || tb[NL80211_CMD_UNSPEC]) {
		log_printf(MSG_WARNING, "[%s]: error netlink request format\n", __func__);
	}

	if (!tb || !tb[NL80211_ATTR_WIPHY] || !tb[NL80211_ATTR_WIPHY_NAME]) {
		log_printf(MSG_WARNING, "[%s]: necessary attribute not available\n", __func__);
		return -1;
	}

	while(phys) {
		if (!strcmp(phys->name, (char *)NLA_DATA(tb[NL80211_ATTR_WIPHY_NAME])))
			break;
		previous = phys;
		phys = phys->next;
	}

	if (!phys) {
		phys = malloc(sizeof(struct wiphy));
		memset(phys, 0 ,sizeof(struct wiphy));
		assert(phys);
		strcpy(phys->name, (char *)NLA_DATA(tb[NL80211_ATTR_WIPHY_NAME]));
		if (previous)
			previous->next = phys;
		else
			this->info.phys = phys;
	}
	phys->id = *(u32 *)NLA_DATA(tb[NL80211_ATTR_WIPHY]);
	if (tb[NL80211_ATTR_SUPPORTED_IFTYPES])
		phys->iftype_sup = *(u16 *)NLA_DATA(tb[NL80211_ATTR_SUPPORTED_IFTYPES]);
	return 0;
}

int peek_get_all_wiphy(struct wireless_peek *this) {
	struct nlmsghdr *hdr;
	struct nlattr *tb[NL80211_ATTR_MAX];
	char *payload;
	int len = MAX_PAYLOAD;
	int ret = -1;
	memset(&tb, 0, NL80211_ATTR_MAX);
	hdr = peek_alloc_generic_packet(this->info.nl80211.id,
		NLM_FLAG_DUMP, 1, 0, NL80211_CMD_GET_WIPHY);
	if (!hdr) {
		log_printf(MSG_WARNING, "[%s]: alloc netlink message header fail\n", __func__);
		return -1;
	}
	len -= (NLMSG_HDRLEN + GENL_HDRLEN);
	payload = GENL_DATA(NLMSG_DATA(hdr));
	/* tb[NL80211_ATTR_WIPHY] = 0, don't filter any phy instant. */
	peek_netlink_put_u32(&payload, &len, NL80211_ATTR_WIPHY, 0);
	hdr->nlmsg_len = MAX_PAYLOAD - len;
	if (peek_netlink_send(this->comm_list.system.genl_sock, hdr, NETLINK_GENERIC))
		goto fail;
	ret = peek_netlink_recv(this->comm_list.system.genl_sock, tb, get_all_wiphy_cb, this);
fail:
	if (hdr)
		free(hdr);
	return ret;
}

int peek_get_interfaces_by_phy(struct wireless_peek *this, netlink_cb cb) {
	struct nlmsghdr *hdr;
	struct nlattr *tb[NL80211_ATTR_MAX];
	int len = MAX_PAYLOAD;
	int ret = -1;

	hdr = peek_alloc_generic_packet(this->info.nl80211.id,
		NLM_FLAG_DUMP, 0, 0, NL80211_CMD_GET_INTERFACE);
	if (!hdr) {
		log_printf(MSG_WARNING, "[%s]: alloc netlink message header fail\n", __func__);
		return -1;
	}
	len -= (NLMSG_HDRLEN + GENL_HDRLEN);
	hdr->nlmsg_len = MAX_PAYLOAD - len;
	if (peek_netlink_send(this->comm_list.system.genl_sock, hdr, NETLINK_GENERIC))
		goto fail;
	ret = peek_netlink_recv(this->comm_list.system.genl_sock, tb, cb, this);
fail:
	if (hdr)
		free(hdr);
	return ret;
}

static struct wiphy *phy_candidate_select(struct wireless_peek *this) {
	struct wiphy *phys;
	struct wiphy *candidate = NULL;
	phys = this->info.phys;
	if (!this) {
		log_printf(MSG_WARNING, "[%s]: invalid parameter\n", __func__);
		return NULL;
	}
	while(phys) {
		if (phys->iftype_sup & BIT(NL80211_IFTYPE_MONITOR)) {
			if(!candidate)
				candidate = phys;
			if (phys->iftype_sup & BIT(NL80211_IFTYPE_MESH_POINT)) {
				candidate = phys;
				break;
			}
		}
		phys = phys->next;
	}
	return candidate;
}

static int check_monitor_iface_existed(struct nlattr **tb, void *user_data) {
	struct wireless_peek *this = (struct wireless_peek *)user_data;
	struct wireless_iface *iface, *previous;

	if (!tb || !tb[NL80211_ATTR_WIPHY] || !tb[NL80211_ATTR_IFNAME] ||
		!tb[NL80211_ATTR_IFTYPE] || !tb[NL80211_ATTR_IFINDEX]) {
		log_printf(MSG_WARNING, "[%s]: necessary attribute not available\n", __func__);
		return -1;
	}
	iface = this->info.ifaces;
	while(iface) {
		if (strncmp(iface->name, (char *)NLA_DATA(tb[NL80211_ATTR_IFNAME]), IFNAMSIZ))
			break;
		previous = iface;
		iface = iface->next;
	}
	if(!iface) {
		iface = malloc(sizeof(struct wireless_iface));
		memset(iface, 0, sizeof(struct wireless_iface));
		strcpy(iface->name, (char *)NLA_DATA(tb[NL80211_ATTR_IFNAME]));
		previous->next = iface;
	}
	iface->id = *(u32 *)NLA_DATA(tb[NL80211_ATTR_IFINDEX]);
	iface->type = *(u32 *)NLA_DATA(tb[NL80211_ATTR_IFTYPE]);
	iface->phy = peek_iface_search_wiphy_by_id(this, *(u32 *)NLA_DATA(tb[NL80211_ATTR_WIPHY]));

	if (*(u32 *)NLA_DATA(tb[NL80211_ATTR_IFTYPE]) == NL80211_IFTYPE_MONITOR) {
		strcpy(this->config.monitor_dev, (char *)NLA_DATA(tb[NL80211_ATTR_IFNAME]));
		this->status.sniffer_iface = iface;
		return *(u32 *)NLA_DATA(tb[NL80211_ATTR_IFINDEX]);
	}
	return 0;
}

int peek_create_new_interface(struct wireless_peek *this, enum nl80211_iftype type,
	struct wiphy *phy, netlink_cb cb) {
	struct nlmsghdr *hdr;
	struct nlattr *tb[NL80211_ATTR_MAX];
	char *payload;
	int len = MAX_PAYLOAD;
	int ret = -1;

	hdr = peek_alloc_generic_packet(this->info.nl80211.id,
		NLM_FLAG_CREATE, 0, 0, NL80211_CMD_NEW_INTERFACE);
	if (!hdr) {
		log_printf(MSG_WARNING, "[%s]: alloc netlink message header fail\n", __func__);
		return -1;
	}
	len -= (NLMSG_HDRLEN + GENL_HDRLEN);
	payload = GENL_DATA(NLMSG_DATA(hdr));
	peek_netlink_put_u32(&payload, &len, NL80211_ATTR_WIPHY, phy->id);
	peek_netlink_put_u32(&payload, &len, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);
	peek_netlink_put_str(&payload, &len, NL80211_ATTR_IFNAME, this->config.monitor_dev);
	hdr->nlmsg_len = MAX_PAYLOAD - len;
	if (peek_netlink_send(this->comm_list.system.genl_sock, hdr, NETLINK_GENERIC))
		goto fail;
	peek_netlink_recv(this->comm_list.system.genl_sock, tb, cb, this);
	ret = 0;
fail:
	if (hdr)
		free(hdr);
	return ret;
}

int peek_create_monitor_iface(struct wireless_peek *this) {
	int ret;

	if (!this) {
		log_printf(MSG_ERROR, "[%s]: invalid parameter\n", __func__);
		return -1;
	}

	this->status.phy = phy_candidate_select(this);
	if (!this->status.phy) {
		log_printf(MSG_ERROR, "[%s]: no wireless device support monitor mode available\n",
			__func__);
		return -1;
	}
	ret = peek_get_interfaces_by_phy(this, check_monitor_iface_existed);
	/* check monitor VAP existed. */
	if (ret > 0) {
		/* monitor device is already existed. */
		log_printf(MSG_DEBUG, "[%s]: monitor VAP %s is existed\n",
			__func__, this->config.monitor_dev);
	} else if (ret == 0) {
		/* monitor device not existed, create new interface */
		peek_create_new_interface(this, NL80211_IFTYPE_MONITOR,
			this->status.phy, check_monitor_iface_existed);
		log_printf(MSG_DEBUG, "[%s]: create new interface %s, type %s\n", __func__,
			this->config.monitor_dev, get_interface_type(NL80211_IFTYPE_MONITOR));
	} else {
		/* query interface information fail. */
		log_printf(MSG_WARNING, "[%s]: query interface information fail\n", __func__);
		return -1;
	}
	return 0;
}
