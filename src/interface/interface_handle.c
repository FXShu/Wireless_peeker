#include "interface_handle.h"

static int get_if_type(char **argv, enum nl80211_iftype *type, bool need_type) {
	char *tpstr;
/*
	if (need_type && strcmp((*argv)[0], "type"))
		return -1;
	tpstr = (*argv)[!!need_type];
*/
	log_printf(MSG_DEBUG, "%s,%d: %s", __func__, __LINE__, *argv);
	if(need_type) {
		if (strcmp(*argv++, "type")) {
			return -1;
		} else {
			log_printf(MSG_DEBUG, "%s,%d: = %s", __func__, __LINE__, *argv);
			tpstr = *argv;
		}
	} else {
		tpstr = *argv;
	}

	if (!strcmp(tpstr, "adhoc")  ||!strcmp(tpstr, "ibss")) {
		*type = NL80211_IFTYPE_ADHOC;
		return 0;
	} else if (!strcmp(tpstr, "ocb")) {
		*type = NL80211_IFTYPE_OCB;
		return 0;
	} else if (!strcmp(tpstr, "monitor")) {
		*type = NL80211_IFTYPE_MONITOR;
		return 0;
	} else if (!strcmp(tpstr, "master") || !strcmp(tpstr, "ap")) {
		*type = NL80211_IFTYPE_UNSPECIFIED;
		log_printf(MSG_INFO, "you need to run a management daemon, e.g hostapd"
					"see http://wireless.kernel.org/en/users/Document/hostpad"
					"for more information on how to do that");
		return 0;
	} else if (!strcmp(tpstr, "__ap")) {
		*type = NL80211_IFTYPE_AP;
		return 0;
	} else if (!strcmp(tpstr, "__ap_vlan")) {
		*type = NL80211_IFTYPE_AP_VLAN;
		return 0;
	} else if (!strcmp(tpstr, "wds")) {
		*type = NL80211_IFTYPE_WDS;
		return 0;
	} else if (!strcmp(tpstr, "managed") || !strcmp(tpstr, "mgd") || !strcmp(tpstr, "station")){
		*type = NL80211_IFTYPE_STATION;
		return 0;
	} else if (!strcmp(tpstr, "mp")) {
		*type = NL80211_IFTYPE_MESH_POINT;
		return 0;
	} else if (!strcmp(tpstr, "__p2pcl")) {
		*type = NL80211_IFTYPE_P2P_CLIENT;
		return 0;
	} else if (!strcmp(tpstr,"__p2pdev")) {
		*type = NL80211_IFTYPE_P2P_DEVICE;
		return 0;
	} else if (!strcmp(tpstr, "__p2pgo")) {
		*type = NL80211_IFTYPE_P2P_GO;
		return 0;
	}

	return -1;
}
/**
 * char** argv need to be 
 * and the parameter argc is useless
 * but I think maybe oneday will use it
 * so I decide to keep it up
 * command in here maybe like mon0 type monitor...
 * */
int handle_interface_add(struct nl80211_state *state, struct nl_msg *msg, 
			int argc, char **command, enum id_input id) {
	char *name;
	//char *mesh_id = NULL;
	enum nl80211_iftype type;
	//unsigned char mac_addr[ETH_ALEN];
	//int found_mac = 0;

	log_printf(MSG_DEBUG, "%s,%d: new interface's name is %s", __func__, __LINE__, *command);

	name = *command;
	command ++;
	if(get_if_type( command, &type, true)) {
		log_printf(MSG_ERROR, "Invaild interface type:%s", *command);
		return -1;	
	}

	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, name);
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, type);
	
	return 0;
}
