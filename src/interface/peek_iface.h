#ifndef __PEEK_IFACE_H__
#define __PEEK_IFACE_H__


/* reference "include/linux/nl80211.h" */
enum peek_nl80211_iftype {
	PEEK_NL80211_IFTYPE_UNSPECIFIED,
	PEEK_NL80211_IFTYPE_ADHOC,
	PEEK_NL80211_IFTYPE_STATION,
	PEEK_NL80211_IFTYPE_AP,
	PEEK_NL80211_IFTYPE_AP_VLAN,
	PEEK_NL80211_IFTYPE_WDS,
	PEEK_NL80211_IFTYPE_MONITOR,
	PEEK_NL80211_IFTYPE_MESH_POINT,
	PEEK_NL80211_IFTYPE_P2P_CLIENT,
	PEEK_NL80211_IFTYPE_P2P_GO,
	PEEK_NL80211_IFTYPE_P2P_DEVICE,
	
	/* keep last */
	PEEK_NUM_NL80211_IFTYPES,
	PEEK_NL80211_IFTYPE_MAX = NUM_NL80211_IFTYPES - 1
};

/***
 * peek_iface_setup_flags - setup interface flags via ioctl
 *
 * @param iface: name of specify interface
 * @param flags: interface flag, reference "include/net/if.h"
 *
 * @return: 0 on success, -1 when error occur.
 */
int peek_iface_setup_flags(const char *iface, short flags);

/***
 * peek_iface_clean_flags - clean interface flags via ioctl
 *
 * @param iface: name of specify interface
 * @param flags: interface flag, reference "include/net/if.h"
 *
 * @return: 0 on success, -1 when error occur.
 */
int peek_iface_clean_flags(const char *iface, short flags);

/***
 * peek_iface_add_by_dev - add new virtual interface base on device name.
 *
 * @param dev: name of specify device.
 * @param iface: name of new virtual interface.
 * @param type: new interface type.
 *
 * @return: 0 on success, -1 when error occur.
 */
int peek_iface_add_by_dev(const char *dev, const char *iface, enum peek_nl800211_iftype type);

/***
 * peek_iface_add_by_phy - add new virtual interface base on phy id.
 *
 * @param phy: id of specify phy.
 * @param iface: name of new virtual interface.
 * @param type: new interface type.
 *
 * @return: 0 on success, -1 when error occur.
 */
int peek_iface_add_by_phy(int phy, const char *iface, enum peek_nl80211_iftype type);
#endif /* __PEEK_IFACE_H__ */
