#ifndef __PEEK_IFACE_H__
#define __PEEK_IFACE_H__

#include "wireless_peek.h"

/***
 * peek_iface_setup_flags - setup interface flags via ioctl
 *
 * @param this: global variable
 * @param iface: name of specify interface
 * @param flags: interface flag, reference "include/net/if.h"
 *
 * @return: 0 on success, -1 when error occur.
 */
int peek_iface_setup_flags(struct wireless_peek *this, const char *iface, short flags);

/***
 * peek_iface_clean_flags - clean interface flags via ioctl
 *
 * @param this: global variable
 * @param iface: name of specify interface
 * @param flags: interface flag, reference "include/net/if.h"
 *
 * @return: 0 on success, -1 when error occur.
 */
int peek_iface_clean_flags(struct wireless_peek *this, const char *iface, short flags);

/***
 * peek_system_init - initial system info and establish connection with kernel.
 *
 * @param this: global variable
 *
 * @return: 0 on success, -1 when error occur.
 */
int peek_system_init(struct wireless_peek *this);

/***
 * peek_get_all_wiphy - get wiphy information via netlink.
 *
 * @param this: global variable
 *
 * @return: 0 on success, -1 when error occur.
 */
int peek_get_all_wiphy(struct wireless_peek *this);

/***
 * peek_create_new_interface - create new regular VAP.
 *
 * @param this: global variable.
 * @param type: type of VAP.
 * @param phy: specific phy.
 *
 * @return: 0 on success, -1 when error occur.
 *
 */
int peek_create_new_interface(struct wireless_peek *this, enum nl80211_iftype type, struct wiphy *phy);

/***
 * peek_create_monitor_iface - create a monitor type VAP.
 *   for performance consider, calling this function when create monitor VAP
 *   instead of peek_create_new_interface.
 *
 * @param this: global variable.
 *
 * @return: 0 on success, -1 when error occur.
 */
int peek_create_monitor_iface(struct wireless_peek *this);

#endif /* __PEEK_IFACE_H__ */
