#ifndef __PEEK_IFACE_COMMON_H__
#define __PEEK_IFACE_COMMON_H__

/***
 * peek_iface_search_wiphy_by_id - search phy by specific id.
 *
 * @param this: global variable.
 * @param id: specific id.
 *
 * @return: pointer to phy which match specific id, or NULL if not found.
 */
struct wiphy *peek_iface_search_wiphy_by_id(struct wireless_peek *this, u32 id);
#endif /* __PEEK_IFACE_COMMON_H__ */
