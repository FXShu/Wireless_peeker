#include "wireless_peek.h"

struct wiphy *peek_iface_search_wiphy_by_id(struct wireless_peek *this, u32 id) {
	struct wiphy *phy;
	phy = this->info.phys;

	while(phy) {
		if (phy->id == id)
			break;
	}
	return phy;
}

