#include <stdio.h>
#include "wireless_peek.h"
#include "peek_iface.h"
int debug_level;

int main(int argc, char **argv) {
	struct wireless_peek peeker;
	struct wiphy *phys;
	debug_level = MSG_DEBUG;
	memset(&peeker, 0, sizeof(struct wireless_peek));
	peek_system_init(&peeker);
	peek_get_all_wiphy(&peeker);
	phys = peeker.info.phys;
	while(phys) {
		log_printf(MSG_DEBUG, "[%s]: phy %s, id %d, type %d\n", __func__, phys->name, phys->id, phys->iftype_sup);
		phys = phys->next;
	}
	close(peeker.comm_list.system.genl_sock);
}
