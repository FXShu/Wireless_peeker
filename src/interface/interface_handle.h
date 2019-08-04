#ifndef INTERFACE_HANDLE_H
#define INTERFACE_HANDLE_H
#include "common.h"


int handle_interface_add(struct nl80211_state *state, struct nl_msg *msg,
			int argc, char **argv, enum id_input id) ; 
#endif /* INTERFACE_HANDLE_H */
