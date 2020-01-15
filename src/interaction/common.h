#ifndef INTERACTION_COMMON_H
#define INTERACTION_COMMON_H
#include "include.h"

struct mitm_recv_info {
	int sock_fd;
	int send_flags;
	struct sockaddr_un recv_from;
	socklen_t length;
};
#endif /* INTERACTION_COMMON_H */
