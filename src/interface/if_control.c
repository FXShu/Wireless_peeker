#include "if_control.h"

int if_up (char *if_name) {
	int sockfd;
	struct ifreq ifr;
	int res = 0;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd < 0) {
		log_printf(MSG_ERROR, "%s,%d: socket create failed!", __func__, __LINE__);
		return -1;
	}
	memset(&ifr, 0, sizeof(struct ifreq));

	strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

	ifr.ifr_flags |= IFF_UP;
	res = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	if (res < 0) {
		log_printf(MSG_ERROR, "Interface %s: Error: SIOCSIFFLAGS failed: %s",
			       	if_name, strerror(errno));
		return -1;
	}
	return 0;
}
