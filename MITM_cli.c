#include "./src/utils/common.h"
#include "MITM_cli.h"
static register_command_sock(){
	
}

static void usage(void) {
	
}

int main(int argc, char **argv) {
	int c;

	for (;;) {
		c = getopt(argc, argv, "h");
		if (c < 0) break;
		switch(c) {
		case h:
			usage();
			return 0;
			break;
		}
	}
	eloop_init();

	int sockfd;
}
