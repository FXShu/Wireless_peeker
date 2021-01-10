#include <stdio.h>
#include "wireless_peek.h"
#include "peek_iface.h"
int debug_level;

int main(int argc, char **argv) {
	struct wireless_peek peeker;

	debug_level = MSG_DEBUG;

	peek_system_init(&peeker);
}
