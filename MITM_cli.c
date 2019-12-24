#include "MITM_cli.h"

#ifndef MITM_CTRL_DIR
#define MITM_CTRL_DIR "/tmp/MITM"
#endif /* MITM_CTRL_DIR */

#ifndef MITM_CLI_DIR
#define MITM_CLI_DIR "/tmp/MITM"
#endif /* MITM_CLI_DIR */

int debug_level;
extern struct MITM_ctrl_msg msg_handler[];
struct MITM_info info;

static void mitm_client_terminate(int sig, void *signal_ctx) {
	struct mitm_ctrl *ctrl = (struct mitm_ctrl *)signal_ctx;
	struct mitm_ctrl fuckyou;
	eloop_terminate();
	unlink(ctrl->local.sun_path);
	free(ctrl);
	log_printf(MSG_INFO, "thanks for using mitm_cli");
}

static void usage(void) {
	log_printf(MSG_INFO, "mitm_ctrl v1.0\n"
		       	     "usage: mitm_ctrl [-p<path>] [-G<keep alive interval>]\n");
}

static void hello() {
	log_printf(MSG_INFO, 
			"-----------------------------------------------------------------------\n"
			"| Welcome to MITM Comman Line.                                        |\n"
			"| This program is used to show how the Man-IN-THE-MIDDLE work.        |\n"
			"| Please notice that if you execute this process                      |\n"
			"| to peer otherone's network taffic is illegal.                       |\n"
			"----------------------------------------------------------------------");
}

static void get_ap_list(struct mitm_ctrl *ctrl) {
	mitm_ctrl_request(ctrl, MITM_GET_AP_LIST_REQUEST, sizeof(MITM_GET_AP_LIST_REQUEST));
	return;
}

static void get_mitm_state(void *eloop_ctx, void *user_ctx) {
	int *interval = (int *)eloop_ctx;
	struct mitm_ctrl *ctrl = (struct mitm_ctrl *) user_ctx;
	mitm_ctrl_request(ctrl, MITM_GET_STATUS_REQUEST, sizeof(MITM_GET_STATUS_REQUEST));
	eloop_register_timeout(*interval, 0, get_mitm_state, interval, ctrl);
}

int parse_command (char* buffer, char ) {
	int opt;
	for(int i = 0; i < BUFFER_LEN; i++) {
		if (buffer[i] == '\0') break;
		if (*buffer >= '0' && *buffer <= '9')
			opt=atoi(buffer);
		buffer++;
	}
}

void handle_user_input(int sock, void *eloop_ctx, void *sock_ctx) {
	char buffer[BUFFER_LEN];
	int opt;
	memset(buffer, 0, BUFFER_LEN);
	struct mitm_ctrl *ctrl = (struct mitm_ctrl *)sock_ctx;
	fgets(buffer, BUFFER_LEN, stdin);
	opt = atoi(buffer);
	for (int i = 0; i < mitm_get_action_num(); i++) {
		if (opt == msg_handler[i].number) {
			mitm_ctrl_request(ctrl, msg_handler[i].command, 
					strlen(msg_handler[i].command));
		}	
	}
}

void print_options(int sig) {
	log_printf(MSG_INFO, "MITM state in %s state, please choose below action.");
	for (int i = 0; i < mitm_get_action_num(); i++) {
		if (!(msg_handler[i].header > info.state) && !(msg_handler[i].tail < info.state)) {
			log_printf(MSG_INFO, "[%d]%s", msg_handler[i].number, 
					msg_handler[i].prompt);
		}
	}
}

int main(int argc, char **argv) {
	int c;
	struct mitm_ctrl *ctrl;
	char *mitm_ctrl_path;
	int ask_mitm_state_interval = 1;
	/* used to communicate with UI(web, cli...) */
	char *ctrl_ifname = NULL;
	/* if true, use terminal to control MITM binary */
	info.state = 0;

	for (;;) {
		c = getopt(argc, argv, "hp:G:i:d:");
		if (c < 0) break;
		switch(c) {
		case 'h':
			usage();
			return 0;
		case 'p':
			mitm_ctrl_path = strdup(optarg);
			break;
		case 'i':
			ctrl_ifname = strdup(optarg);
			break;
		case 'd':
			debug_level = atoi(optarg);
			break;
		default:
			usage();
			return 0;
		}
	}

	if (eloop_init())  
		return -1;

	ctrl = mitm_ctrl_open2((MITM_CTRL_PATH), MITM_CLI_DIR, &info);
	if (!ctrl) { 
		log_printf(MSG_ERROR, "init control interface client failed");
		return -ENOMEM;
	}
	RESET_CURSOR();
	CLEAR_SCREEN();
	hello();
	signal(SIGUSR1, print_options);
	eloop_register_timeout(ask_mitm_state_interval, 0, get_mitm_state, 
			&ask_mitm_state_interval, ctrl);
	eloop_register_signal_terminate(mitm_client_terminate, ctrl);
	eloop_register_read_sock(0, handle_user_input, NULL, ctrl);
	eloop_run();			
}
