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
	log_printf(MSG_INFO, "Thanks for using mitm_cli");
}

static void usage(void) {
	log_printf(MSG_INFO, "mitm_ctrl v1.0\n"
		       	     "usage: mitm_ctrl [-p<path>] [-G<keep alive interval>]\n");
}

char const *mitm_get_state(enum MITM_state state) {
	switch(state) {
		case MITM_state_idle:
			return "IDLE";
		case MITM_state_ap_search:
			return "Searching for available AP";
		case MITM_state_capture_handshake:
			return "Capturing handshake packet";
		case MITM_state_crash_PTK:
			return "Crashing PTK";
		case MITM_state_ready:
			return "Ready for Man-In-The_Middle attack";
		case MITM_state_spoofing:
			return "Attacking";
		default:
			return "Unknow";
	}
}

static void hello() {
	log_printf(MSG_INFO, 
			"-----------------------------------------------------------------------\n"
			"| Welcome to MITM Comman Line.                                        |\n"
			"| This program is used to show how the Man-IN-THE-MIDDLE work.        |\n"
			"| Please notice that if you execute this process                      |\n"
			"| to peer otherone's network taffic is illegal.                       |\n"
			"----------------------------------------------------------------------");
	STORE_CURSOR_POSITION();
}

static void get_mitm_state(void *eloop_ctx, void *user_ctx) {
	int *interval = (int *)eloop_ctx;
	struct mitm_ctrl *ctrl = (struct mitm_ctrl *) user_ctx;
	mitm_ctrl_request(ctrl, MITM_GET_STATUS_REQUEST, sizeof(MITM_GET_STATUS_REQUEST));
	eloop_register_timeout(*interval, 0, get_mitm_state, interval, ctrl);
}

static char* sort_input_out(char *input) {
	char command[BUFFER_LEN];
	memset(command, 0, BUFFER_LEN);
	int opt = 0, first_delim = 1, new_option = 0;
	int offset;
	opt = atoi(input);
	if (opt == 0 || opt > mitm_get_action_num()) return NULL;
	for (int num = 0; num < mitm_get_action_num();num++) {
		if(opt == msg_handler[num].number) {
			strcpy(command, msg_handler[num].command);
			new_option = 1;
			break;
		}
	}
	offset = strlen(command);
	if (!offset) return NULL;
	for (int i = log10(opt) + 1; i < strlen(input); i++) {
		if ((input[i] == ' ' || input[i] == '\t' || input[i] == ',') && new_option) {
			strcat(command, first_delim? "?": "&");
			offset ++;
			first_delim = 0;
			new_option = 0;
		} else if (input[i] == '=') {
			strcat(command, "=");
			offset++;
		} else if (input[i] == '\r' || input[i] == '\n'){
			/* ignore those character.*/
		}else {
			command[offset++] = input[i];
			new_option = 1;
		}
	}
	return strdup(command);
}

void print_options(int sig) {
	RECOVER_CURSOR_POSITION();
	DELETE_MULTIPLE_LINE(100);
	log_printf(MSG_INFO, "MITM at "YELLOW"\"%s\""NONE" state, please choose below action.", 
		mitm_get_state(info.state));
	for (int i = 0; i < mitm_get_action_num(); i++) {
		if (!(msg_handler[i].header > info.state) && !(msg_handler[i].tail < info.state))
			log_printf(MSG_INFO, "[%d]%s", msg_handler[i].number, msg_handler[i].prompt);
	}
	printf("\n");
}

void handle_user_input(int sock, void *eloop_ctx, void *sock_ctx) {
	char buffer[BUFFER_LEN];
	char *command;
	memset(buffer, 0, BUFFER_LEN);
	struct mitm_ctrl *ctrl = (struct mitm_ctrl *)sock_ctx;
	fgets(buffer, BUFFER_LEN, stdin);
	do {
		command = sort_input_out(buffer);
		if (!command) {
			log_printf(MSG_WARNING, "Wrong Input format!");
			break;
		}
		mitm_ctrl_request(ctrl, command, strlen(command));
		free(command);
	} while(0);
	print_options(-1);
}

int main(int argc, char **argv) {
	int c;
	struct mitm_ctrl *ctrl;
	char *mitm_ctrl_path;
	int ask_mitm_state_interval = 3;
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
