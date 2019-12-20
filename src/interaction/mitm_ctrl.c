#ifdef CONFIG_CTRL_IFACE
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h> // fcntl - manipulate file descriptor
#endif /* CONFIG_CTRL_IFACE */
#include "mitm_action.h"
#include "mitm_ctrl.h"



#ifndef CONFIG_CTRL_IFACE_CLIENT_DIR
#define CONFIG_CTRL_IFACE_CLIENT_DIR "/tmp"
#endif /* CONFIG_CTRL_IFACE_CLIENT_DIR */

#ifndef CONFIG_CTRL_IFACE_CLIENT_PREFIX
#define CONFIG_CTRL_IFACE_CLIENT_PREFIX "mitm_ctrl_"
#endif /* CONFIG_CTRL_IFACE_CLIENT_PREFIX */


#define COUNT_OF_MSG 50
	
struct MITM_ctrl_msg msg_handler[] = {
	{MITM_CTRL_CONNECT_REQUEST, mitm_ctrl_connect_request_action},
        {MITM_CTRL_CONNECT_REPLY, mitm_ctrl_connect_reply_action},
        {MITM_CTRL_DISCONNECT_REQUEST, mitm_ctrl_disconnect_request_action},
        {MITM_CTRL_DISCONNECT_REPLY, mitm_ctrl_disconnect_reply_action},
        {MITM_GET_AP_LIST_REQUEST, mitm_get_ap_list_request_action, 
		MITM_state_ap_search, MITM_state_spoofing, "Print ap list"},
        {MITM_GET_AP_LIST_REPLY, mitm_get_ap_list_reply_action},
       	{MITM_SET_VICTIM_REQUEST, mitm_set_victim_request_action, 
		MITM_state_ready, MITM_state_spoofing, "Set victim:[IP:ip] [MAC:mac]"},
        {MITM_SET_VICTIM_REPLY, mitm_set_victim_reply_action},
        {MITM_GET_STATUS_REQUEST, mitm_get_status_request_action, 
		MITM_state_idle, MITM_state_spoofing, "Report state"},
        {MITM_GET_STATUS_REPLY, mitm_get_status_reply_action},
        {MITM_STATUS_CHANGED, mitm_status_change_action},
        {MITM_START_ATTACK_REQUEST, mitm_start_attack_request_action},
        {MITM_START_ATTACK_REPLY, mitm_start_attack_reply_action},
        {MITM_KEEP_ALIVE_REQUSET, mitm_keep_alive_request_action},
        {MITM_KEEP_ALIVE_REPLY, mitm_keep_alive_reply_action}
};


void mitm_server_handle_msg(int sock, void *eloop_ctx, void *sock_ctx) {
	struct mitm_recv_info info;
	int ret;
	int flags;
	char buffer[COMMAND_BUFFER_LEN];

	struct mitm_ctrl *ctrl = (struct mitm_ctrl*) sock_ctx;
	struct MITM *MITM = (struct MITM*) eloop_ctx;
	flags = 0;

	info.length = sizeof(struct sockaddr_un);
	memset(&info.recv_from, 0, sizeof(struct sockaddr_un));

	ret = recvfrom(ctrl->s, buffer, COMMAND_BUFFER_LEN, flags,
		       	(struct sockaddr*)&info.recv_from,&info.length);
	if (ret < 0) { 
		log_printf(MSG_DEBUG, "[CTRL_COMMAND] recvfrom fail, with error:%s",
			       	strerror(errno));
		return;
	} 

	info.sock_fd = ctrl->s;
	info.send_flags = 0;
	for (int i = 0; i < ARRAY_SIZE(msg_handler); i++) {
		if (!strncmp(msg_handler[i].command, buffer, strlen(msg_handler[i].command))) {
			msg_handler[i].action(&info, MITM, buffer);
			break;
		} 
		/* maybe can send the MITM_INVAILD_MESSAGE_FORMAT here. */
	}

}

struct mitm_ctrl* mitm_server_open(struct MITM *MITM, const char *ctrl_path) {
	int ret;

	unlink(ctrl_path);
	struct mitm_ctrl *ctrl;
	if (!ctrl_path) { 
		log_printf(MSG_ERROR, "no control interface path specify");
		return NULL;
	}
	ctrl = malloc(sizeof(struct mitm_ctrl));
	if (!ctrl) {
		log_printf(MSG_ERROR, "malloc ctrl failed");
		return NULL;
	}
	ctrl->s = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (ctrl->s < 0) {
		log_printf(MSG_ERROR, "[%s]:create socket failed, with error:%s",
			       	__func__, strerror(errno));
		goto OPEN_SERVER_FAIL;
	}
	memset(&ctrl->local, 0, sizeof(struct sockaddr_un));
	ctrl->local.sun_family = AF_UNIX;
	strncpy(ctrl->local.sun_path, ctrl_path, sizeof(ctrl->local.sun_path) - 1);
	ret = bind(ctrl->s, (const struct sockaddr *)&(ctrl->local), sizeof(struct sockaddr_un));
	if (ret < 0) {
		log_printf(MSG_ERROR, "[%s]:bind socket to local file failed, with error:\"%s\" %s",
			       	__func__, (errno == ENOENT) ? MITM_CTRL_DIR : "",strerror(errno));
		goto OPEN_SERVER_FAIL;
	}
	eloop_register_read_sock(ctrl->s, mitm_server_handle_msg, MITM, ctrl);
	return ctrl;
OPEN_SERVER_FAIL:
	free(ctrl);
	return NULL;
}
struct mitm_ctrl* mitm_ctrl_open(const char *ctrl_path) {
	return mitm_ctrl_open2(ctrl_path, NULL);
}

struct mitm_ctrl* mitm_ctrl_open2(const char *ctrl_path,
	       			const char *cli_path) {
	struct mitm_ctrl *ctrl;
	static int counter = 0;
	int ret;
	size_t res;
	int tries = 0;
	int flags;

	if (!ctrl_path){
		log_printf(MSG_ERROR, "no control file path specify!");       
		return NULL;
	}
	ctrl = malloc(sizeof(struct mitm_ctrl));
	if (!ctrl){
		log_printf(MSG_ERROR, "alloc memory failed, please check memory left");
		return NULL;
	}

	ctrl->s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (ctrl->s < 0) {
		log_printf(MSG_ERROR, "[%s]:socket failed, with error:%s", __func__, strerror(errno));
		free(ctrl);
		return NULL;
	}

	ctrl->local.sun_family = AF_UNIX;
	counter++;
try_again:
	if (cli_path && cli_path[0] == '/') {
		ret = snprintf(ctrl->local.sun_path, sizeof(ctrl->local.sun_path),
			       	"%s/" CONFIG_CTRL_IFACE_CLIENT_PREFIX "%d-%d",
			       	cli_path, (int) getpid(), counter);
	} else {
		ret = snprintf(ctrl->local.sun_path, sizeof(ctrl->local.sun_path),
			       	CONFIG_CTRL_IFACE_CLIENT_DIR "/" 
				CONFIG_CTRL_IFACE_CLIENT_PREFIX "%d-%d",
			      	(int) getpid(), counter);
	}
	if (ret < 0 || (ret > strlen(ctrl->local.sun_path))) {
		log_printf(MSG_ERROR, "copy cil address failed");
		close(ctrl->s);
		free(ctrl);
		return NULL;
	}
	tries++;

	if (bind(ctrl->s, (struct sockaddr *) &ctrl->local, sizeof(ctrl->local)) < 0) {
		if (errno == EADDRINUSE && tries < 2) {
			/*
			 * getpid() returns unique identifier for the instance
			 * of MITM_ctrl, so the existing socket file must have 
			 * been left by unclean termination of an earlier run.
			 * Remove the file and try again.
			 */
			unlink(ctrl->local.sun_path);
			//unlikn, linlinkat - delete a name and possibly the file it regers to
			goto try_again;
		}
		log_printf(MSG_WARNING, "bind socket to local file failed, with error: %s", strerror(errno));
		close(ctrl->s);
		free(ctrl);
		return NULL;
	}
	eloop_register_read_sock(ctrl->s, mitm_server_handle_msg, NULL, ctrl);

	ctrl->dest.sun_family = AF_UNIX;
	if (strncmp(ctrl_path, "@abstract:", 10) == 0) {
		ctrl->dest.sun_path[0] = '\0';
		os_strlcpy(ctrl->dest.sun_path + 1, ctrl_path + 10,
			       	sizeof(ctrl->dest.sun_path) -1);
		// 10 for size of @abstract: 
	} else {
		res = os_strlcpy(ctrl->dest.sun_path, ctrl_path,
			       	sizeof(ctrl->dest.sun_path));
		if (res >= sizeof(ctrl->dest.sun_path)) {
			close(ctrl->s);
			free(ctrl);
			return NULL;
		}
	}

	if (connect(ctrl->s, (struct sockaddr *) &ctrl->dest, sizeof(ctrl->dest)) < 0) {
		log_printf(MSG_ERROR, "connect to server failed, with error:%s", strerror(errno));
		close(ctrl->s);
		unlink(ctrl->local.sun_path);
		free(ctrl);
		return NULL;
	}

	/*
	 * make socket non-blocking so tgat we don't hang forever 
	 * if target dies unexpectedly.
	 */

	flags = fcntl(ctrl->s, F_GETFL);
	if (flags >= 0) {
		flags |= O_NONBLOCK;
		if (fcntl(ctrl->s, F_SETFL, flags) < 0) {
			perror("fcntl(ctrl->s, O_NONBLOCK)");
			/*
			 * the perror() function produces a message on standard error
			 * describing the last error encountered during a call to a system
			 * or library function
			 */

			/* Not fatal, continue on. */
		}
	}

	return ctrl;
}

void mitm_ctrl_close(struct mitm_ctrl *ctrl) {
	if(!ctrl) return;

	unlink(ctrl->local.sun_path);
	if (ctrl->s >= 0)
		close(ctrl->s);
	free(ctrl);
}


#ifdef CONFIG_CTRL_IFACE_UDP

struct mitm_ctrl* mitm_ctrl_open(const char *ctrl_path) {
	struct mitm_ctrl *ctrl;
	char buf[128];
	size_t len;
#ifdef CONFIG_CTRL_IFACE_UDP_REMOTE
	struct hostent *h;
#endif /* CONFIG_CTRL_IFACE_UDP_REMOTE */
	ctrl = malloc(sizeof(struct mitm_ctrl));
	if(!ctrl) return NULL;
#ifdef CONFIG_CTRL_IFACE_UDP_IPV6
	ctrl->s = socket(PF_INET6, SOCK_DGRAM, 0);
#else /* CONFIG_CTRL_IFACE_UDP_IPV6 */
	ctrl->s = socket(PF_INET6, SOCK_DGRAM, 0);
#endif /* CONFIG_CTRL_IFACE_UDP_IPV6 */
	if (ctrl->s < 0) {
		perror("socket");
		free(ctrl);
		return NULL;
	}

#ifdef CONFIG_CTRL_IFACE_UDP_IPV6
	ctrl->local.sin6_family = AF_INET6;
#endif /* CONFIG_CTRL_IFACE_UDP_IPV6 */
#ifdef CONFIG_CTRL_IFACE_UDP_REMOTE
	ctrl->local.sin6_addr = in6addr_any;
#endif /* CONFIG_CTRL_IFACE_UDP_REMOTE */
}

#endif /* CONFIG_CTRL_IFACE_UDP */
int mitm_ctrl_request(struct mitm_ctrl *ctrl, const char *cmd, size_t cmd_len,
	       	char *reply, size_t *reply_len, void (*msg_cb)(char *msg, size_t len)) {
	if (!ctrl || ctrl->s < 0) return -1;
	struct timeval tv;
	struct os_reltime started_at;
	int res;
	fd_set rfds;
	const char *_cmd;
	char *cmd_buf = NULL;
	size_t _cmd_len;
	int flags = 0;

	FD_ZERO(&rfds);

	FD_SET(ctrl->s, &rfds);

	_cmd = cmd;
	_cmd_len = cmd_len;	

	started_at.sec = 0;
	started_at.usec = 0;
retry_send:
	//if (send(ctrl->s, _cmd, _cmd_len, flags) < 0) {
	if (write(ctrl->s, _cmd, _cmd_len) < 0) {
		//EAGAIN : Resource temporarily unavailable
		//EBUSY:Device or Resource busy
		//EWOULDBLOCK: Operation would block
		if (errno == EAGAIN || errno == EBUSY || errno == EWOULDBLOCK) {
			if (started_at.sec == 0) {
				os_get_reltime(&started_at);
			} else {
				struct os_reltime n;
				os_get_reltime(&n);
				/* Try for a few seconds. */
				if (os_reltime_expired(&started_at, &n, 5)) {
					goto send_err;
				}
				sleep(1);
				goto retry_send;
			}
		}
send_err:
		free(cmd_buf);
	       	// free(void *pointer) - if pointer point to a NULL memery address, do nothing
		return -1;
	} 
	return 0;
}

int mitm_ctrl_recv(struct mitm_ctrl *ctrl, char *reply, size_t *reply_len) {
	int res;
	int flags;
	flags = 0;
	res = recv(ctrl->s, reply, *reply_len, flags);
	if (res < 0) {
		log_printf(MSG_ERROR, "%s:%s", __func__, strerror(errno));
		return -1 ;
	}
	*reply_len = res;
	return 0;
}

int mitm_ctrl_pending(struct mitm_ctrl *ctrl) {
	struct timeval tv;
	fd_set rfds;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(ctrl->s, &rfds);
	select(ctrl->s + 1, &rfds, NULL, NULL, &tv);
	return FD_ISSET(ctrl->s, &rfds);
}

int mitm_ctrl_get_fd(struct mitm_ctrl *ctrl) {
	return ctrl->s;
}
