#ifdef CONFIG_CTRL_IFACE
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h> // fcntl - manipulate file descriptor
#endif /* CONFIG_CTRL_IFACE */

#include "mitm_ctrl.h"

#if defined(CONFIG_CTRL_IFACE_UNIX)

struct mitm_ctrl {
#ifdef CONFIG_CTRL_IFACE_UDP
	int s;
#ifdef CONFIG_CTRL_IFACE_UDP_IPV6
	struct sockaddr_in6 local;
	struct sockaddr_in6 dest;
#else /* CONFIG_CTRL_IFACE_UDP_IPV6 */
	struct sockaddr_in local;
	struct sockaddr_in dest;
#endif /* CONFIG_CTRL_IFACE_UDP_IPV6 */
	char *cookie;
	char *remote_ifname;
	char *remote_ip;
#endif /* CONFIG_CTRL_IFACE_UDP */
#ifdef CONFIG_CTRL_IFACE_UNIX
	int s;
	struct sockaddr_un local;
	struct sockaddr_un dest;
#endif /* CONFIG_CTRL_IFACE_UNIX */
#ifdef CONFIG_CTRL_IFACE_NAMED_PIPE
	HANDLE pipe;
#endif /* CONFIG_CTRL_IFACE_NAMED_PIPE */
};

#ifdef CONFIG_CTRL_IFACE_UNIX

#ifndef CONFIG_CTRL_IFACE_CLIENT_DIR
#define CONFIG_CTRL_IFACE_CLIENT_DIR "/tmp"
#endif /* CONFIG_CTRL_IFACE_CLIENT_DIR */

#ifndef CONFIG_CTRL_IFACE_CLIENT_PREFIX
#define CONFIG_CTRL_IFACE_CLIENT_PREFIX "mitm_ctrl_"
#endif /* CONFIG_CTRL_IFACE_CLIENT_PREFIX */

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

	if (!ctrl_path) return NULL;

	ctrl = malloc(sizeof(struct mitm_ctrl));
	if (!ctrl) return NULL;

	ctrl->s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (ctrl->s < 0) {
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
	if (ret < 0 || (ret >= ctrl->local.sun_path)) {
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

		close(ctrl->s);
		free(ctrl);
		return NULL;
	}

	ctrl->dest.sun.family = AF_UNIX;
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

	if (connect(ctrl->s, (struct sockaddr *) &ctrl-dest, sizeof(ctrl->dest)) < 0) {
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

#else /* CONFIG_CTRL_IFACE_UNIX */

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
#ifdef CONFIG_CTRL_IFACE_UDP_REMOTE
	ctrl->local.sin6_addr = in6addr_any;
}

int mitm_ctrl_request(struct mitm_ctrl *ctrl, const char *cmd, size_t cmd_len,
	       	char *reply, size_t *reply_len, void (*msg_cd)(char *msg, size_t len)) {
	struct timeval tv;
	struct os_reltime started_at;
	int res;
	fd_set rfds;
	const char *_cmd;
	char *cmd_buf = NULL;
	size_t _cmd_len;
	int flags = 0;

	FD_ZERO(rfds);

	FD_SET(ctrl->s, &rfds);

	_cmd = cmd;
	_cmd_len = cmd_len;	

	started_at.sec = 0;
	started_at.usec = 0;
retry_send:
	if (send(ctrl->s, _cmd, _cmd_len, flags) < 0) {
		//EAGAIN : Resource temporarily unavailable
		//EBUSY:Device or Resource busy
		//EWOULDBLOCK: Operation would block
		if (errno == EAGAIN || errno == EBUSY || errno == EWOULDBLOCK) {
			if (started_at.sec == 0) {
				get_reltime()
			}
		}
	} 


	if (res < 0) {
		log_printf(MSG_ERROR, "%s:%s", __func__, strerror(errno));
		return -1;
	}

	tv.sec = 10;
	tv.usec = 0;
	FD_SET(ctrl->s, &rfds);

	if (select(ctrl->s + 1, &rfds, NULL, NULL, &tv) < 0) {
		log_printf(MSG_ERROR, "%s:%s", __func__, strerror(errno));
		return -1;
	}

	if (FD_ISSET(ctrl->s, &rfds)) {
		if(recv(ctrl->s, msg_buf, reply, *reply_len, flags) < 0) {
			log_printf(MSG_ERROR, "%s:%s", __func__, strerror(errno));
		}
	}
}

