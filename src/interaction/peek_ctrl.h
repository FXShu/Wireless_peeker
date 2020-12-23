#ifndef __PEEK_CTRL_H__
#define __PEEK_CTRL_H__

#include "common.h"
#include "command.h"
#include "peek_action.h"

struct peek_ctrl {
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

struct peek_ctrl* peek_ctrl_server_open(struct wireless_peek *this, const char *ctrl_path);

struct peek_ctrl * peek_ctrl_open(const char *ctrl_path);

struct peek_ctrl * peek_ctrl_open2(const char *ctrl_path, const char *cli_path, 
		struct wireless_peek_info *info);

void peek_ctrl_close(struct peek_ctrl *ctrl);

/* mitm_ctrl_request
 * send a request to caller and wait the caller reply.
 * reply - the caller reply this request will stored in here.
 * reply_len - when the function return, and the value is zero,
 * 	       this value will be modify to the length of reply.
 * msg_cd - when the caller reply is illgel, this function will used
 * 	    to warn caller.  
 * */
int peek_ctrl_request(struct peek_ctrl *ctrl, const char *cmd, size_t cmd_len);

int peek_ctrl_recv(struct peek_ctrl *ctrl, char *reply, size_t *reply_len);

/* mitm_ctrl_pending
 * This function is called, when the user want to wait a message from parter.
 * Return - 1 for having a message from parter, 0 for no message receive
 * when the function is return by 0, should call the mitm_ctrl_recv to receive the message.  
 * */
int peek_ctrl_pending(struct peek_ctrl *ctrl);

int peek_ctrl_get_fd(struct peek_ctrl *ctrl);

int peek_get_action_num();
#endif /* __PEEK_CTRL_H__ */
