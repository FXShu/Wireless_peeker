#ifndef MITM_CTRL_H
#define MITM_CTRL_H

#include "common.h"
#include "command.h"

struct mitm_ctrl* mitm_server_open(struct MITM *MITM, const char *ctrl_path);

struct mitm_ctrl * mitm_ctrl_open(const char *ctrl_path);

struct mitm_ctrl * mitm_ctrl_open2(const char *ctrl_path, const char *cli_path);

void mitm_ctrl_close(struct mitm_ctrl *ctrl);

/* mitm_ctrl_request
 * send a request to caller and wait the caller reply.
 * reply - the caller reply this request will stored in here.
 * reply_len - when the function return, and the value is zero,
 * 	       this value will be modify to the length of reply.
 * msg_cd - when the caller reply is illgel, this function will used
 * 	    to warn caller.  
 * */
int mitm_ctrl_request(struct mitm_ctrl *ctrl, const char *cmd, 
		size_t cmd_len, char *reply, size_t *reply_len, 
		void (*msg_cd)(char *msg, size_t len));

int mitm_ctrl_recv(struct mitm_ctrl *ctrl, char *reply, size_t *reply_len);

/* mitm_ctrl_pending
 * This function is called, when the user want to wait a message from parter.
 * Return - 1 for having a message from parter, 0 for no message receive
 * when the function is return by 0, should call the mitm_ctrl_recv to receive the message.  
 * */
int mitm_ctrl_pending(struct mitm_ctrl *ctrl);

int mitm_ctrl_get_fd(struct mitm_ctrl *ctrl);
#endif /* MITM_CTRL_H */
