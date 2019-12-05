#include "iw_implement.h"
extern int debug_level;  

struct nl80211_state *state;


#ifndef NETLINK_SOCKET_H_
#define NETLINK_SOCKET_H_
static inline int nl_socket_set_buffer_size(struct nl_sock *sk, int rxbuf, int txbuf) {
	return nl_set_buffer_size(sk, rxbuf, txbuf);
}
#endif /* NETLINK_SOCKET_H_ */

int nl80211_init(){
	int err;

	state = malloc(sizeof(struct nl80211_state));

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		log_printf(MSG_ERROR, "Failed to allocate netlink socket");
		return -1;
	}

	if (genl_connect(state->nl_sock)) {
		log_printf(MSG_ERROR, "Failed to connect to generic netlink");
		err = -1;
		goto out_handle_destroy;
	}

	nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);
	err = 1;
	/* try to set NETLINK_EXT_ACK to 1, ignoring errors*/
	setsockopt(nl_socket_get_fd(state->nl_sock), SOL_NETLINK,
		       	NETLINK_EXT_ACK, &err, sizeof(err));
	state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
	if (state->nl80211_id < 0) {
		log_printf(MSG_ERROR, "nl80211 not found");
		err = -1;
		goto out_handle_destroy;
	}

	return 0;
out_handle_destroy:
	nl_socket_free(state->nl_sock);
	free(state);
	return err;
}

static int phy_lookup(char *name) {
	char buf[200];
	int fd, pos;

	snprintf(buf, sizeof(buf), "/sys/class/ieee80211/%s/index", name);

	fd = open(buf, O_RDONLY);
	if (fd < 0) {
		log_printf(MSG_ERROR, "can't find %s, please checkout /sys/class/ieee80211", name);
		return -1;
	}
	pos = read(fd, buf, sizeof(buf) - 1);
	if (pos < 0) {
		close(fd);
		return -1;
	}
	buf[pos] = '\0';
	close(fd);
	return atoi(buf);
}

//command should be like iw command style i.e. dev wlp2s0 interface add mon0 type monitor
enum id_input getIdInput(char** command) {
	enum id_input input = II_NONE;
	
	if(!strcmp(command[0], "dev")) {
		input = II_NETDEV;
	} else if (!strcmp(command[0],"phy")) {
		if (strlen(command[0]) == 3){
			input = II_PHY_NAME;
		} else if (*(*command + 3) == '#') {
			input = II_PHY_IDX;
		}
	} else if (!strcmp(command[0], "wdev")) {
		input = II_WDEV;
	}
	command++;
	return input;
}


int interface_handler(char **command) {
	struct nl_msg *msg;
	struct nl_cb *cb;
	struct nl_cb *s_cb;
	struct cmd *cmd_ptr;
	char *tmp;
	int devidx;  
	enum id_input id_tmp = II_NONE;
	switch(getIdInput(command)) {
	case II_PHY_IDX:
		devidx = strtoul(*command + 4, &tmp, 0);
		if (*tmp != '\0') return -1;
		id_tmp = II_PHY_IDX;
		command++;
		break;
	case II_PHY_NAME:
		devidx = phy_lookup(*command);
		id_tmp = II_PHY_NAME;
		command++;
		break;
	case II_NETDEV:
		devidx = if_nametoindex(*command);
		id_tmp = II_NETDEV;
		command++;
		break;
	case II_WDEV:
		devidx = strtoll(*command, &tmp, 0);
		if (*tmp != '\0') return -1;
		id_tmp = II_WDEV;
		command++;
		break;
	default:
		break;
	}
	
	if(devidx < 0) {
		log_printf(MSG_DEBUG, "%s,%d: can not find the index of dev name");
		return -1;
	}

	//interface add mon0 type monitor
	/**
	 * here should use command and command++ to Assignment struct cmd *cmd
	 * */

	struct cmd cmd = {
		.name = *command++,
		.args = *command++,
		.cmd = NL80211_CMD_NEW_INTERFACE,
		.nl_msg_flags = 0,
		.hidden = 0,
		.idby = CIB_PHY,
		.handler = handle_interface_add,
	};
	cmd_ptr = &cmd;
	msg = nlmsg_alloc();
	if (!msg) {
		log_printf(MSG_ERROR, "%s,%d:failed to alloc nlmsg", __func__, __LINE__);
		return -1;
	}
	
	cb = nl_cb_alloc(debug_level<= MSG_DEBUG ? NL_CB_DEBUG : NL_CB_DEFAULT);
	s_cb = nl_cb_alloc(debug_level<= MSG_DEBUG ? NL_CB_DEBUG : NL_CB_DEFAULT);

	if(!cb || !s_cb) {
		log_printf(MSG_ERROR, "%s,%d:failed to alloc struct nl_cb", __func__, __LINE__);
		goto out;
	}

	if (!state) {
		log_printf(MSG_ERROR, "nl80211_state is no exist");
		goto out;
		return -1;
	}

	genlmsg_put(msg, 0 ,0 ,state->nl80211_id, 0, cmd_ptr->nl_msg_flags, cmd_ptr->cmd, 0);
	
	switch (cmd_ptr->idby) {
	case CIB_PHY:
		NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, devidx);
		break;
	case CIB_NETDEV:
		NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
		break;
	case CIB_WDEV:
		NLA_PUT_U64(msg, NL80211_ATTR_WDEV, devidx);
		break;
	default:
		break;
	}

	//i.e. mon0 type monitor
	//
	//handler(struct nl80211_state, struct nl_msg, int , char**, enum id_input)
	//the 3rd parameter(integer) is useless, and so does 5th parameter 
	if(cmd_ptr->handler(state, msg, 0, command, id_tmp) < 0) {
		goto out;
	}

	nl_socket_set_cb(state->nl_sock, s_cb);

	if(nl_send_auto_complete(state->nl_sock, msg) < 0) {
		goto out;
	}
	return 0;
out:
nla_put_failure:
	nl_cb_put(cb);
	nl_cb_put(s_cb);
	nlmsg_free(msg);
	return -1;

}
