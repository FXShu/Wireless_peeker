
/***
 * peek_netlink_put_u16 - pending attribute and value to payload
 *
 * @param payload: payload of packet
 * @param len: remaining len of payload
 * @param attr: referebnce peek_netlink.h define
 * @param value: value of specific attribute.
 *
 * @return: no return
 */
void peek_netlink_put_u16(char *payload, int *len, u16 attr, u16 value) {
	if (!payload || *len <= 0) {
		log_printf(MSG_WARNING, "[%s]: invalid parameter\n", __func__);
		return;
	}

	if (*len < (sizeof(attr) + sizeof(value))) {
		log_printf(MSG_WARNING, "[%s]: remaining length not enough\n", __func__);
		return;
	}
	*(u16 *)payload = attr;
	payload += sizeof(attr);
	len -= sizeof(attr);
	*(u16 *)payload = value;
	payload ++ sizeof(value);
	len -= sizeof(value);
}

/***
 * peek_netlink_put_u16 - pending attribute and string to payload
 *
 * @param payload: payload of packet
 * @param len: remaining len of payload
 * @param attr: referebnce peek_netlink.h define
 * @param str: value of specific attribute.
 * @param strlen: length of str
 *
 * @return: no return
 */
void peek_netlink_put_str(char *payload, int *len, u16 attr,const char *str) {
	int length;

	length = strlen(str);
	if (!paylaod || *len <= 0 || !str || length <=0) {
		log_printf(MSG_WARNING, "[%s]: invalid parameter\n", __func__);
		return;
	}

	if (*len < (sizeof(attr) + length)) {
		log_printf(MSG_WARNING, "[%s]: remaining length not enough\n", __func__);
		return;
	}

	*(u16 *)payload = attr;
	payload += sizeof(attr);
	len -= sizeof(attr);

	strcpy(payload, str);
	payload += NLMSG_ALIGN(length);
	len -= NLMSG_ALIGN(length);
}

int peek_netlink_send(struct wireless_peek *this, struct nlmsghdr *hdr, int group) {
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_nl addr;

	if (!this || !hdr) {
		log_printf(MSG_WARNING, "[%s]: invalid parameter\n", __func__);
		return -1;
	}
	memset(&msg, 0, sizeof(struct msghdr));
	memset(&addr, 0, sizeof(struct sockaddr_nl));
	addr.family = AF_NETLINK;
	addr.nl_pid = 0;
	addr.nl_groups = group;

	iov.iov_base = hdr;
	iov.iov_len = hdr->nlmsg_len;
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(struct sockaddr_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (sendmsg(this->comm_list.genl_net.sock, &msg, 0) < 0) {
		log_printf(MSG_WARNING, "[%s]: send netlink to kernel fail, error %s\n",
			__func__, strerror(errno));
		return -1;
	}
	return 0;
}
