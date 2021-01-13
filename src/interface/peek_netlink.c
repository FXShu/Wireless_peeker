#include <linux/genetlink.h>
#include "peek_netlink.h"
#include "common.h"

struct nlmsghdr *peek_alloc_generic_packet(int type, int flags, int seq, int pid, int cmd) {
	struct nlmsghdr *hdr;
	struct genlmsghdr *ghdr;
	hdr = malloc(NLMSG_SPACE(MAX_PAYLOAD));
	if (!hdr) {
		log_printf(MSG_ERROR, "[%s]: memory alloc fail\n", __func__);
		return NULL;
	}
	memset(hdr, 0, NLMSG_SPACE(MAX_PAYLOAD));

	hdr->nlmsg_type = type;
	hdr->nlmsg_flags = flags;
	hdr->nlmsg_seq = seq;
	if (pid > 0)
		hdr->nlmsg_pid = pid;
	else
		hdr->nlmsg_pid = getpid();

	ghdr = NLMSG_DATA(hdr);
	ghdr->cmd = cmd;
	ghdr->version = 1;
	return hdr;
}

void peek_netlink_put_u16(char **payload, int *len, u16 attr, u16 value) {
	struct nlattr nla;
	printf("0\n");
	if (!*payload || *len <= 0) {
		log_printf(MSG_WARNING, "[%s]: invalid parameter\n", __func__);
		return;
	}

	nla.nla_type = attr;
	nla.nla_len = NLA_HDRLEN + sizeof(value);

	if (*len < nla.nla_len) {
		log_printf(MSG_WARNING, "[%s]: remaining length not enough\n", __func__);
		return;
	}
	memcpy(*payload, &nla, sizeof(struct nlattr));
	*payload += sizeof(struct nlattr);
	*len -= sizeof(struct nlattr);

	*(u16 *)(*payload) = value;
	*payload += NLA_ALIGN(sizeof(value));
	*len -= NLA_ALIGN(sizeof(value));
	printf("1\n");
}

void peek_netlink_put_u32(char **payload, int *len, u16 attr, u32 value) {
	struct nlattr nla;

	if (!*payload || *len <= 0) {
		log_printf(MSG_WARNING, "[%s]: invalid parameter\n", __func__);
		return;
	}

	nla.nla_type = attr;
	nla.nla_len = NLA_HDRLEN + sizeof(value);

	if (*len < nla.nla_len) {
		log_printf(MSG_WARNING, "[%s]: remaining length not enough\n", __func__);
		return;
	}
	memcpy(*payload, &nla, sizeof(struct nlattr));
	*payload += sizeof(struct nlattr);
	*len -= sizeof(struct nlattr);

	*(u16 *)(*payload) = value;
	*payload += sizeof(value);
	*len -= sizeof(value);
}

void peek_netlink_put_str(char **payload, int *len, u16 attr,const char *str) {
	int length;
	struct nlattr nla;

	length = strlen(str);
	if (!*payload || *len <= 0 || !str || length <=0) {
		log_printf(MSG_WARNING, "[%s]: invalid parameter\n", __func__);
		return;
	}

	nla.nla_type = attr;
	nla.nla_len = NLA_HDRLEN + NLA_ALIGN(length);

	if (*len < nla.nla_len) {
		log_printf(MSG_WARNING, "[%s]: remaining length not enough\n", __func__);
		return;
	}

	memcpy(*payload, &nla, sizeof(struct nlattr));
	*payload += sizeof(struct nlattr);
	*len -= sizeof(struct nlattr);

	strcpy(*payload, str);
	*payload += NLMSG_ALIGN(length);
	*len -= NLMSG_ALIGN(length);
}

int peek_netlink_send(int sock, struct nlmsghdr *hdr, int group) {
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_nl addr;

	if (!hdr) {
		log_printf(MSG_WARNING, "[%s]: invalid parameter\n", __func__);
		return -1;
	}
	memset(&msg, 0, sizeof(struct msghdr));
	memset(&addr, 0, sizeof(struct sockaddr_nl));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	addr.nl_groups = group;

	iov.iov_base = hdr;
	iov.iov_len = hdr->nlmsg_len;
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(struct sockaddr_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	lamont_hdump(MSG_DEBUG, __func__, (char *)msg.msg_iov->iov_base, msg.msg_iov->iov_len);

	if (sendmsg(sock, &msg, 0) < 0) {
		log_printf(MSG_WARNING, "[%s]: send netlink to kernel fail, error %s\n",
			__func__, strerror(errno));
		return -1;
	}
	return 0;
}
/* TODO: policy check. */
static int peek_netlink_parse(struct nlmsghdr *hdr, int len,
	struct nlattr **tb, netlink_cb cb, void *user_data) {
	struct genlmsghdr *ghdr;
	struct nlattr *nla;
	int ret = 0;

	if (!cb) {
		return 0;
	}

	while(NLMSG_OK(hdr, len)) {
		ghdr = NLMSG_DATA(hdr);
		len -= GENL_HDRLEN;
		nla = GENL_DATA(ghdr);

		while(NLA_OK(nla, len)) {
			tb[nla->nla_type] = nla;
			nla = NLA_NEXT(nla, len);
		}
		ret |= cb(tb, user_data);
		hdr = NLMSG_NEXT(hdr, len);
	}
	return ret;
}

int peek_netlink_recv(int sock, struct nlattr **tb, netlink_cb cb, void *user_data) {
	struct nlmsghdr *hdr;
	int len;
	char buffer[MAX_PAYLOAD];
	struct iovec iov = {
		.iov_base = buffer,
		.iov_len = MAX_PAYLOAD,
	};
	struct msghdr message = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	memset(buffer, 0, MAX_PAYLOAD);
	len = recvmsg(sock, &message, sizeof(struct msghdr));
	if (len < 0) {
		log_printf(MSG_WARNING, "[%s]: recv message via netlink fail, error %s\n",
			__func__, strerror(errno));
		return -1;
	}
	lamont_hdump(MSG_DEBUG, __func__, (char *)message.msg_iov->iov_base, len);
	hdr = (struct nlmsghdr *)message.msg_iov->iov_base;
	return peek_netlink_parse(hdr, len, tb, cb, user_data);
}

