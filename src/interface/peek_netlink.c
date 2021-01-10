#include <linux/genetlink.h>
#include "peek_netlink.h"
#include "common.h"

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
	*len -= sizeof(attr);
	*(u16 *)payload = value;
	payload += sizeof(value);
	*len -= sizeof(value);
}

void peek_netlink_put_str(char *payload, int *len, u16 attr,const char *str) {
	int length;
	length = strlen(str);
	struct nlattr nla;

	if (!payload || *len <= 0 || !str || length <=0) {
		log_printf(MSG_WARNING, "[%s]: invalid parameter\n", __func__);
		return;
	}

	nla.nla_type = attr;
	nla.nla_len = NLA_HDRLEN + NLA_ALIGN(length);

	if (*len < nla.nla_len) {
		log_printf(MSG_WARNING, "[%s]: remaining length not enough\n", __func__);
		return;
	}

	memcpy(payload, &nla, sizeof(struct nlattr));
	payload += sizeof(struct nlattr);
	*len -= sizeof(struct nlattr);

	strcpy(payload, str);
	payload += NLMSG_ALIGN(length);
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
    msg.msg_iovlen = 1;
    for (int i = 0; i < msg.msg_iov->iov_len; i++) {
        printf("0x%x ", *((char *)(msg.msg_iov->iov_base) + i));
    }
    printf("\n");

	if (sendmsg(sock, &msg, 0) < 0) {
		log_printf(MSG_WARNING, "[%s]: send netlink to kernel fail, error %s\n",
			__func__, strerror(errno));
		return -1;
	}
	return 0;
}

int peek_netlink_recv(int sock, struct nlmsghdr **hdr) {
	int len;
	char buffer[MAX_PAYLOAD];
	struct iovec iov = {
		.iov_base = buffer,
		.iov_len = MAX_PAYLOAD,
	};
	struct msghdr message = {
		.msg_iov = &iov,
		.msg_iovlen =1,
	};

	memset(buffer, 0, MAX_PAYLOAD);
	len = recvmsg(sock, &message, sizeof(struct msghdr));
	if (len < 0) {
		log_printf(MSG_WARNING, "[%s]: recv message via netlink fail, error %s\n",
			__func__, strerror(errno));
		return -1;
	}
	*hdr = malloc(len);
	assert(*hdr);
	memcpy((void *)*hdr, message.msg_iov->iov_base, len);
	return len;
}

#define GENL_DATA(gnlh) ((void *)gnlh + GENL_HDRLEN)
#define NLA_OK(nla, len) ((len) >= (int)sizeof(struct nlattr) && \
							nla->nla_len >= sizeof(struct nlattr) && \
							nla->nla_len <= len)

#define NLA_NEXT(nla, len) (len -= NLA_ALIGN(nla->nla_len), \
							(struct nlattr *)(((char *)nla) + NLA_ALIGN(nla->nla_len)))

#define NLA_DATA(nla) *(u16 *)((char *)nla + NLA_HDRLEN)
#define CTRL_ATTR_FAMILY_ID 1
void peek_parse(struct nlmsghdr *hdr, int len) {
	struct genlmsghdr *ghdr;
	struct nlattr *nla;

	while(NLMSG_OK(hdr, len)) {
		printf("netlink packet: len %d, type 0x%x, flags 0x%x, seq %d, pid %d\n",
			hdr->nlmsg_len, hdr->nlmsg_type, hdr->nlmsg_flags, hdr->nlmsg_seq, hdr->nlmsg_pid);

		ghdr = NLMSG_DATA(hdr);
		len -= GENL_HDRLEN;
		printf("generic netlink packet: cmd 0x%x, version %d\n",
			ghdr->cmd, ghdr->version);
		nla = GENL_DATA(ghdr);

		while(NLA_OK(nla, len)) {
			if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
				printf("attr %d = %d\n", nla->nla_type, NLA_DATA(nla));
			}
			nla = NLA_NEXT(nla, len);
		}
		hdr = NLMSG_NEXT(hdr, len);
	}
}
