#ifndef __PEEK_NETLINK_H__
#define __PEEK_NETLINK_H__

#include <linux/netlink.h>
#include "common.h"

#define MAX_PAYLOAD 1024

#define GENL_DATA(gnlh) ((void *)gnlh + GENL_HDRLEN)
#define NLA_OK(nla, len) ((len) >= (int)sizeof(struct nlattr) && \
				nla->nla_len >= sizeof(struct nlattr) && \
				nla->nla_len <= len)

#define NLA_NEXT(nla, len) (len -= NLA_ALIGN(nla->nla_len), \
				(struct nlattr *)(((char *)nla) + NLA_ALIGN(nla->nla_len)))

#define NLA_DATA(nla) (void *)((char *)nla + NLA_HDRLEN)
#define CTRL_ATTR_FAMILY_ID 1

/* generic netlink flag */
/* GET request */
#define NLM_FLAG_ROOT	(1u << 0) /* specify tree root */
#define NLM_FLAG_MATCH	(1u << 1) /* return all matching */
#define NLM_FLAG_ATOMIC	(1u << 2) /* atomic GET */
#define NLM_FLAG_DUMP	(NLM_FLAG_ROOT|NLM_FLAG_MATCH)
/* NEW request */
#define NLM_FLAG_REPLACE	(1u << 0) /* Override existing */
#define NLM_FLAG_EXCL		(1u << 1) /* Do not touch, if it exists */
#define NLM_FLAG_CREATE		(1u << 2) /* Create, if it does not exist */
#define NLM_FLAG_APPEND		(1u << 3) /* Add to end of list */

typedef int (*netlink_cb)(struct nlattr **tb, void* user_data);

/***
 * peek_alloc_generic_packet - alloc netlink packet include netlink header and generic netlink header
 *
 * @param type: ID of specific netlink family.
 * @param flags: operate flags.
 * @param seq: sequence of packet.
 * @param pid: process pid.
 * @param cmd: request command.
 *
 * @return: pointer to netlink header alloced.
 */
struct nlmsghdr *peek_alloc_generic_packet(int type, int flags, int seq, int pid, int cmd);

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
void peek_netlink_put_u16(char **payload, int *len, u16 attr, u16 value);

/***
 * peek_netlink_put_u32 - pending attribute and value to payload
 *
 * @param payload: payload of packet
 * @param len: remaining len of payload
 * @param attr: referebnce peek_netlink.h define
 * @param value: value of specific attribute.
 *
 * @return: no return
 */
void peek_netlink_put_u32(char **payload, int *len, u16 attr, u32 value);

/***
 * peek_netlink_put_str - pending attribute and string to payload
 *
 * @param payload: payload of packet
 * @param len: remaining len of payload
 * @param attr: referebnce peek_netlink.h define
 * @param str: value of specific attribute.
 * @param strlen: length of str
 *
 * @return: no return
 */
void peek_netlink_put_str(char **payload, int *len, u16 attr,const char *str);

/***
 * peek_netlink_send - send message to netlink
 *
 * @param sock: socket to communicate to netlink.
 * @param hdr: packet which prepare to send to netlink.
 * @param group: group of netlink family.
 *
 * @return: 0 on success, -1 when error occur.
 */
int peek_netlink_send(int sock, struct nlmsghdr *hdr, int group);

/***
 * peek_netlink_recv - recv message from netlink
 *
 * @param sock: socket to communicate to netlink.
 * @param tb: receive message.
 * @param cb: callback function which handle received message.
 * @param user_data: parameter of cb function.
 *
 * @return: value of callback function return.
 */
int peek_netlink_recv(int sock, struct nlattr **tb, netlink_cb cb, void *user_data);

#endif /*  __PEEK_NETLINK_H__ */
