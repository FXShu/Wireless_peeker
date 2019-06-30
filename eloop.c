#include "includes.h"
#include <assert.h>

//#include "common.h"
//include "trace.h"
#include "list.h"
#include "eloop.h"

#if defined(CONFIG_ELOOP_POLL) && defined(CONFIG_ELOOP_EPOLL)
#error Do not define both of poll and epoll
#endif

#if defined(CONFIG_ELOOP_POLL) && defined(CONFIG_ELOOP_KQUEUE)
#error Do not define both of poll and kqueue
#endif

#if !defined(CONFIG_ELOOP_POLL) && !defined(CONFIG_ELOOP_EPOLL) && \
    !defined(CONFIG_ELOOP_KQUEUE)
#define CONFIG_ELOOP_SELECT
#endif

#ifdef CONFIG_ELOOP_POLL
#include <poll.h>
#endif /* CONFIG_ELOOP_POLL */

#ifdef CONFIG_ELOOP_EPOLL
#include <sys/epoll.h>
#endif /* CONFIG_ELOOP_EPOLL */

#ifdef CONFIG_ELOOP__KQUEUE
#include <sys/event.h>
#endif /* CONFIG_ELOOP_KQUEUE*/

struct eloop_sock {
	int sock;
	void *eloop_data;
	void *user_data;
	eloop_sock_handler handler;
}
