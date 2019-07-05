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
	HACK_TRACE_REF(eloop);
	HACK_TRACE_REF(user);
	HACK_TRACE_INFO
};

struct eloop_timeout {
	struct dl_list list;
	struct os_reltime time;
	void *eloop_data;
	void *user_data;
	eloop_timeout_handler handler;
	HACK_TRACE_REF(eloop);
	HACK_TRACE_REF(user);
	HACK_TRACE_INFO
};

struct eloop_signal {
	int sig;
	void *user_data;
	eloop_signal_handler handler;
	int signaled;
};

struct eloop_sock_table {
	int count;
	struct eloop_sock *table;
	eloop_event_type type;
	int changed;
};

struct eloop_data {
	int max_sock;

	int count; /* sum of all table counts */
#ifdef CONFIG_ELOOP_POLL
	int max_pollfd_map; /* number of pollfds_map currently allocated */
	int max_poll_fds; /* number of pollfds currently allocated */
	struct pollfd *pollfds;
	struct pollfd **pollfds_map;
#endif /* CONFIG_ELOOP_POLL */
#if defined(CONFIG_ELOOP_EPOLL) || defined(CONFIG_ELOOP_KQUEUE)
	int max_fd;
	struct eloop_sock *fd_table;
#endif /* CONFIG_ELOOP_EPOLL || CONFIG_ELOOP_KQUEUE */
#ifdef CONFIG_ELOOP_EPOLL
	int epollfd;
	int epoll_max_event_num;
	struct epoll_event *epoll_events;
#endif /* CONFIG_ELOOP_EPOLL */
#ifdef CONFIG_ELOOP_KQUEUE
	int kqueuefd;
	int kqueue_nevents;
	struct kevent *kqueue_events;
#endif /* CONFIG_ELOOP_KQUEUE */
	struct eloop_sock_table readers;
	struct eloop_sock_table writers;
	struct eloop_sock_table exceptions;

	struct dl_list timeout;

	int signal_count;
	struct eloop_signal *signals;
	int signaled;
	int pending_terminate;

	int terminate;
};

static struct eloop_data eloop;


#ifdef WPA_TRACE

static void eloop_sigsegv_handler(int sig){
	wpa_trace_show("eloop SIGSEGV");
	abort();
}

static void eloop_trace_sock_add_ref(struct eloop_sock_table *table) {
	int i;
	if (table == NULL || table -> table == NULL)
		return;
	for (i = 0; i < table->count; i++) {
		hack_trace_add_ref(&table->table[i], eloop, 
				table->table[i].eloop_data);
		hack_trace_add_ref(&table->table[i], user,
				table->table[i].user_data);
	}
}

static void eloop_trace_sock_remove_ref(struct eloop_sock_table *table){
	int i;
	if (table == NULL || table->table == NULL)
		return;
	for(i = 0; i < table->count; i++) {
		hack_trace_remove_ref(&table->table[i], user,
				table->table[i].user_data);
	}
}

#else /* WPA_TRACE*/
#define eloop_trace_sock_add_ref(table) do { } while (0)
#define eloop_trace_sock_remove_ref(table) do { } while (0)

#endif /* WPA_TRACE */

int eloop_init(void) {
	os_memset(&eloop, 0, sizeof(eloop));
	dl_list_init(&eloop->timeout);
#ifdef CONFIG_ELOOP_EPOLL
	eloop.epollfd = epoll_create1(0);
	if(eloop.epollfd < 0) {
		log_printf(MSG_ERROR, "%s: epoll_create1 failed. %s",
				__func__,strerror(errno));
		return -1;
	}
#endif /* CONFIG_ELOOP_EPOLL */
#ifdef CONFIG_ELOOP_KQUEUE
	eloop.kqueuefd = kqueue();
	if (eloop.kqueuefd < 0) {
		log_printf(MSG_ERROR, "%s: kqueue failed: %s",
				__func__,strerror(errno));
	}
#endif /* CONFIG_ELOOP_KQUEUE */
#if defined(CONFIG_ELOOP_EPOLL) || defined(CONFIG_ELOOP_KQUEUE)
	eloop.readers.type = EVENT_TYPE_READ;
	eloop.writeers.type = EVENT_TYPE_WRITE;
	eloop.exceptions.type = EVENT_TYPE_EXCEPTION;
#endif /* CONFIG_ELOOP_EPOLL || CONFIG_ELOOP_KQUEUE */
#ifdef WPA_TRACE
	signal(SIGSEGV, eloop_sigsegv_handler);
#endif /* WPA_TRACE */
	return 0;
}

#ifdef CONFIG_ELOOP_EPOLL
static int eloop_sock_queue(int sock, eloop_event_type type) {
	struct epoll_event ev;
	os_memset(&ev, 0, sizeof(ev));
	switch(type) {
	case EVENT_TYPE_READ:
		ev.events = EPOLLIN;
	break;
	case EVENT_TYPE_WRITE:
		ev.events = EPOLLOUT;
	break;
	/**
	 * Exceptions are always checked when using epoll, but I suppose it's
	 * possible that somone registered a socket *only* for exception 
	 * handling.
	 */
	case EVENT_TYPE_EXCEPTION:
		ev.events = EPOLLERR | EPOLLHUP;
		break;
	}
	return 0;
}
#endif /* CONFIG_ELOOP_EPOLL */

#ifdef CONFIG_ELOOP_KQUEUE
static int eloop_sock_queue(int sock, eloop_event_type type) {
	int filter;
	struct kevent ke;

	switch (type) {
	case EVENT_TYPE_READ:
		filter = EVFILT_READ;
		break;
	case EVENT_TYPE_WRITE:
		filter = EVFILT_WRITE;
		break;
	default:
		filter = 0;
	}
	EV_SET(&ke, sock, filter, EV_ADD, 0, 0, 0);
	if (kevent(eloop.kqueuefd, &ke, 1, NULL) == -1) {
		log_printf(MSG_ERROR, "%s: kevent(ADD) for fd=%d failed: %s",
				__func__,eloop.kqueuefd,strerror(errno));
		return -1;
	}
	return 0;
}
#endif /* CONFIG_ELOOP_KQUEUE */

static int eloop_sock_table_add_sock(struct eloop_sock_table *table,
					int sock, eloop_sock_handler handler,
					void *eloop_data, void *user_data){
#ifdef CONFIG_ELOOP_EPOLL
	struct epoll_event *temp_event;
#endif /* CONFIG_ELOOP_EPOLL */
#ifdef CONFIG_ELOOP_KQUEUE
	struct kevent *temp_event;
#endif /* CONFIG_ELOOP_KQUEUE */
#if defind(CONFIG_ELOOP_EPOLL) || defined(CONFIG_ELOOP_KQUEUE)
	struct eloop_sock *temp_table;
	int next;
#endif /* CONFIG_ELOOP_EPOLL || CONFIG_ELOOP_KQUEUE */
	struct eloop_sock *tmp;
	int new_max_sock;

	if (sock > eloop.max_sock)
		new_max_sock = sock;
	else
		new_max_sock = eloop.max_sock;

	if (table == NULL)
		return -1;

#ifdef CONFIG_ELOOP_POLL
	if (new_max_sock >= eloop.max_pollfd_map) {
		struct pollfd **nmap;
		nmap = os_realloc_array(eloop.pollfd_map, new_max_sock + 50,
					sizeof(struct pollfd *));
		if (nmap == NULL) 
			return -1;

		eloop.max_pollfd_map = new_max_sock + 50;
		eloop.pollfds_map = nmap;
	}

	if (eloop.count + 1 > eloop.max_poll_fds) {
		struct pollfd *n;
		int nmax = eloop.count + 1 + 50;
	}
}
