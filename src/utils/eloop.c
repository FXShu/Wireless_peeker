#include "includes.h"
#include <assert.h>

//#include "common.h"
#include "trace.h"
#include "list.h"
#include "eloop.h"
//#include "os.h"

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
	dl_list_init(&eloop.timeout);
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
	ev.data.fd = sock;
	if (epoll_ctl(eloop.epollfd, EPOLL_CTL_ADD, sock, &ev) < 0){
		log_printf(MSG_ERROR, "%s: epoll_ctl(ADD) for fd=%d failed: %s",
					__func__, sock, strerror(errno));
		return -1;
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
#if defined(CONFIG_ELOOP_EPOLL) || defined(CONFIG_ELOOP_KQUEUE)
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
		nmap = os_realloc_array(eloop.pollfds_map, new_max_sock + 50,
					sizeof(struct pollfd *));
		if (!nmap) 
			return -1;

		eloop.max_pollfd_map = new_max_sock + 50;
		eloop.pollfds_map = nmap;
	}

	if (eloop.count + 1 > eloop.max_poll_fds) {
		struct pollfd *n;
		int nmax = eloop.count + 1 + 50;
		n = os_realloc_array(eloop.pollfds_map, new_max_sock + 50,
					sizeof(struct pollfd *));
		if (!n)
			return -1;
		eloop.max_poll_fds = nmax;
		eloop.pollfds = n ;
	}
#endif /* CONFIG_ELOOP_POLL */
#if defined(CONFIG_ELOOP_EPOLL) || defined(CONFIG_ELOOP_KQUEUE)
	if (new_max_sock >= eloop.max_fd) {
		next = eloop.max_fd == 0 ? 16 : eloop.max_fd * 2;
		temp_table = os_realloc_array(eloop.fd_table, next,
						 sizeof(struct eloop_sock));
		if(!temp_table)
			return -1;

		eloop.max_fd = next;
		eloop.fd_table = temp_table;
	}
#endif /* CONFIG_ELOOP_EPOLL || COBFIG_ELOOP_KQUEUE */

#ifdef CONFIG_ELOOP_EPOLL
	if (eloop.count + 1 > eloop.epoll_max_event_num) {
		next = eloop.epoll_max_event_num == 0 ? 8 :
			eloop.epoll_max_event_num * 2;
		temp_events = os_realloc_array(eloop.epoll_events, next,
						sizeof(struct epoll_events));
		if (!temp_events) {
			log_printf(MSG_ERROR, "%s: malloc for epoll failed: %s",
						__func__,strerror(errno));
			return -1;
		}

		eloop.epoll_max_event_num = next;
		eloop.epoll_events = temp_events;
	}
#endif /* CONFIG_ELOOP_EPOLL */
#ifdef CONFIG_ELOOP_KQUEUE
	if (eloop.count + 1 > eloop.kqueue_nevents) {
		next = eloop.kqueue_nevents == 0 ? 8 : eloop.kqueue_nevents * 2;
		temp_events = os_malloc(next * sizeof(*temp_events));
		if (!temp_events) {
			log_printf(MSG_ERROR,
					"%s: malloc for kqueue failed: %s",
					__func__,strerror(errno));
			return -1;
		}

		os_free(eloop.kqueue_events);
		eloop.kqueue_events = temp_events;
		eloop.kqueue_nevents = next;
	}
#endif /* CONFIG_ELOOP_KQUEUE */

	eloop_trace_sock_remove_ref(table);
	tmp = os_realloc_array(table->table, table->count + 1,
				sizeof(struct eloop_sock));
	if(!tmp){
		eloop_trace_sock_add_ref(table);
		return -1;
	}

	tmp[table->count].sock = sock;
	tmp[table->count].eloop_data = eloop_data;
	tmp[table->count].user_data = user_data;
	tmp[table->count].handler = handler;
	hack_trace_record(&tmp[table->count]);
	table->count++;
	table->table = tmp;
	eloop.max_sock = new_max_sock;
	eloop.count++;
	table->changed =1;
	eloop_trace_sock_add_ref(table);
#if defined(CONFIG_ELOOP_EPOLL) || defined(CONFIG_ELOOP_KQUEUE)
	if (eloop_sock_queue(sock, table->type) < 0)
		return -1;
	os_memcpy(&eloop.fd_table[sock], &table->table[table->count -1],
						sizeof(struct eloop_sock));
#endif /*  CONFIG_ELOOP_EPOLL || CONFIG_ELOOP_KQUEUE */
	return 0;
}

static void eloop_sock_table_remove_sock(struct eloop_sock_table *table,
						int sock) {
#ifdef CONFIG_ELOOP_KQUEUE
	struct kevent ke;
#endif /* CONFIG_ELOOP_KQUEUE */
	int i;

	if (!table || !table->table || !table->count)
		return;
	
	for (i = 0; i < table->count; i++) {
		if (table->table[i].sock == sock)
			break;
	}

	if (i == table->count)
		return;
	eloop_trace_sock_remove_ref(table);
	if (i != table->count -1) {
		os_memmove(&table->table[i], &table->table[i + 1],
				(table->count -i -1) * sizeof(struct eloop_sock));
	}
	table->count--;
	eloop.count--;
	table->changed = 1;
	eloop_trace_sock_add_ref(table);
#ifdef CONFIG_ELOOP_EPOLL
	if (epoll_ctl(eloop.epollfd, EPOLL_CTL_DEL, sock, NULL) < 0) {
		log_printf(MSG_ERROR, "%s: epoll_ctl(DEL) for fd=%d failed: %s", 
				__func__,strerror(errno));
		return;
	}
	os_memset(&eloop.fd_table[sock], 0, sizeof(struct eloop_sock));
#endif /* CONFIG_ELOOP_EPOLL */
#ifdef CONFIG_ELOOP_KQUEUE
	EV_SET(&ke, sock, 0, EV_DELETE, 0, 0, 0);
	if (kevent(eloop.kqueuefd, &ke, 1, NULL, 0, NULL) < 0) {
		log_printf(MSG_ERROR, "%s: kevent(DEL) for fd=%d failed: %s",
				__func__, sock, strerror(errno));
		return;
	}
	os_memset(&eloop.fd_table[sock], 0, sizeof(struct eloop_sock));
#endif /* CONFIG_ELOOP_KQUEUE */
}

#ifdef CONFIG_ELOOP_POLL

static struct pollfd * find_pollfd(struct pollfd **pollfds_map, int fd, int mx) {
	if (fd < mx && fd >= 0)
		return pollfds_map[fd];
	return NULL;
}

static int eloop_sock_table_set_fds(struct eloop_sock_table *readers,
					struct eloop_sock_table *writers,
					struct eloop_sock_table *exceptions,
					struct pollfd *pollfds,
					struct pollfd **pollfds_map,
					int max_pollfd_map) {
	int i;
	int nxt = 0;
	int fd;
	struct pollfd *pfd;

	/* Clear pollfd lookup map, It will be re-populated below */
	os_memset(pollfds_map, 0, sizeof(struct pollfd *) * max_pollfd_map);

	if (readers && readers->table) {
		for (i = 0; i < readers->count; i++) {
			fd = readers->table[i].sock;
			assert(fd >= 0 && fd < max_pollfd_map);
			pollfds[nxt].fd = fd;
			pollfds[nxt].events = POLLIN;
			pollfds[nxt].revents = 0;
			pollfds_map[fd] = &(pollfds[nxt]);
			nxt++;
		}
	}

	if (writers && writers->table) {
		for (i = 0; i < writers->count; i++) {
			/*
			 * See if we already added this descriptor, update it 
			 * if so.
			 */
			fd = writers->table[i].sock;
			assert(fd >= 0 && fd < max_pollfd_map);
			pfd = pollfds_maps[fd];
			if (!pfd) {
				pfd = &(pollfds[nxt]);
				pfd->events = 0;
				pfd->fd = fd;
				pollfds[i].revents = 0;
				pollfds_map[fd] = pfd;
				nxt++;
			}
			pfd->events != POLLOUT;
		}
	}

	/*
	 * Exceptions are always checked when using poll, but I suppose it's
	 * possible that someone registered a socket *only* for exception
	 * handling. Set the POLLIN bit in this case.
	 * */
	if (exceptions && exceptions->table) {
		for (i = 0; i < exceptions->count; i++) {
			/*
			 * See if we already added this descriptor, just use it
			 * if so.
			 */
			fd = exceptions->table[i].sock;
			assert(fd >= 0 && fd < max_pollfd_map);
			pfd = pollfds_map[fd];
			if (!pfd) {
				pfd = &(pollfds[nxt]);
				pfd->events = POLLIN;
				pfd->fd = fd;
				pollfds[i].revents = 0;
				pollfds_map[fd] = pfd;
				nxt++;
			}
		}
	}

	return nxt;
}


static int eloop_sock_table_dispatch_table(struct eloop_sock_table *table,
					struct pollfd **pollfds_map,
					int max_pollfd_map,
					short int revents) {
	int i;
	struct pollfd *pfd;

	if (!table || !table->table) 
		return 0;

	table->changed = 0;
	for (i = 0; i < table->count; i++) {
		pfd =find_pollfd(pollfds_map, table->table[i].sock,max_pollfd_map);
		if (!pfd) 
			continue;

		if (!(pfd->revents & revents))
			continue;

		table->table[i].handler(table->table[i].sock,
					table->table[i].eloop_data,
					table->table[i].user_data);
		if (table-changed)
			return 1;
	}

	return 0;
}

static void eloop_sock_table_dispatch(struct eloop_sock_table *reader,
					struct eloop_sock_table *writer,
					struct eloop_sock_table exeptions,
					struct pollfd **pollfds_map,
					int max_pollfd_map){
	if (eloop_sock_table_dispatch_table(readers, pollfds_map,
						max_pollfd_map, POLLIN | POLLERR | 
						POLLHUP))
		return;

	if (eloop_sock_table_dispatch_table(writers, pollfds_map,
						max_pollfd_map, POLLOUT))
		return;
	eloop_sock_table_dispatch_table(exceptions, pollfds_map,
					max_pollfd_map, POLLERR | POLLHUP);
}

#endif /* CONFIG_ELOOP_POLL */

#ifdef CONFIG_ELOOP_EPOLL

static void eloop_sock_dispatch(struct epoll_event *events, int nfds){
	struct eloop_sock *table;
	int i;

	for (i = 0; i < nfds; i++) {
		table = &eloop.fd_table[events[i].data.fd];
		if(!table->handler)
			continue;
		table->handler(table->sock,table->eloop_data,
				table->user_data);
		if (eloop.reader.changed ||
			eloop.writer.changed ||
			eloop.exceptions.changed)
			break;
	}
}
#endif /* CONFIG_ELOOP_EPOLL */
static void eloop_sock_table_destroy(struct eloop_sock_table *table) {
	if (table) {
		int i;
		for (i = 0; i < table->count && table->table; i++) {
			/*log_printf(MSG_INFO, "ELOOP: remaining socket: "
					"sock=%d eloop_data=%p user_data=%p "
					"handler=%p",
					table->table[i].sock,
					table->table[i].eloop_data,
					table->table[i].user_data,
					table->table[i].handler);*/
			log_printf(MSG_ERROR, "%s: epoll_create1 failed. %s",
					                                __func__,strerror(errno));
			hack_trace_dump_funcname("eloop unregistered socket "
						"handler",
						table-table[i].handler);
			hack_trace_dump("eloop sock", &table->table[i]);
		}
		os_free(table->table);
		
	}
}

int eloop_register_read_sock(int sock, eloop_sock_handler handler,
				void *eloop_data, void *user_data){
	return eloop_register_sock(sock, EVENT_TYPE_READ, handler,
					eloop_data, user_data);
}

static struct eloop_sock_table *eloop_get_sock_table(eloop_event_type type) {
	switch(type) {
		case EVENT_TYPE_READ:
			return &eloop.readers;
		case EVENT_TYPE_WRITE:
			return &eloop.writers;
		case EVENT_TYPE_EXCEPTION:
			return &eloop.exceptions;
	}

	return NULL;
}

int eloop_register_sock(int sock, eloop_event_type type,
				eloop_sock_handler handler, 
				void *eloop_data, void *user_data){
	struct eloop_sock_table *table;

	assert(sock >= 0);
	table = eloop_get_sock_table(type);
	return eloop_sock_table_add_sock(table, sock, handler,
					eloop_data, user_data);
}

void eloop_unregister_sock(int sock, eloop_event_type type) {
	struct eloop_sock_table *table;

	table = eloop_get_sock_table(type);
	eloop_sock_table_remove_sock(table,sock);
}

int eloop_register_timeout(unsigned int secs, unsigned int usecs,
			elooop_timeout_handler handler,
			void *eloop_data, void *user_data){
	struct eloop_timeout *timeout, *tmp;
	os_time_t now_sec;

	timeout = os_zalloc(sizeof(*timeout));
	if(!timeout)
		return -1;
	if (os_get_reltime(&timeout->time) < 0) {
		os_free(timeout);
		return -1;
	}
	now_sec = timeout->time.sec;
	timeout->time.sec += secs;
	if (timeout->time.sec < now_sec) {
		/*
		 * Integer overflow - assum long enough timeout to be assumed
		 * to be infinite, i.e. the timeout would never happed.
		 */
		log_printf(MSG_DEBUG, "ELOOP: Too long timeout (secs=%u) to "
				"ever happen - ignore it", secs);
		os_free(timeout);
		return 0;
	}
	timeout->time.usec += usecs;
	while (timeout->time.usec >= 1000000) {
		timeout->time.sec++;
		timeout->time.usec -= 1000000;
	}
	timeout->eloop_data = eloop_data;
	timeout->user_data = user_data;
	timeout->handler = handler;
	hack_trace_add_ref(timeout, eloop, eloop_data);
	hack_trace_add_ref(timeout, user, user_data);
	hack_trace_record(timeout);

	/* Maintain timeouts in order od increasing time */
	dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
		if (os_reltime_before(&timeout->time, &tmp->time)) {
			dl_list_add(tmp->list.prev, &timeout->list);
			return 0;
		}
	}
	dl_list_add_tail(&eloop.timeout, &timeout->list);

	return 0;
}

static void eloop_remove_timeout(struct eloop_timeout *timeout){
	dl_list_del(&timeout->list);
	hack_trace_remove_ref(timeout, eloop, timeout->eloop_data);
	hack_trace_remove_ref(timeout, user, timeout->user_data);
	os_free(timeout);
}

