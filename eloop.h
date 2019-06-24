#ifndef ELOOP_H
#define ELOOP_H
#include<sys/epoll.h>


/**
 * eloop_event_type - eloop socket event type for eloop_register_sock()
 * @EVENT_TYPE_READ: Socket has data acailable for reading
 * @EVENT_TYPE_WRITE: Socket has room for new data to be written
 * @EVENT_TYPE_EXCEPTION: An exception has been reported
 */
typedef enum {
	EVENT_TYPE_READ = 0,
	EVENT_TYPE_WRITE,
	EVENT_TYPE_EXCEPTION
} eloop_event_type;

// eloop_sock_handler - eloop socket event callback type 
typedef void (*eloop_sock_handler)(int sock, void *eloop_ctx, void *sock_ctx);

//eloop_event_handler - eloop generic event callback type
typedef void (*eloop_event_handler)(void *eloop_data,void *user_ctx);


// eloop_timeout_handler - eloop timeout event callback type
typedef void (*eloop_timeout_handler)(void *eloop_data, void *user_ctx);

// eloop_signal_handler - eloop signal event callback type
typedef void (*eloop_signal_handler)(int sig, void *signal_ctx);

/**
 * eloop_init() - Initialize global event loop data
 * Returns: 0 on success, -1 on failure
 *
 * This function must be called before any other eloop_* function,
 */
int eloop_init(void);

/**
 * eloop_register_read_sock - Register handler for read events
 * Return: 0 on success, -1 on failure
 * 
 * Register a read socket notifier for the given file descriptor. The handler
 * function will be called whenever data is available for reading from the 
 * socket. The handler function is responsible for clearing the event after
 * having processed it in order to avoid eloop from calling the handler again
 * for the same event
 */
int eloop_register_read_sock(int sock, eloop_sock_handler handler,
				void *eloop_data, void *user_data);

// eloop_unregister_read_sock - Unregister handler for read events
void eloop_unregister_read_sock(int sock);

/**
 * eloop_register_sock - Register handler for scoket events
 * Return: 0 on success, -1 on failure
 *
 * Register on event notifier for the given socket's file descriptor. The
 * handler function will be called whenever the that event is triggered for the
 * socket. The handler function is responsible for clearing the event after
 * having processed it in order to avoid eloop from calling the handler again
 * for the same event
 */
int eloop_register_sock(int sock, eloop_event_type type,
			eloop_sock_handler handler,
			void *eloop_data, void *user_data);

// eloop_unregister_sock - Unregister handler for socker events
void eloop_unregister_sock(int sock,eloop_event_type type);

/**
 * eloop_register_event - Register handler for generic events
 * Return: 0 on success, -1 on failure
 *
 * Register an event handler for the given event. This function is used to
 * register eloop implementation specific events which are mainly targeted for
 * operating system specific code (driver interface and l2_packet) since the 
 * portable code will not be able to use such an OS-specific call. The handler
 * function will ve called whenever the event is triggered. The handler
 * function is responsible for clearing the event after having oricessed it in
 * order to avoid eloop from calling the handler again for the same event.
 */

int eloop_register_event(void *event, size_t event_size,
			eloop_event_handler handler,
			void *eloop_data, void *user_data);
#endif //ELOOP_H

