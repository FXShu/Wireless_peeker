#ifndef ELOOP_H
#define ELOOP_H

/**
 * ELOOP_ALL_CTX - eloop_cancel_timeout() magic number to match all timeouts
 * */
#define ELOOP_ALL_CTX (void*) -1

#include<sys/epoll.h>
#include "os.h"

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

/**
 * eloop_sock_handler - eloop socket event callback type 
 */
typedef void (*eloop_sock_handler)(int sock, void *eloop_ctx, void *sock_ctx);

/**
 * eloop_event_handler - eloop generic event callback type
 */
typedef void (*eloop_event_handler)(void *eloop_data,void *user_ctx);


/**
 * eloop_timeout_handler - eloop timeout event callback type
 */
typedef void (*eloop_timeout_handler)(void *eloop_data, void *user_ctx);

/**
 * eloop_signal_handler - eloop signal event callback type
 */
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

/**
 * eloop_unregister_read_sock - Unregister handler for read events
 */
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

/**
 * eloop_unregister_sock - Unregister handler for socker events
 */
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

/**
 * eloop_unregister_event - Unregister handler for a generic event 
 * eloop_reguster_event().
 */
void eloop_unreigster_event(void *event, size_t event_size);

/**
 * eloop_register_timeout - Register timeout
 * @secs: Number of seconds to the timeout
 * @usecs: Number of microseconds to the timeout
 * @handler: Callback function to be called when timeout occurs
 * @eloop: Callback context data (eloop_ctx)
 * @user_data: Callback context data (sock_ctx)
 * Return: 0 on success, -1 on failure
 *
 * Register a timeout that will casue the handler function to be called after
 * given time
 */
int eloop_register_timeout(unsigned int secs, unsigned int usecs,
			eloop_timeout_handler handler,
			void *eloop_data, void *user_data);

/**
 * eloop_cancel_timeout - Cancel timeouts
 * @handler: Matching callback function
 * Returns: Number of cancelled timeouts
 *
 * Cancel matching <handler, eloop_data, user_data> timeouts registered with
 * eloop_register_timeout(). ELOOP_ALL_CTX can be used as a wildcard for 
 * cancelling all timeouts regardless of eloop_data/user_data.
 */
int eloop_cancel_timeout(eloop_timeout_handler handler,
			void *eloop_data, void *user_data);

/**
 * eloop_cancel_timeout_one - Cancel a single timeout
 * @handler: Matching callback function
 * @remaining: Time left on the cancelled timer
 * Returns: Number of cancelled timeouts
 *
 * Cancel matching <handler, eloop_data, user_data> timeout registered with
 * eloop_register_timeout() and return the remaining time left.
 */
int eloop_cancel_timeout_one(eloop_timeout_handler handler,
				void *eloop_data, void *user_data,
				struct os_reltime *remaining);

/**
 * eloop_is_timeout_registered - Check if a timeout is already registered
 * Return: 1 if the timeout is registered, 0 if no change is made, -1 if no
 * timeout matched
 */
int eloop_is_timeout_registered(eloop_timeout_handler handler,
				void *eloop_data, void *user_data);


/**
 * eloop_deplete_timeout - Deplete a timeout that is already registered
 * @req_secs: Requested number of seconds to the timeout
 * @req_usecs: Requested number of microseconds to the timeout
 * Return: 1 if the timeout is depleted, 0 if no change is made, -1 if no
 * timeout matched
 *
 * Find a registered matching <handler, eloop_data, user_data> timeout. If found,
 * deplete the timeout if remaining time is more than the requested time.
 */
int eloop_deplete_timeout(unsigned int req_secs, unsigned int req_uses,
			eloop_timeout_handler handler, void *eloop_data,
			void *user_data);



/**
 * eloop_replenish_timeout - Replenish a timeout that is already registered
 * Returns: 1 if the timeout is replenished, 0 if no change is made, -1 if no 
 * timeout matched
 *
 * Find a registered matching <handler, eloop_data, user_data> timeout. If found,
 * replenish the timeout if remaining time is less than the requested time.
 */
int eloop_replenish_timeout(unsigned int req_secs, unsigned int req_usecs,
			eloop_timeout_handler handler, void *eloop_data,
			void *user_data);

/**
 * eloop_register_signal_terminate - Reigster handler for terminate signals
 * Returns: 0 on success, -1 on failure
 *
 * Register a callback function that will be called when a process termination
 * signal is received. The callback function is actually called only after the 
 * system signal handler has returned. This means that the normal limits for
 * sighandlers (i.e., only "safe functions" allowd) do not apply for the
 * registered callback.
 *
 * This functions is a more portable version of eloop_register_signal() since
 * the knowledge of exact details of the signals is hidden in eloop
 * implementation. In case of operating systems using signal(), this function
 * registers handlers for SIGINT and SIGTERM.
 */
int eloop_register_signal_terminate(eloop_signal_handler handler,
					void *user_data);


/**
 * eloop_register_signal_reconfig - Register handler for reconfig signals
 * @handler: Callback function to be called when the signal is received
 * Returns: 0 on success, -1 on failure
 *
 * Register a callback function that will be called when a reconfiguration
 * handup signal is received. Yhe callback function is catually called only
 * after the system signal handler has returned. This means that the normal
 * limits for sighandlers (i.e., only "safe functions" allowed)do not apply 
 * for the registered callback.
 *
 * This function is a more portable version of eloop_register_signal() since 
 * the knowledge of exact details of the signals is hidden in eloop
 * implementation. In case of operating systems using signal(), this function
 * registers a handler for SIGHUP
 */
int eloop_register_signal_reconfig(eloop_signal_handler handler,
				void *user_data);

/**
 * eloop_sock_requeue - Requeue sockets
 *
 * Requeue sockets after forking because some implementations require this,
 * such as epoll and kqueue.
 */
int eloop_sock_requeue(void);

/**
 * eloop_run -Start the event loop
 *
 * start the event loop and continue running as long as there ate any
 * registered event handlers. This function is run after event loop has been
 * initialized with event_init() and one or more events have been registered.
 */
void eloop_run(void);

/**
 * eloop_terminate - Terminate event loop
 *
 * Terminate event loop even if there are registered events. This can be used 
 * to request the program to be terminated cleanly
 */
void eloop_terminate(void);

/**
 * eloop_wait_for_read_sock - Wait for a single reader
 * @sock: File descriptor number for the scoket
 *
 * Do a blocking wait for singal read scoket.
 */
void eloop_wait_for_read_sock(int sock);
#endif //ELOOP_H

