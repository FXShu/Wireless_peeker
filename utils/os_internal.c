#include "includes.h"
#include <time.h>
#include <sys/wait.h>

#undef OS_REJECT_LIB_FUNCTIONS
#include "common.h"

void os_sleep(os_time_t sec, os_time_t usec) {
	if (sec)
		sleep(sec);
	if (usec)
		usleep(usec);
}
