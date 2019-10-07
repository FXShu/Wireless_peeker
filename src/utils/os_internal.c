#include "includes.h"
#include <time.h>
#include <sys/wait.h>
#include "os.h"
#undef OS_REJECT_LIB_FUNCTIONS
#include "common.h"

void os_sleep(os_time_t sec, os_time_t usec) {
	if (sec)
		sleep(sec);
	if (usec)
		usleep(usec);
}
/*
int os_get_reltime(struct os_reltime *t) {
	int res;
	struct timeval tv;
	res = gettimeofday(&tv, NULL);
	t->sec = tv.tv_sec;
	t->usec = tv.tv_usec;
	return res;
}
*/
void * os_zalloc(size_t size) {
	return calloc(1, size);
} 
