#include "os.h"

size_t os_strlcpy(char *dest, const char *src, size_t size) {
	const char *s = src;
	size_t left = size;

	if (left) {
		/* copy string up the maximun size of the dest buffer */
		while (--left != 0) {
			if ((*dest ++ = *s++) == '\0')
				break;
		}
	}

	if (left == 0) {
		/* Not enough room for the string: force NUL-termination */
		if (size != 0)
			*dest = '\0';
		while (*s++)
			; /* determine total src string length */
	}

	return s - src -1;
}

int os_get_reltime(struct os_reltime *t) {
#if defined(CLOCK_BOOTTIME)
	static clockid_t clock_id = CLOCK_BOOTTIME;
#elif defined(CLOCK_MONOTONIC)
	static clockid_t clock_id = CLOCK_MONOTONIC;
#else
	static clockid_t clock_id = CLOCK_REALTIME;
#endif
	struct timespec ts;
	int res;

	while (1) {
		res = clock_gettime(clock_id, &ts);
		if (res == 0) {
			t->sec  = ts.tv_sec;
			t->usec = ts.tv_nsec / 1000;
			return 0;
		}
		switch (clock_id) {
#ifdef CLOCK_BOOTTIME
		case CLOCK_BOOTTIME:
			clock_id = CLOCK_MONOTONIC;
			break;
#endif /* CLOCK_BOOTTIME */
#ifdef CLOCK_MONOTONIC
		case CLOCK_MONOTONIC:
			clock_id = CLOCK_REALTIME;
			break;
#endif
		case CLOCK_REALTIME:
			return -1;
		}
	}
}
/* call this function to check if target time is exceed pervious time
 * over %sec second %usec microseconds.
 * prev: previous time
 * next: target time
 * Return: nonzero for true, zero for false
 * */
/*int os_reltime_expired (struct timeval *prev, struct timeval *next,
	       	time_t sec, suseconds_t usec) {
	struct timeval tmp;
	tmp.tv_sec  = sec;
	tmp.tv_usec = usec;

	timeradd(prev, &tmp, &tmp);

	return timercmp(next, &tmp, >);	
}*/

char *os_get_hw_info() {
 FILE *fp;
  char *info;
  info = malloc(200);
  if (!info) {
    printf("Alloc memory failed, with error :%s\n", strerror(errno));
    return NULL;
  }
  fp = popen("lshw | grep CPU | grep version | awk -F: '{print $2}'", "r");
  if (!fp) {
    printf("Run 'lshw' command failed, with error :%s\n", strerror(errno));
    return NULL;
  }
  fgets(info, 200, fp);
  pclose(fp);
  return info;
}

char *os_get_os_info() {
  FILE *fp;
  char *info;
  info = malloc(200);
  if (!info) {
    printf("Alloc memory failed, with error :%s\n", strerror(errno));
    return NULL;
  }
  fp = popen("uname -v", "r");
  if (!fp) {
    printf("Run 'lshw' command failed, with error :%s\n", strerror(errno));
    return NULL;
  }
  fgets(info, 200, fp);
  pclose(fp);
  return info;
}
