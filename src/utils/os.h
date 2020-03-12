#ifndef OS_H
#define OS_H

#include "includes.h"
#ifdef WPA_TRACE
void * os_malloc(size_t size);
void * os_realloc(void *ptr, size_t size);
void os_free(void *ptr);
char * os_strdup(const char *s);
#else /* WPA_TRACE */
#ifndef os_malloc
#define os_malloc(s) malloc((s))
#endif
#ifndef os_realloc
#define os_realloc(p, s) realloc((p), (s))
#endif
#ifndef os_free
#define os_free(p) free((p))
#endif
#ifndef os_strdup
#ifdef _MSC_VER
#define os_strdup(s) _strdup(s)
#else
#define os_strdup(s) strdup(s)
#endif
#endif
#endif /* WPA_TRACE */

#ifndef os_memcpy
#define os_memcpy(d, s, n) memcpy((d), (s), (n))
#endif
#ifndef os_memmove
#define os_memmove(d, s, n) memmove((d), (s), (n))
#endif
#ifndef os_memset
#define os_memset(s, c, n) memset(s, c, n)
#endif
#ifndef os_memcmp
#define os_memcmp(s1, s2, n) memcmp((s1), (s2), (n))
#endif

#ifndef os_snprintf
#ifdef _MSC_VER
#define os_snprintf _snprintf
#else
#define os_snprintf snprintf
#endif
#endif

#define SET(offset, nums) nums |= (1 << offset)

typedef long os_time_t;

void os_sleep(os_time_t sec, os_time_t usec); 

struct os_time {
	os_time_t sec;
	os_time_t usec;
};

struct os_reltime {
	os_time_t sec;
	os_time_t usec;
};

static inline void * os_realloc_array(void *ptr, size_t nmemb, size_t size) {
	if (size && nmemb > (~(size_t) 0 /size))
		return NULL;
	return os_realloc(ptr, nmemb * size);
}

static inline int os_reltime_before(struct os_reltime *a,
				struct os_reltime *b){
	return (a->sec < b->sec) || 
		(a->sec == b->sec && a->usec < b->usec);
}

static inline void os_reltime_sub(struct os_reltime *a, struct os_reltime *b,
				  struct os_reltime *res) {
	res->sec = a->sec - b ->sec;
	res->usec = a->usec - b->usec;
	if (res->usec < 0 ) {
		res->sec--;
		res->usec += 1000000;
	}
}

static inline int os_reltime_expired(struct os_reltime *now, 
		struct os_reltime *ts, os_time_t timeout_secs)
{
	struct os_reltime age;

	os_reltime_sub(now, ts, &age);
	return (age.sec > timeout_secs) ||
	(age.sec == timeout_secs && age.usec > 0);
}

void * os_zalloc(size_t size);
int os_get_reltime(struct os_reltime *t);
size_t os_strlcpy(char *dest,const char *src, size_t siz);

char *os_get_hw_info();
char *os_get_os_info();
#endif /* OS_H */
