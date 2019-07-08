#ifndef OS_H
#define OS_H

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
#endif /* OS_H */
