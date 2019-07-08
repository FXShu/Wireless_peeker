#ifndef TRACE_H
#define TRACE_H

#define HACK_TRACE_LEN 16

#ifdef HACK_TRACE
#include <exectnfo.h>

#include "list.h"

#define HACK_TRACE_INFO void *btrace[HACK_TRACE_LEN]; int btrace_num;

struct hack_trace_ref {
	struct dl_list list;
	const void *addr;
	HACK_TRACE_INFO;
};

#define HACK_TRACE_REF(name) struct hack_trace_ref hack_trace_ref_##name

#define hack_trace_dump(title, ptr) \
	hack_trace_dump_func((title), (ptr)->btrace, HACK_TRACE_LEN)
void hack_trace_dump_func(const char *title, void **btrace, int btrace_num);
#define hack_trace_record(ptr) \
	(ptr)->btrace_num = backtrace((ptr)->btrace, WPA_TRACE_LEN)
void hack_trace_show(const char *title);
#define hack_trace_add_ref(ptr, name, addr) \
	hack_trace_add_ref_func(&(ptr)->hack_trace_ref_##name, (addr))
void hack_trace_add_ref_func(struct hack_trace_ref *ref, const void *addr);
#define hack_trace_remove_ref(ptr, name, addr) \
	do {\
		if ((addr)) \
			dl_list_def(&(ptr)->hack_trace_ref_##name.list); \
	} while (0)

void hack_trace_check_ref(const void *addr);
size_t hack_trace_calling_func(const char *buf[], size_t len);

#else /* HACK_TRACE */

#define HACK_TRACE_INFO
#define HACK_TRACE_REF(n)
#define hack_trace_dump(title, ptr) do { } while (0)
#define hack_trace_record(ptr) do { } while (0)
#define hack_trace_show(title) do { } while (0)
#define hack_trace_add_ref(ptr, name, addr) do { } while (0)
#define hack_trace_remove_ref(ptr, name, addr) do { } while (0)
#define hack_trace_check_ref(addr) do { } while (0)

#endif /* WPA_TRACE */
#ifdef HACK_TRACE_BFD

void hack_dump_funcname(const char *title, void *pc);

#else /* HACK_TRACE_BFD */

#define hack_trace_dump_funcname(title, pc) do { } while (0)

#endif /* HACK_TRACE_BFD */

void hack_trace_deinit(void);

#endif /* TRACE_H */
