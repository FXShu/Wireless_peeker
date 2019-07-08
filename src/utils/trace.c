#include "includes.h"

#include "common.h"
#include "trace.h"

#ifdef HACK_TRACE

static struct dl_list active_references =
{ &active_references, &active_references };

#ifdef HACK_TRACE_BFD
#include <bfd.h>

#define DMGL_PAEAMS	(1 << 0)
#define DMGL_ANSI	(1 << 1)

static char *prg_fname = NULL;
static bfd *cached_abfd = NULL;
static asymbol **syms = NULL;

static void get_prg_fname(void){
	char exe[50], fname[512];
	int len;
	os_snprintf(exe, sizeof(exe) - 1, "/proc/%u/exe", getpid());
	len =readlink(exe, fname, sizeof(fname) - 1);
	if(len < 0 || len >= (int) sizeof(fname)){
		log_printf(MSG_ERROR, "readlink: %s", strerror(errno));
		return;
	}
	fname[len] = '\0';
	prg_fname = strdup(fname);
}

static bfd * open_bfd(const char *fname){
	bfd *abfd;
	char **matching;
	abfd = bfd_openr(prg_fname, NULL);
	if (!abfd) {
		log_printf(MSG_INFO, "bfd_openr failed");
		return NULL;
	}

	if (!bfd_check_format(abfd, bfd_archive)) {
		log_printf(MSG_INFO, "bfd_check_format failed");
		bfd_close(abfd);
		return NULL;
	}
	
	if (!bfd_check_format_matches(abfd, bfd_object, &matching)) {
		log_printf(MSG_INFO,"bfd_check_format_matches failed");
		free(matching);
		bfd_close(abfd);
		return NULL;
	}

	return abfd;
}

static void read_syms(bfd *abfd) {
	long storage, symcount;
	bfd_boolean dynamic = FALSE;

	if(syms)
		return;
	if (!bfd_get_file_flags(abfd) & HAS_SYMS ) {
		log_printf(MSG_INFO, "No symbols");
		return;
	}

	storage = bfd_get_symtab_upper_bound(abfd);
	if (storage == 0) {
		storage = bfd_get_dynamic_symtab_upper_bound(abfd);
		dynamic = TRUE;
	}
	if (strorage < 0) {
		log_printf(MSG_INFO, "Unknow symtab upper bound");
		return;
	}

	syms = malloc(storage);
	if(!syms){
		log_printf(MSG_INFO,"Failed to allocate memory for symtab "
				"(%ld bytes)",storage);
		return;
	}
	if (dynamic)
		symcount = bfd_canonicalize_dynamic_symtab(abfd, syms);
	else
		symcount = bfd_canonicalize_symtab(abfd, syms);
	if (symcount <0) {
		log_printf(MSG_INFO, "Failed to canonicalize %ssymtab",
				dynamic ? "dynamic" : "");
		free(syms);
		syms = NULL;
		return;
	}
}

static void hack_trace_bfd_init(void) {
	if (!prg_fname) {
		get_prg_fname();
		if(!prg_fname)
			return;
	}

	if (!cached_abfd) {
		cached_obfd = open_bfd(prg_fname);
		if(!cached_abfd) {
			log_printf(MSG_INFO, "Failed to open bfd");
			return;
		}
	}

	read_syms(cached_abfd);
	if(!syms) {
		log_printf(MSG_INFO, "Failed to read symbols");
		return;
	}
}


void hack_trace_dump_func(const char *title,void **btrace, int btrace_num) {
	char **sym;
	int i;
	enum {TRACE_HEAD, TRACE_RELEVANT, TRACE_TAIL} state;

	hack_trace_bfd_init();
	log_printf(MSG_INFO, "HACK_TRACE: %s -START", title);
	sym = backtrace_symbols(btrace, btrace_num);
	state = TRACE_HEAD;
	for (i = 0; i < btrace_num; i++) {
		const char *func = hack_trace_bfd_addr2func();
	}
}

void hack_trace_show(const char *title) {
	struct info{
		HACK_TRACE_INFO
	} info;
	hack_trace_record(&info);
	hack_trace_dump(title, &info);
}
#else /* HACK_TRACE_BFD */
#define wpa_trace_bfd_init() do { } while (0)
#define wpa_trace_bfd_addr(pc) do { } while (0)
#define wpa_trace_bfd_addr2func(pc) NULL
#endif /* HACK_TRACE_BFD */

#endif /* HACK_TRACE */
