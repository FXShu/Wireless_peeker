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
