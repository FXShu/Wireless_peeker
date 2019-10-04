#include <termios.h>
#include <unistd.h>
#include "common.h"

static char cmdbuf[CMD_BUF_LEN];
static int cmdbuf_pos = 0;
static int cmdbuf_len = 0;
static char currbuf[CMD_BUF_LEN];
static int currbuf_valid = 0;
static const char *ps2 = NULL;

int edit_init(void (*cmd_cd)(void *ctx, char *cmd),
	      void (*eof_cd)(void *ctx), 
	      char ** (*completion_cb)(void *ctx, const char *cmd, int pos), 
	      void *ctx, const char *history_file, const char *ps) {
	currbuf[0] = '\0';
}
