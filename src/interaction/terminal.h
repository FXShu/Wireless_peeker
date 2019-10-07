#ifndef INTERACTION_TERMINAL_H
#define INTERACTION_TERMINAL_H

#include "common.h"
#define CMD_BUF_LEN 4096
#define HISTORY_MAX 100

struct edit_history{
	struct dl_list list;
	char str[1];
};

int terminal_init(void (*cmd_cd)(void *ctx, char *cmd),
	      void (*eof_cd)(void *ctx),
	      char ** (*completion_cd)(void *ctx, const char *cmd, int pos),
	      void *ctx, const char *history_file, const char *ps);

#endif /* INTERACTION_TERMINAL_H */
