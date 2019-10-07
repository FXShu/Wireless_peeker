#include "terminal.h"
#include <termios.h>
#include <unistd.h>
#include "common.h"

static char cmdbuf[CMD_BUF_LEN];
static int cmdbuf_pos = 0;
static int cmdbuf_len = 0;
static char currbuf[CMD_BUF_LEN];
static int currbuf_valid = 0;
static const char *ps2 = NULL;

static struct dl_list history_list;
static struct edit_history *history_curr;

static void *edit_cb_ctx;
static void (*edit_cmd_cb)(void *ctx, char *cmd);
static void (*edit_eof_cb)(void *ctx);
static char ** (*edit_completion_cb)(void *ctx, const char *cmd, int pos) = NULL;

static struct termios prevt, newt;

#define CLEAR_END_LINE "\e[K"

static void histroy_add(const char *str) {
	struct edit_history *h, *match = NULL, *last = NULL;
	size_t len, count = 0;
	if (str[0] == '\0') 
		return;
	dl_list_for_each(h, &history_list, struct edit_history, list) {
		if (!strcmp(str, h->str)) {
			match = h;
			break;
		}
		last = h;
		count++;
	}
	if (match) {
		dl_list_del(&h->list);
		dl_list_add(&history_list, &h->list);
		history_curr = h;
		return;
	}

	if (count >= HISTORY_MAX && last) {
		dl_list_del(&last->list);
		free(last);
	}

	len = strlen(str);
	h = zalloc(sizeof(*h) + len);
	if (!h)
		return;
	dl_list_add(&history_list, &h->list);
	os_strlcpy(h->str, str, len + 1);
	history_curr = h;
}

static void history_read(const char *history_file) {
	FILE *history_f;
	char buf[CMD_BUF_LEN], *pos;
	history_f = fopen(history_file, "r");
	if (!history_f) {
		strerror(errno);
		return;
	}

	while(fgets(CMD_BUF_LEN, buf, history_f)) {
		for(pos = buf; *pos; pos++) {
			if(*pos == '\r' || *pos == '\n') {
				*pos = '\0';
				break;
			}
		}
		histroy_add(buf);
	}

}

int terminal_init(void (*cmd_cd)(void *ctx, char *cmd),
	      void (*eof_cd)(void *ctx), 
	      char ** (*completion_cb)(void *ctx, const char *cmd, int pos), 
	      void *ctx, const char *history_file, const char *ps) {
	currbuf[0] = '\0';
	dl_list_init(&history_list);
	history_curr = NULL;
	if (history_file)
		history_read(history_file);
}
