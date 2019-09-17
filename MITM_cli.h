#ifndef MITM_CLI_H
#define MITM_CLI_H

typedef void (*command)(struct *MITM, void *user_ctx);
struct MITM_link_ops {
	char *kind;
	command cmd;
};

#endif /* MITM_CLI_H */
