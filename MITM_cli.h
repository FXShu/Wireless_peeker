#ifndef MITM_CLI_H
#define MITM_CLI_H

#include "common.h"
#include "./src/interaction/mitm_ctrl.h"

typedef void (*command)(struct MITM *mitm, void *user_ctx);
struct MITM_link_ops {
	char *kind;
	command cmd;
};



#endif /* MITM_CLI_H */
