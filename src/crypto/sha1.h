#include "common.h"
#define SHA1_MAC_LEN 20
int sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac);
