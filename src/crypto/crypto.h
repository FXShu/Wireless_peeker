#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"
/**
 * sha1_vector - SHA-1 hash for data vector
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash
 * Returns: 0 on success, -1 on failure
 **/
int sha1_vector(size_t num_elem, const uint8_t *addr[], const size_t *len,
		                uint8_t *mac);

#endif /* CRYPTO_H */
