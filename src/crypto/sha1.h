#ifndef SHA1_H
#define SHA1_H

#include "common.h"
#define SHA1_MAC_LEN 20

#define SHA1_CTX SHA_CTX
#define SHA1Init SHA1_Init
#define SHA1Update SHA1_Update
#define SHA1Final SHA1_Final

typedef struct {
	SHA1_CTX k_ipad;
	SHA1_CTX k_opad;
	/*
	 *   unsigned char k_ipad[65];
	 *   unsigned char k_opad[65];
	 */
	unsigned char k_ipad_set;
	unsigned char k_opad_set;
} SHA1_CACHE;


int hmac_sha1_vector(unsigned char *key, size_t key_len, size_t num_elem,
					unsigned char *addr[], const size_t *len, unsigned char *mac, int usecached);

int hmac_sha1(unsigned char *key, size_t key_len, unsigned char *data, 
		size_t data_len, unsigned char *mac, int usecached);

int pbkdf2_sha1(char *passphrase, char *ssid, size_t ssid_len
		, int iterations, unsigned char *buf, size_t buflen, int usecached);


int sha1_prf(unsigned char *key, unsigned int key_len, char *label,
		    unsigned char *data, unsigned int data_len, unsigned char *buf, size_t buf_len);

#endif /* SHA1_H */


