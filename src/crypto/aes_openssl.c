#include <crypto.h>

static const EVP_CIPHER *aes_get_evp_cipher(size_t keylen) {
	switch (keylen) {
	case 16:
		return EVP_aes_128_ecb();
	case 24:
		return EVP_aes_192_ecb();
	case 32:
		return EVP_aes_256_ecb();
	}
	return NULL;
}

void * aes_encrypt_init (const u8 *key, size_t len) {
	EVP_CIPHER_CTX *ctx;

	/* EVP_CIPHER -  structure for symmetric cipher method implementation. */
	const EVP_CIPHER *type;

	type = aes_get_evp_cipher(len);
	if (!type) {
		log_printf(MSG_WARNING, "%s: Unsupported len=%ld", __func__, len);
		return NULL;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return NULL;
	if (EVP_EncryptInit_ex(ctx, type, NULL, key, NULL) != 1) {
		free(ctx);
		return NULL;
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	return ctx;
}

int aes_encrypt(void *ctx, const u8 *plain, u8 *crypt) {
	EVP_CIPHER_CTX *c = ctx;
	int clen = 16;
	if (EVP_EncryptUpdate(c, crypt, &clen, plain, 16) != 1) {
		log_printf(MSG_ERROR, "OpenSSL: EVP_EncryptUpdata failed: %s",
		ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	return 0;
}

void aes_encrypt_deinit(void *ctx) {
	EVP_CIPHER_CTX *c = ctx;
	u8 buf[16];
	int len = sizeof(buf);
	if (EVP_EncryptFinal_ex(c, buf, &len) != 1) {
		log_printf(MSG_ERROR, "OpenSSL: EVP_EncryptFinal_ex failed: %s",
		ERR_error_string(ERR_get_error(), NULL));
	}
	if (len != 0) {
		log_printf(MSG_ERROR, "OpenSSL: Unexpected padding length %d in AES encrypt", len);
	}
	EVP_CIPHER_CTX_free(c);
}
