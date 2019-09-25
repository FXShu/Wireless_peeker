#include "os.h"

size_t os_strlcpy(char *dest, const char *src, size_t siz) {
	const char *s = src;
	size_t left = size;

	if (left) {
		/* copy string up the maximun size of the dest buffer */
		while (--left != 0) {
			if ((*dest ++ = *s++) == '\0')
				break;
		}
	}

	if (left == 0) {
		/* Not enough room for the string: force NUL-termination */
		if (size != 0)
			*dest = '\0';
		while (*s++)
			; /* determine total src string length */
	}

	return s - src -1;
}

int os_get_reltime(struct timeval tv) {
#if defi
}
