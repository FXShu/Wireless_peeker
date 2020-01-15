#include "split.h"

int find_info_tag(char *arg, int arg_size, const char *tag1, const char *info) {
	const char *p;
	char tag[128], *q;

	p = info;
	if (*p == '?')
		p++;
	for(;;) {
		q = tag;
		while (*p != '\0' && *p != '=' && *p != '&') {
			if ((q - tag) < sizeof(tag) - 1)
				*q++ = *p;
			p++;
		}
		*q = '\0';
		q = arg;
		if (*p == '=') {
			p++;
			while(*p != '&' && *p != '\0') {
				if ((q - arg) < arg_size - 1) {
					if (*p == '+')
						*q++ = ' ';
					else
						*q++ = *p;
				}
				p++;
			}
		}
		*q = '\0';
		if (!strcmp(tag, tag1))
			return 1;
		if (*p != '&')
			break;
		p++;
	}
	return 0;
}
