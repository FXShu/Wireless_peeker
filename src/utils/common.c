#include "common.h"

void * __hide_aliasing_typecast(void *foo) {
	return foo;
}

void * zalloc(size_t size) {
	return calloc(1, size);
}
