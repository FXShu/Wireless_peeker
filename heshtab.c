#include"hashtab.h"

void init_hash_table(hash_node* node,int size){
	for(int i =0; i < size ; i++){
		(node + i) = NULL;
	}
}

unsigned int hash(char* s){
	unsigned int h = 0;
	for(;*s;s+)
		h=*s+h*31;
	return h%
}
