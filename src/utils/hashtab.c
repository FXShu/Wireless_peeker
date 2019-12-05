#include"hashtab.h"

int malloc_and_copy_string(char** dst,char* src){
        int len;

        if(*dst || !src){
                return -1;
        }
        len = strlen(src);
        *dst = malloc(len+1);
        memset(*dst,0,len+1);
        strncpy(*dst, src, len);

        return 0;
}

int malloc_and_copy_node(struct node* dst,struct node* src){
	if(!dst || !src){
                return -1;
        }
	if((-1 == malloc_and_copy_string(&(dst->key),src->key)) ||
                        (-1 == malloc_and_copy_string(&(dst->value),src->value))){
                if(dst->key) free(dst->key);
                if(dst->value) free(dst->value);
                return -1;
        }
        dst->next = NULL;
        return 0;
}

int hash(struct hash_table* table,char* key){
	int len, hash_index, char_sum =0;
	char c;

	 if(NULL == table || table->max_node_index <= 0 || NULL == key){
		return -1;
	}

	len = strlen(key);
	while(len-- >0){
		c = *key++;
		char_sum +=(int)c;
	}

	hash_index = char_sum % table->max_node_index;
	return hash_index;
}

int search(struct hash_table* table,struct node* node){
	struct node* cur;
	int hash_index;

	if(table || table->nodes || node || node->key){
		return -1;
	}
	hash_index = table->hash(table,node->key);
	if(hash_index == -1){
		return -1;
	}
	cur = table->nodes[hash_index];
	if(!cur){
		return -1;
	}
	while(cur && strcmp(cur->key,node->key)){
		cur = cur->next;
	}

	if(cur){
		return malloc_and_copy_string(&node->value,cur->value);
	}else{
		return -1;
	}
}

int compare_node(struct node* dst,struct node* src){
	if(!dst || !src){
		return -1;
	}

	if(!strcmp(dst->key,src->key) && !strcmp(dst->value,src->value)){
		return 0;
	}
	return -1;

}

void free_node(struct node** p){
	struct node* n;
	n = *p;
	if(n->key) free(n->key);
	if(n->value) free(n->value);

	n->key = NULL;
	n->value = NULL;

	free(n);
	n = NULL;
}

int insert(struct hash_table* table,struct node* node){
	struct node** cur;
	int hash_index;
	if(!table || !table->nodes || !node || 
			!node->key || !node->value){
		return -1;
	}
	hash_index = table->hash(table,node->key);
	if(hash_index == -1){
		return -1;
	}
	cur = &table->nodes[hash_index];
	while(*cur){
		if(!compare_node(*cur,node)){
			return -1;
		}
		cur = &((*cur)->next);
	}
	*cur = malloc(sizeof(struct node));
	memset(*cur,0,sizeof(struct node));

	return malloc_and_copy_node(*cur,node);
}

int cancel(struct hash_table* table,struct node* node){
	struct node **cur,**next,**prev;
	int hash_index;
	if(!table || !table->nodes || !node ||
			!node->key || !node->value){
		return -1;
	}

	hash_index = table->hash(table,node->key);
	if(hash_index == -1){
		return -1;
	}

	cur = &table->nodes[hash_index];
	if(!*cur){
		return -1;
	}
	next = &((*cur)->next);
	prev = &table->nodes[hash_index];
	do{
		if(!compare_node(*cur,node)){
			free_node(cur);
			*cur = NULL;
			(*prev)->next = *next;
			return 0;
		}

		prev = cur;
		cur = &((*cur)->next);
		next = &((*cur)->next)?&((*cur)->next):NULL;
	}while(*cur);

	return 0;
}

int init_hashtable(struct hash_table* table,int size){
	if(!table || size <= 0){
		return -1;
	}

	table->nodes = malloc(size * sizeof(struct node *));
	if(!table->nodes){
		printf("init: malloc fail with %ld byte\n",size * sizeof(struct node*));
		return -1;
	}
	memset(table->nodes,0,size * sizeof(struct node*));

	table->max_node_index = size;
	table->hash = hash;
	table->search = search;
	table->cancel = cancel;
	table->insert = insert;
	return 0;
}

void print_hashtable(struct hash_table* table){
	int i ;
	struct node* cur;

	if(!table || !table->nodes || table->max_node_index <=0 ){
		return ;
	}
	for(i = 0; i < table->max_node_index; i++){
		cur = table->nodes[i];
		printf("index %d: ",i);
		while(cur){
			printf("[%s]=[%s]",cur->key,cur->value);
			cur = cur->next;
		}
		printf("\n");
	}
}

inline struct node* create_node(char* key,char* value){
	struct node* n;

	n = malloc(sizeof(struct node));
	memset(n,0,sizeof(struct node));
	if(key){
		malloc_and_copy_string(&n->key,key);
	}
	if(value){
		malloc_and_copy_string(&n->value,value);
	}

	return n;
}
