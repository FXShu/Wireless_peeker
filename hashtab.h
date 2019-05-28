#ifndef HASH_TABLE_H
#define HASH_TABLE_H
#include<string.h>
#include<stdlib.h>

typedef struct {
	char* key;
	char* value;
	struct node *next;
}node;

typedef struct {
	struct node** nodes;
	int max_node_index;
	int(*hesh)(struct hash_table* table,char* key);
	int(*search)(struct hash_table* table,struct node* node);
	int(*insert)(struct hash_table* table,struct node* node);
	int(*cancel)(struct hash_table* table,struct node* node);
}hash_table;

void free_node(struct node** n);
struct node* create_node(char* key,char* value);
void print_hashtable(struct hash_table* table);
int init_hashtable(hash_table* table,int size);

#endif
