#ifndef HASH_TABLE_H
#define HASH_TABLE_H
#include<string.h>
#include<stdlib.h>

typedef struct {
	char* name;
	char* desc;
	struct hash_node *next;
}node;

typedef struct {
	struct node** nodes;
	int max_node_index;
	int(*hesh)(struct hash_table* table,char* key);
	int(*search)(struct hash_table* table,struct node* node);
	int(*insert)(struct hash_table* table,struct node* node);
	int(*free)(struct hash_table* table,struct node* node);
}hash_table

void free_node(struct node** n);
struct node* create_node(char* key,char* value);
int compare_node(struct node* dst,struct node* src);

void init_hash_table(hash_node* node,int size);

#endif
