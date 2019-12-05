#ifndef HASH_TABLE_H
#define HASH_TABLE_H
#include<string.h>
#include<stdlib.h>
#include<stdio.h>
#include<stdint.h>

struct node{
	char *key;
	char *value;
	struct node *next;
};

struct hash_table{
	struct node** nodes;
	int max_node_index;
	int(*hash)(struct hash_table* table,char* key);
	int(*search)(struct hash_table* table,struct node* node);
	int(*insert)(struct hash_table* table,struct node* node);
	int(*cancel)(struct hash_table* table,struct node* node);
};

void free_node(struct node** n);
struct node* create_node(char* key,char* value);
void print_hashtable(struct hash_table* table);
int init_hashtable(struct hash_table* table,int size);

#endif
