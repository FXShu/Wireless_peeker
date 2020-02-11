#ifndef LIST_H
#define LIST_H
#include "common.h"
/**
 * struct dl_list - Doubly-linked list
 */
struct dl_list {
	struct dl_list *next;
	struct dl_list *prev;
};

#define DL_LIST_HEAD_INIT(l) { &(l), &(l) }

static inline void dl_list_init(struct dl_list *list) {
	list->next = list;
	list->prev = list;
}

static inline void dl_list_add(struct dl_list *list, struct dl_list *item) {
	item->next = list->next;
	item->prev = list;
	list->next->prev = item;
	list->next = item;
}

static inline void dl_list_add_tail(struct dl_list *list, struct dl_list *item) {
	dl_list_add(list->prev, item);
}

static inline void dl_list_del(struct dl_list *item) {
	item->next->prev = item->prev;
	item->prev->next = item->next;
	item->next = NULL;
	item->prev = NULL;
}

static inline int dl_list_empty(struct dl_list *list){
	return list->next == list;
}

static inline unsigned int dl_list_len(struct dl_list *list){
	struct dl_list *item;
	int count = 0;
	for(item = list->next;item != list; item = list->next){
		count ++;
	}
	return count;
}

#ifndef offsetof
#define offsetof(type, member)  ((long) &((type *) 0)->member)
#endif

#define LOCATE(conv, object, type, member) ((conv *) ((char *)object + offsetof(type, member)))

#define dl_list_entry(item, type, member) \
	((type *) ((char *) item - offsetof(type, member)))

#define dl_list_first(list, type, member) \
	(dl_list_empty((list)) ? NULL : \
	 dl_list_entry((list)->next, type, member))

#define dl_list_last(list, type, member) \
	(dl_list_empty((list)) ? NULL : \
	 dl_list_entry((list)->prev, type, member))

#define dl_list_for_each(item, list, type, member) \
	for (item = dl_list_entry((list)->next, type, member); \
			&item->member != (list); \
			item = dl_list_entry(item->member.next,type, member))

#define dl_list_for_each_safe(item, n, list, type, member) \
	for (item = dl_list_entry((list)->next, type, member), \
			n = dl_list_entry(item->member.next, type, member); \
		&item->member != (list); \
		item = n, n = dl_list_entry(item->member.next, type, member))

#define DEFINE_DL_LIST(name) \
	struct dl_list name = { &(name), &(name) }

#endif /* LIST_H */
