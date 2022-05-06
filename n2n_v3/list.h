#pragma once

#include "n2n.h"

typedef struct list_s {
	unsigned int len;
	unsigned int used;
	void** data;
	int (*comparer) (void* data1, void* data2);
} * list_t;


list_t list_create(int (*p) (void* data1, void* data2));
void list_resize(list_t list, int len);
void list_destory(list_t list);
void list_insert(list_t list, void* data, unsigned int offset);
void list_add(list_t list, void* data);
int list_indexOf(list_t list, void* data);
int list_indexOf2(list_t list, void* data, int startOffset, int endOffset);
void* list_get(list_t list, int index);
void list_test();
int cppeer(void* d1, void* d2);