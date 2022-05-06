#pragma once
#include "list.h"

list_t list_create(int (*p) (void* data1, void* data2)) {
	list_t t = malloc(sizeof(struct list_s));
	memset(t, 0, sizeof(struct list_s));
	t->comparer = p;
	list_resize(t, 32);
	return t;
}

void list_resize(list_t list, int len) {
	if (list->len >= len) {
		return;
	}
	void** tofree = list->data;
	unsigned int oldlen = list->len;
	list->len = len;
	list->data = malloc(sizeof(void*) * list->len);
	if (tofree != NULL) {
		memcpy(list->data, tofree, oldlen * sizeof(void*));
		free(tofree);
	}
}

void list_destory(list_t list) {
	void** tofree = list->data;
	list->data = NULL;
	list->len = 0;
	list->used = 0;
	if (tofree != NULL) {
		free(tofree);
	}
}

void list_insert(list_t list, void* data, unsigned int offset) {
	if (list->used >= list->len) {
		list_resize(list, list->len + 32);
	}
	if (offset >= list->used) {
		list->data[list->used] = data;
		printf("set data[%d]=%d, data=%d \r\n", list->used, data, *((int*)data));
		list->used++;
	}
	else {
		void** temp = malloc(sizeof(void*) * list->used);
		memcpy(temp, list->data, list->used * sizeof(void*));
		list->data[offset] = data;
		memcpy(&(list->data)[offset + 1], &temp[offset], (list->used - offset) * sizeof(void*));
		free(temp);
		printf("set data[%d]=%d, data=%d \r\n", offset, data, *((int*)data));
		list->used++;
	}
}

int list_indexOf4add(list_t list, void* data, int startOffset, int endOffset) {
	if (endOffset - startOffset <= 1) {
		if (list->comparer(data, list->data[startOffset]) == 0) {
			return startOffset;
		}
		else if (list->comparer(data, list->data[endOffset]) == 0) {
			return endOffset;
		}
		else {
			return -1;
		}
	}
	else {
		int mid = (startOffset + endOffset) / 2;
		int c = list->comparer(data, list->data[mid]);
		if (c < 0) {
			return list_indexOf4add(list, data, startOffset, mid - 1 > startOffset ? mid - 1 : startOffset);
		}
		else if (c > 0) {
			return list_indexOf4add(list, data, mid + 1 < endOffset ? mid + 1 : endOffset, endOffset);
		}
		else {
			return mid;
		}
	}
}

void list_add(list_t list, void* data) {

	if (list->used == 0) {
		list_insert(list, data, 0);
		return;
	}
	int idx = list_indexOf2(list, data, 0, list->used - 1);
	list_insert(list, data, idx);
	//for (unsigned int i = 0; i < list->used; i++) {
	//	printf("compare %d ,handle=%d ,addr1=%d, addr2=%d\r\n", i, list->comparer, &(list->data)[i],list->data+i*sizeof(void*));
	//	int c = list->comparer(data, (list->data[i]));
	//	printf("compare %d result %d \r\n", i, c);
	//	if (c <= 0) {
	//		//insert at i
	//		list_insert(list, data, i);
	//		return;
	//	}
	//}
	////insert at list->used
	//list_insert(list, data, list->used);
}

int list_indexOf(list_t list, void* data) {
	if (list->used == 0) {
		return -1;
	}
	int idx = list_indexOf2(list, data, 0, list->used - 1);
	if (idx >= list->used) {
		return -1;
	}
	if (list->comparer(data, list->data[idx]) != 0) {
		return -1;
	}
	return idx;
}

int list_indexOf2(list_t list, void* data, int startOffset, int endOffset) {
	int c1 = list->comparer(data, list->data[startOffset]);
	if (c1 <= 0) {
		return startOffset;
	}
	int c2 = list->comparer(data, list->data[endOffset]);
	if (c2 == 0) {
		return endOffset;
	}
	else if (c2 > 0) {
		return endOffset + 1;
	}

	if (startOffset + 1 == endOffset) {
		return endOffset;
	}


	int mid = (startOffset + endOffset) / 2;
	int c = list->comparer(data, list->data[mid]);
	if (c < 0) {
		// data < mid && data > startoffset
		if (mid <= startOffset + 1) {
			return mid;
		}
		return list_indexOf2(list, data, startOffset + 1, mid - 1);
	}
	else if (c > 0) {
		//data > mid && data < endoffset
		if (mid + 1 >= endOffset) {
			return mid + 1;
		}
		return list_indexOf2(list, data, mid + 1, endOffset - 1);
	}
	else {
		return mid;
	}
}

void* list_get(list_t list, int index) {
	if (index < 0 || index >= list->used) {
		return NULL;
	}
	return list->data[index];
}

int cppeer(void* d1, void* d2) {
	//printf("comparing d1=%d, d2=%d\r\n", d1, d2);
	int s = *((int*)d1);
	int s2 = *((int*)d2);
	//printf("comparing s=%d, s2=%d\r\n", s, s2);
	if (s < s2)return -1;
	else if (s > s2) return 1;
	else return 0;
}

void list_test() {
	list_t list = list_create(cppeer);
	int d1 = 0;
	int d2 = 2;
	int d3 = 5;
	int d4 = 1;
	int d5 = 7;
	printf("list created \r\n");
	list_add(list, &d1);
	//printf("list added 1 \r\n");
	//for (int i = 0; i < list->used; i++) {
	//	printf("list[%d]=%d data=%d\r\n", i, list_get(list, i), *((int*)list_get(list, i)));
	//}
	list_add(list, &d2);
	//printf("list added 2 \r\n");
	//for (int i = 0; i < list->used; i++) {
	//	printf("list[%d]=%d data=%d\r\n", i, list_get(list, i), *((int*)list_get(list, i)));
	//}
	list_add(list, &d3);
	//printf("list added 3 \r\n");
	//for (int i = 0; i < list->used; i++) {
	//	printf("list[%d]=%d data=%d\r\n", i, list_get(list, i), *((int*)list_get(list, i)));
	//}
	list_add(list, &d4);
	printf("list added \r\n");
	for (int i = 0; i < list->used; i++) {
		printf("list[%d]=%d data=%d\r\n", i, list_get(list, i), *((int*)list_get(list, i)));
	}
	int idx = list_indexOf(list, &d3);
	printf("find index = %d,dt=%d \r\n", idx, *((int*)list_get(list, idx)));

	/*idx = list_indexOf(list, &d1);
	printf("find index = %d,dt=%d \r\n", idx, *((int*)list_get(list, idx)));
	idx = list_indexOf(list, &d2);
	printf("find index = %d,dt=%d \r\n", idx, *((int*)list_get(list, idx)));
	idx = list_indexOf(list, &d4);
	printf("find index = %d,dt=%d \r\n", idx, *((int*)list_get(list, idx)));*/
	idx = list_indexOf(list, &d5);
	printf("find index = %d \r\n", idx);

	//int d[10000];
	//for (int i = 0; i < 10000; i++) {
	//	d[i] = i*3;
	//	list_add(list, &d[i]);
	//}

	//idx = list_indexOf(list, &d[4332]);
	//printf("find index = %d,dt=%d \r\n", idx, *((int*)list_get(list, idx)));
}