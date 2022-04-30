#pragma comment(lib,"libpthread.lib")

#ifdef WIN32
#define HAVE_STRUCT_TIMESPEC
#endif
#include "sendqueue.h"
#include <pthread.h>
#include <semaphore.h>
#include <windows.h>
#ifndef WIN32
#include <asm/atomic.h>
#else
#include <winnt.h>
#endif

long safeIncrement(long* num)
{
#ifdef WIN32
	return InterlockedIncrement(num);
#else
	return atomic_add_return(1, num);
#endif
}

long safeDecrement(long* num)
{
#ifdef WIN32
	return InterlockedDecrement(num);
#else
	return atomic_add_return(-1, num);
#endif
}
sem_t sem;
void t() {
	/*sem_init(&sem, 0, 1);
	pthread_t p1;
	pthread_t p2;
	pthread_create(&p1, NULL, proc, NULL);
	pthread_create(&p1, NULL, proc, NULL);
	Sleep(2000);
	printf("post1 start\r\n");
	sem_post(&sem);
	printf("post1 over\r\n");
	Sleep(2000);
	printf("post2 start\r\n");
	sem_post(&sem);
	printf("post2 over\r\n");*/
	printf("queue creating\r\n");
	struct multiThreadQueue*  queue = createQueue();
	startConsumers(queue, 2);
	Sleep(2000);
	enqueue(queue, NULL, 1);
	Sleep(2000);
	enqueue(queue, NULL, 2);
	Sleep(2000);
	enqueue(queue, NULL, 3);
	Sleep(2000);
}

void* proc(void* arg) {
	printf("wait start\r\n");
	sem_wait(&sem);
	printf("wait over\r\n");
}

struct multiThreadQueue* createQueue() {
	int size0 = sizeof(struct multiThreadQueue);
	struct multiThreadQueue* mutex = malloc(size0);
	memset(mutex, 0, size0);
	mutex->lock4Queue = PTHREAD_MUTEX_INITIALIZER;
	mutex->lock4CheckPeer = PTHREAD_MUTEX_INITIALIZER;
	mutex->lock4UpdatePeer= PTHREAD_MUTEX_INITIALIZER;
	sem_init(&mutex->semiToConsume, 0, 0);
	sem_init(&mutex->semiToProduce, 0, BUFFERLEN-1);
	//printf("queue created");
	return mutex;
}

void enqueue(struct multiThreadQueue* queue, char* data, u_int8_t type) {
	if (sem_wait(&queue->semiToProduce) == 0) {
		struct queueItem s;// *s = malloc(sizeof(struct queueItem));
		s.data = data;
		s.type = type;
		if (pthread_mutex_lock(&queue->lock4Queue) == 0) {
			u_int16_t curridx = queue->enqueueIndex++;
			curridx = curridx % BUFFERLEN;
			queue->datalist[curridx] = s;
			pthread_mutex_unlock(&queue->lock4Queue);
			//printf("入队列：%d\r\n", s.type);
			sem_post(&queue->semiToConsume);
		}
		else {
			//printf("入队列err2：%d\r\n", type);
		}
	}
	else {
		//printf("入队列err：%d\r\n", type);
	}
}

struct queueItem dequeue(struct multiThreadQueue* queue) {
	if (sem_wait(&queue->semiToConsume) == 0) {
		if (pthread_mutex_lock(&queue->lock4Queue) == 0) {
			u_int16_t curridx = queue->dequeueIndex++;
			curridx = curridx % BUFFERLEN;
			struct queueItem s = queue->datalist[curridx];
			pthread_mutex_unlock(&queue->lock4Queue);
			sem_post(&queue->semiToProduce);
			return s;
		}
	}
	struct queueItem item;
	item.data = NULL;
	item.type = 0;
	return item;
}

void sendproc(struct multiThreadQueue* queue) {
	while (1) {
		struct queueItem item = dequeue(queue); //消息
		//printf("出列列：%d\r\n", item.type);
		switch (item.type)
		{
		case 1:
			break;
		case 2:
			break;
		default:
			break;
		}
	}
}

void startConsumers(struct multiThreadQueue* queue, int threadcount) {
	for (int i = 0; i < threadcount; i++) {
		pthread_t p1;
		pthread_create(&p1, NULL, sendproc, queue);
	}
}
