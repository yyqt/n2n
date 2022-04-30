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
	multiThreadQueue_t  queue = createQueue();
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

multiThreadQueue_t createQueue() {
	int size0 = sizeof(struct multiThreadQueue);
	multiThreadQueue_t mutex = malloc(size0);
	memset(mutex, 0, size0);
	pthread_mutex_init(&mutex->lock4Queue, NULL);
	pthread_mutex_init(&mutex->lock4CheckPeer, NULL);
	pthread_mutex_init(&mutex->lock4UpdatePeer, NULL);
	/*mutex->lock4Queue = PTHREAD_MUTEX_INITIALIZER;
	mutex->lock4CheckPeer = PTHREAD_MUTEX_INITIALIZER;
	mutex->lock4UpdatePeer= PTHREAD_MUTEX_INITIALIZER;*/
	sem_init(&mutex->semiToConsume, 0, 0);
	sem_init(&mutex->semiToProduce, 0, BUFFERLEN-1);
	//printf("queue created");
	return mutex;
}

void enqueue(multiThreadQueue_t queue, char* data, u_int8_t type) {
	if (sem_wait(&queue->semiToProduce) == 0) {
		struct queueItem s;// *s = malloc(sizeof(struct queueItem));
		s.data = data;
		s.type = type;
		if (pthread_mutex_lock(&queue->lock4Queue) == 0) {
			u_int16_t curridx = queue->enqueueIndex++;
			curridx = curridx % BUFFERLEN;
			queue->datalist[curridx] = s;
			pthread_mutex_unlock(&queue->lock4Queue);
			traceEvent(TRACE_INFO, "入队列：%d，index=%d\r\n", s.type, curridx);
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

queueItem_t dequeue(multiThreadQueue_t queue) {
	if (sem_wait(&queue->semiToConsume) == 0) {
		if (pthread_mutex_lock(&queue->lock4Queue) == 0) {
			u_int16_t curridx = queue->dequeueIndex++;
			curridx = curridx % BUFFERLEN;
			queueItem_t s = queue->datalist[curridx];
			pthread_mutex_unlock(&queue->lock4Queue);
			sem_post(&queue->semiToProduce);
			traceEvent(TRACE_INFO, "出队列：%d,index=%d\r\n", s.type, curridx);
			return s;
		}
	}
	queueItem_t item;
	item.data = NULL;
	item.type = 0;
	return item;
}
static long threadcc = 0;
void sendproc(multiThreadQueue_t queue) {
	long threadid = safeIncrement(&threadcc);
	traceEvent(TRACE_NORMAL, "sendproc线程%d启动\r\n", threadid);
	while (queue->state != 2) {
		queueItem_t item = dequeue(queue); //消息
		if (item.data == NULL) {
			continue;
		}
		//printf("出列列：%d\r\n", item.type);
		switch (item.type)
		{
		case 1: //向socket发送
		{
			sending_pkg t = item.data;
			(*t->p)(t);
			break;
		}
		case 2: //向tap发送
		{
			recving_pkg t = item.data;
			(*t->p)(t);
			break;
		}
		default:
			break;
		}
	}
	traceEvent(TRACE_NORMAL, "sendproc线程%d退出\r\n", threadid);
}

void startConsumers(multiThreadQueue_t queue, int threadcount) {
	for (int i = 0; i < threadcount; i++) {
		pthread_t p1;
		pthread_create(&p1, NULL, sendproc, queue);
	}
}


int lockOne(pthread_mutex_t* m)
{
	return pthread_mutex_lock(m);
}
int releaseOne(pthread_mutex_t* m) {
	return pthread_mutex_unlock(m);
}