#pragma once
#pragma comment(lib,"libpthread.lib")

#ifdef WIN32
#define HAVE_STRUCT_TIMESPEC
#endif
#include "n2n.h"
#include <pthread.h>
#include <semaphore.h>
#define BUFFERLEN 512

typedef struct queueItem
{
	//数据地址
	char *data;
	////缓冲区长度
	//u_int32_t buflen;
	////数据长度
	//u_int32_t datalen;
	////是否已解压，1已解压，2已发送
	//u_int8_t state;
	//类型（1加密发送，2解密输入）
	u_int8_t type;
} queueItem_t;

//一个环形队列（线程安全）
typedef struct multiThreadQueue
{
	//数据缓冲
	queueItem_t datalist[BUFFERLEN];
	//当前位置
	u_int16_t enqueueIndex;
	//发送位置
	u_int16_t dequeueIndex;
	//队列待消费信号
	sem_t semiToConsume;
	//队列生产信号
	sem_t semiToProduce;
	//检查对端的锁
	pthread_mutex_t lock4Queue;
	//检查对端的锁
	pthread_mutex_t lock4CheckPeer;
	//更新终节点的锁
	pthread_mutex_t lock4UpdatePeer;
	//状态，为1正常，2退出
	u_int8_t state;
} *multiThreadQueue_t;


/*


1、semiToProduce 取得生产者信号
2、lock lock4Queue
3、enqueueIndex++
4、datalist[enqueueIndex]=value  入队
5、release lock4Queue
5、port semiToConsume 释放消费者信号

readTunTapThread:
1、semiToConsume 取得消费者信号
2、lock lock4Queue
3、dequeueIndex++
4、return datalist[dequeueIndex] 出队
5、release lock4Queue
6、decrypt/encrypt
7、send to socket/tap
8、post semiToProduce 释放生产者信号




*/


//原子自加
long safeIncrement(long *num);

//原子自减
long safeDecrement(long* num);
void* proc(void* arg);
void t();

multiThreadQueue_t createQueue();
void enqueue(multiThreadQueue_t queue, char* data, u_int8_t type);
struct queueItem dequeue(multiThreadQueue_t queue);
void sendproc(multiThreadQueue_t queue);
void startConsumers(multiThreadQueue_t queue, int threadcount);