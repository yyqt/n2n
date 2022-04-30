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
	//���ݵ�ַ
	char *data;
	////����������
	//u_int32_t buflen;
	////���ݳ���
	//u_int32_t datalen;
	////�Ƿ��ѽ�ѹ��1�ѽ�ѹ��2�ѷ���
	//u_int8_t state;
	//���ͣ�1���ܷ��ͣ�2�������룩
	u_int8_t type;
} queueItem_t;

//һ�����ζ��У��̰߳�ȫ��
typedef struct multiThreadQueue
{
	//���ݻ���
	queueItem_t datalist[BUFFERLEN];
	//��ǰλ��
	u_int16_t enqueueIndex;
	//����λ��
	u_int16_t dequeueIndex;
	//���д������ź�
	sem_t semiToConsume;
	//���������ź�
	sem_t semiToProduce;
	//���Զ˵���
	pthread_mutex_t lock4Queue;
	//���Զ˵���
	pthread_mutex_t lock4CheckPeer;
	//�����սڵ����
	pthread_mutex_t lock4UpdatePeer;
	//״̬��Ϊ1������2�˳�
	u_int8_t state;
} *multiThreadQueue_t;


/*


1��semiToProduce ȡ���������ź�
2��lock lock4Queue
3��enqueueIndex++
4��datalist[enqueueIndex]=value  ���
5��release lock4Queue
5��port semiToConsume �ͷ��������ź�

readTunTapThread:
1��semiToConsume ȡ���������ź�
2��lock lock4Queue
3��dequeueIndex++
4��return datalist[dequeueIndex] ����
5��release lock4Queue
6��decrypt/encrypt
7��send to socket/tap
8��post semiToProduce �ͷ��������ź�




*/


//ԭ���Լ�
long safeIncrement(long *num);

//ԭ���Լ�
long safeDecrement(long* num);
void* proc(void* arg);
void t();

multiThreadQueue_t createQueue();
void enqueue(multiThreadQueue_t queue, char* data, u_int8_t type);
struct queueItem dequeue(multiThreadQueue_t queue);
void sendproc(multiThreadQueue_t queue);
void startConsumers(multiThreadQueue_t queue, int threadcount);