#ifndef WCOMM_DSCAO__
#define WCOMM_DSCAO__
#include <pthread.h>
#include <sys/socket.h>
#include <my_global.h>
#include <mysql.h>

#define MAX_POINTER 64
#define MAX_POINTER_MASK 0x3f
#define MAX_TXSIZE 2048

enum TX_TYPE {TX_REC = 1, UTXO_REQ = 2};

struct wpacket {
	unsigned short len;
	unsigned short ptype;
	char pkt[0];
};

struct winfo {
	struct sockaddr_storage srcaddr;
	struct wpacket wpkt;
};

struct wcomm {
	void *pointers[MAX_POINTER];
	char buf[MAX_POINTER*MAX_TXSIZE];
	pthread_cond_t wcd;
	pthread_mutex_t wmtx;
	int sock;
	volatile short tail;
	short head;
};

static inline int wcomm_empty(const struct wcomm *wm)
{
	return wm->head == wm->tail;
}

static inline int wcomm_full(const struct wcomm *wm)
{
	return ((wm->head + 1) & MAX_POINTER_MASK) == wm->tail;
}

static inline struct winfo *wcomm_getarea(struct wcomm *wm)
{
	return wm->pointers[wm->head];
}

static inline void wcomm_head_inc(struct wcomm *wm)
{
	wm->head = (wm->head + 1) & MAX_POINTER_MASK;
}

static inline void wcomm_tail_inc(struct wcomm *wm)
{
	wm->tail = (wm->tail + 1) & MAX_POINTER_MASK;
}

void wcomm_exit(struct wcomm *wm);
struct wcomm *wcomm_init(void);

const struct winfo *wcomm_getload(struct wcomm *wm);
void wcomm_signal(struct wcomm *wm);

#endif /* WCOMM_DSCAO__ */
