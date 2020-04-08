#include <sys/mman.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include "loglog.h"
#include "wcomm.h"

struct winfo *wcomm_remove(struct wcomm *wm)
{
	const struct winfo *cwif;
	struct winfo *wif;

	assert(!wcomm_empty(wm));
	cwif = wm->pointers[wm->tail];
	assert(cwif->wpkt.len < MAX_TXSIZE - sizeof(struct winfo));
	wif = malloc(cwif->wpkt.len + sizeof(struct winfo));
	if (!check_pointer(wif))
		return NULL;
	wif->srcaddr = cwif->srcaddr;
	wif->wpkt = cwif->wpkt;
	memcpy(wif->wpkt.pkt, cwif->wpkt.pkt, cwif->wpkt.len);
	wcomm_tail_inc(wm);
	return wif;
}

void wcomm_exit(struct wcomm *wm)
{
	int sysret;

	sysret = pthread_mutex_destroy(&wm->wmtx);
	if (sysret)
		logmsg(LOG_ERR, "pthread_mutex_destroy failed: %s\n",
				strerror(sysret));
	sysret = pthread_cond_destroy(&wm->wcd);
	if (sysret)
		logmsg(LOG_ERR, "pthread_cond_destroy failed: %s\n",
				strerror(sysret));
	munmap(wm, sizeof(struct wcomm));
}

struct wcomm *wcomm_init(void)
{
	int i, sysret;
	char *curchr;
	struct wcomm *wm;

	wm = mmap(NULL, sizeof(struct wcomm), PROT_NONE|PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (unlikely(wm == MAP_FAILED)) {
		wm = NULL;
		check_pointer(wm);
		return wm;
	}
	sysret = pthread_cond_init(&wm->wcd, NULL);
	if (unlikely(sysret)) {
		logmsg(LOG_ERR, "pthread_cond_init failed: %s\n",
				strerror(errno));
		munmap(wm, sizeof(struct wcomm));
		return NULL;
	}
	sysret = pthread_mutex_init(&wm->wmtx, NULL);
	if (unlikely(sysret)) {
		logmsg(LOG_ERR, "pthread_cond_init failed: %s\n",
				strerror(errno));
		munmap(wm, sizeof(struct wcomm));
		pthread_cond_destroy(&wm->wcd);
		return NULL;
	}
	wm->tail = 0;
	wm->head = 0;
	curchr = wm->buf;
	for (i = 0; i < MAX_POINTER; i++) {
		wm->pointers[i] = curchr;
		curchr += MAX_TXSIZE;
	}
	return wm;
}

void wcomm_signal(struct wcomm *wm)
{
	struct timespec tm;

	tm.tv_sec = 1;
	tm.tv_nsec = 0;
	while (wcomm_full(wm))
		nanosleep(&tm, NULL);
	pthread_mutex_lock(&wm->wmtx);
	wcomm_head_inc(wm);
	pthread_cond_signal(&wm->wcd);
	pthread_mutex_unlock(&wm->wmtx);
}
