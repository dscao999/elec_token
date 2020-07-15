#include <sys/mman.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include "loglog.h"
#include "wcomm.h"
#include "global_param.h"

const struct winfo *wcomm_getload(struct wcomm *wm)
{
	const struct winfo *cwif;

	assert(!wcomm_empty(wm));
	cwif = wm->pointers[wm->tail];
	assert(cwif->wpkt.len < MAX_TXSIZE - sizeof(struct winfo));
	return cwif;
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
		check_pointer(NULL);
		return NULL;
	}
	sysret = pthread_cond_init(&wm->wcd, NULL);
	if (unlikely(sysret)) {
		logmsg(LOG_ERR, "pthread_cond_init failed: %s\n",
				strerror(errno));
		goto err_exit_10;
	}
	sysret = pthread_mutex_init(&wm->wmtx, NULL);
	if (unlikely(sysret)) {
		logmsg(LOG_ERR, "pthread_cond_init failed: %s\n",
				strerror(errno));
		goto err_exit_20;
	}
	wm->tail = 0;
	wm->head = 0;
	curchr = wm->buf;
	for (i = 0; i < MAX_POINTER; i++) {
		wm->pointers[i] = curchr;
		curchr += MAX_TXSIZE;
	}

	return wm;

err_exit_20:
	pthread_cond_destroy(&wm->wcd);
err_exit_10:
	munmap(wm, sizeof(struct wcomm));
	return NULL;
}

void wcomm_signal(struct wcomm *wm)
{
	struct timespec tm;
	int tries = 0;

	tm.tv_sec = 1;
	tm.tv_nsec = 0;
	while (wcomm_full(wm)) {
		if (tries++ % 10 == 0)
			logmsg(LOG_WARNING, "Too much load comming, " \
					"Queue Full!");
		nanosleep(&tm, NULL);
	}
	pthread_mutex_lock(&wm->wmtx);
	wcomm_head_inc(wm);
	pthread_cond_signal(&wm->wcd);
	pthread_mutex_unlock(&wm->wmtx);
}
