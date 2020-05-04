#include <time.h>
#include <assert.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "tok_block.h"
#include "ripemd160.h"
#include "loglog.h"
#include "global_param.h"

#define ZBITS	25

static const unsigned short VER = 100;

static const unsigned char gensis[] = "Startup of Electronic Token " \
				      "Blockchain. All started from Oct 2019 with Dashi Cao.";

static int num_zerobits(const unsigned char *hash)
{
	int zbits = 0, i, j;
	const unsigned char *p = hash;
	unsigned char cb, bbit;

	for (i = 0; i < SHA_DGST_LEN; i++, p++) {
		cb = *p;
		bbit = 0x80;
		for (j = 8; j > 0; j--) {
			if ((cb & bbit) == 0)
				zbits++;
			else
				break;
			bbit = (bbit >> 1);
		}
		if (j > 0)
			break;
	}
	return zbits;
}

static inline void blhdr_hash(unsigned char *dgst, const struct bl_header *hdr)
{
	sha256_dgst_2str(dgst, (const unsigned char *)hdr,
			sizeof(struct bl_header));
}

int zbits_blkhdr(const struct bl_header *hdr, unsigned char *dgst)
{
	unsigned char shabuf[SHA_DGST_LEN];
	unsigned char *sha_dgst;

	if (dgst == NULL)
		sha_dgst = shabuf;
	else
		sha_dgst = dgst;
	blhdr_hash(sha_dgst, hdr);
	return num_zerobits(sha_dgst);
}

struct th_arg {
	struct bl_header *hdr;
	volatile int *fin;
	char up;
	char zbits;
	volatile char th_flag;
};

static void *nonce_search(void *arg)
{
	unsigned char dgst[SHA_DGST_LEN];
	struct th_arg *tharg = arg;
	int zerobits = 0;
	unsigned long nonce = tharg->hdr->nonce;

	assert(tharg->up == -1 || tharg->up == 1);
	do {
		tharg->hdr->nonce += tharg->up;
		if (tharg->hdr->nonce == nonce)
			break;
		zerobits = zbits_blkhdr(tharg->hdr, dgst);
	} while (zerobits < g_param->mine.zbits && *tharg->fin == 0);
	tharg->zbits = zerobits;
	*tharg->fin = 1;
	tharg->th_flag = -1;
	return NULL;
}

int block_mining(struct bl_header *hdr, volatile int *fin)
{
	unsigned char dgst[SHA_DGST_LEN];
	struct th_arg thargs[2];
	struct bl_header *hdrs[2];
	pthread_t upth, downth;
	pthread_attr_t thattr;
	int zbits, sysret, who;
	struct timespec tm0, tm1, intvl;

	blhdr_hash(dgst, hdr);
	zbits = num_zerobits(dgst);
	if (zbits >= g_param->mine.zbits)
		return zbits;
	sysret = pthread_attr_init(&thattr);
	if (sysret) {
		logmsg(LOG_ERR, "pthread attr init failed: %s\n",
				strerror(sysret));
		return zbits;
	}
	sysret = pthread_attr_setdetachstate(&thattr, PTHREAD_CREATE_DETACHED);
	if (unlikely(sysret)) {
		logmsg(LOG_ERR, "pthread attr set detach failed: %s\n",
				strerror(sysret));
		return zbits;
	}

	hdrs[0] = malloc(2*sizeof(struct bl_header));
	hdrs[1] = hdrs[0] + 1;
	*hdrs[0] = *hdr;
	*hdrs[1] = *hdr;
	thargs[0].hdr = hdrs[0];
	thargs[0].up = 1;
	thargs[0].zbits = zbits;
	thargs[0].fin = fin;
	thargs[0].th_flag = 0;
	thargs[1].hdr = hdrs[1];
	thargs[1].up = -1;
	thargs[1].fin = fin;
	thargs[1].zbits = zbits;
	thargs[1].th_flag = 0;

	clock_gettime(CLOCK_MONOTONIC_RAW, &tm0);
	sysret = pthread_create(&upth, &thattr, nonce_search, thargs);
	if (unlikely(sysret)) {
		logmsg(LOG_ERR, "pthread create failed: %s\n", strerror(sysret));
		thargs[0].th_flag = -1;
	} else
		thargs[0].th_flag = 1;
	sysret = pthread_create(&downth, &thattr, nonce_search, thargs+1);
	if (unlikely(sysret)) {
		logmsg(LOG_ERR, "pthread create failed: %s\n", strerror(sysret));
		thargs[1].th_flag = -1;
	} else
		thargs[1].th_flag = 1;

	intvl.tv_sec = 1;
	intvl.tv_nsec = 0;
	while (thargs[0].th_flag == 1 || thargs[1].th_flag == 1)
		nanosleep(&intvl, NULL);
	clock_gettime(CLOCK_MONOTONIC_RAW, &tm1);
	zbits = thargs[0].zbits;
	who = 0;
	if (zbits < thargs[1].zbits) {
		zbits = thargs[1].zbits;
		who = 1;
	}

	*hdr = *thargs[who].hdr;
	free(hdrs[0]);
	assert(*fin == 1);
	return time_elapsed(&tm0, &tm1);
}

int gensis_block(char *buf, int size)
{
	int len, zbits;
	struct etk_block *etblock;
	struct bl_header *bhdr;
	volatile int fin = 0;

	len = sizeof(gensis) + sizeof(struct etk_block) +
		sizeof(struct txrec_area);
	if (size < len)
		return -1;

	etblock = (struct etk_block *)buf;
	memset(etblock, 0, sizeof(struct etk_block));
	etblock->area_len = sizeof(struct txrec_area) + sizeof(gensis);
	etblock->tx_area[0].txlen = sizeof(gensis);
	memcpy(etblock->tx_area[0].txbuf, gensis, sizeof(gensis));
	sha256_dgst_2str(etblock->tx_area[0].txhash, gensis, sizeof(gensis));
	bhdr = &etblock->hdr;
	bl_header_init(bhdr, NULL);
	sha256_dgst_2str(bhdr->mtree_root, etblock->tx_area[0].txhash,
			SHA_DGST_LEN);
	zbits = block_mining(bhdr, &fin);
	logmsg(LOG_ERR, "Time used: %d milliseconds\n", zbits);

	return sizeof(struct etk_block) + sizeof(struct txrec_area) +
		etblock->tx_area[0].txlen;
}

void bl_header_init(struct bl_header *blkhdr, const unsigned char *dgst)
{
	struct timespec tm;
	struct ripemd160 ripe;

	memset(blkhdr, 0, sizeof(struct bl_header));
	clock_gettime(CLOCK_REALTIME, &tm);

	blkhdr->tm = tm.tv_sec;
	blkhdr->ver = VER;
	blkhdr->zbits = g_param->mine.zbits;
	if (dgst)
		memcpy(blkhdr->prev_hash, dgst, SHA_DGST_LEN);
	ripemd160_reset(&ripe);
	ripemd160_dgst(&ripe, (const unsigned char *)blkhdr,
			sizeof(struct bl_header));
	blkhdr->nonce = ripe.H[1];
	blkhdr->nonce = (blkhdr->nonce << 32) | ripe.H[0];
	blkhdr->node_id = g_param->node.nodeid;
}
