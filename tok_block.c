#include <time.h>
#include <assert.h>
#include <pthread.h>
#include <string.h>
#include "tok_block.h"
#include "ripemd160.h"
#include "loglog.h"

static const unsigned short VER = 100;
static const unsigned short ZBITS = 24;

static const char gensis[] = "Startup of Electronic Token Blockchain. " \
			      "All started from Oct 2019 with Dashi Cao.";

static int num_zerobits(const unsigned char *hash)
{
	int zbits = 0, i, j;
	const unsigned char *p = hash;
	unsigned char cb, bbit;

	for (i = 0; i < 32; i++, p++) {
		cb = *p;
		bbit = 0x80;
		for (j = 7; j >= 0; j--) {
			if ((cb & bbit) == 0)
				zbits++;
			else
				break;
			bbit = (bbit >> 1);
		}
		if (j >= 0)
			break;
	}
	return zbits;
}

static inline void blhdr_hash(struct sha256 *sha, const struct bl_header *hdr)
{
	sha256_reset(sha);
	sha256(sha, (const unsigned char *)hdr, sizeof(struct bl_header));
}

struct th_arg {
	struct bl_header *hdr;
	int up;
	int zbits;
	volatile int *fin;
};

static void *nonce_search(void *arg)
{
	struct sha256 sha;
	struct th_arg *tharg = arg;
	int zerobits = 0;

	assert(tharg->up == -1 || tharg->up == 1);
	do {
		tharg->hdr->nonce += tharg->up;
		blhdr_hash(&sha, tharg->hdr);
		zerobits = num_zerobits((const unsigned char *)sha.H);
	} while (zerobits < ZBITS && *tharg->fin == 0);
	tharg->zbits = zerobits;
	*tharg->fin = 1;
	return NULL;
}

static int block_mining(struct bl_header *hdr, volatile int *fin)
{
	struct sha256 sha;
	struct th_arg thargs[2];
	struct bl_header *hdrs[2];
	pthread_t upth, downth;
	int zbits, sysret, who;

	blhdr_hash(&sha, hdr);
	if ((zbits = num_zerobits((const unsigned char *)sha.H)) >= ZBITS)
		return zbits;
	hdrs[0] = malloc(2*sizeof(struct bl_header));
	hdrs[1] = hdrs[0] + 1;
	*hdrs[0] = *hdr;
	*hdrs[1] = *hdr;
	thargs[0].hdr = hdrs[0];
	thargs[0].up = 1;
	thargs[0].zbits = 0;
	thargs[0].fin = fin;
	thargs[1].hdr = hdrs[1];
	thargs[1].up = -1;
	thargs[1].fin = fin;
	thargs[1].zbits = 0;

/*	sysret = pthread_create(&upth, NULL, nonce_search, thargs);
	if (sysret) {
		logmsg(LOG_ERR, "pthread create failed: %s\n", strerror(sysret));
		return 0;
	}
	sysret = pthread_create(&downth, NULL, nonce_search, thargs+1);
	if (sysret) {
		logmsg(LOG_ERR, "pthread create failed: %s\n", strerror(sysret));
		return 0;
	}
	pthread_join(upth, NULL);
	pthread_join(downth, NULL); */
	nonce_search(thargs);

	zbits = thargs[0].zbits;
	who = 0;
	if (zbits < thargs[1].zbits) {
		zbits = thargs[1].zbits;
		who = 1;
	}
	*hdr = *thargs[who].hdr;
	free(hdrs[0]);
	assert(*fin == 1);
	return zbits;
}

int gensis_block(char *buf, int size)
{
	int len, zbits;
	struct etk_block *etblock;
	struct bl_header *bhdr;
	struct timespec tm;
	union {
		struct ripemd160 ripe;
		struct sha256 sha;
	} hash;
	volatile int fin = 0;
	void *tmpbuf;

	len = sizeof(gensis) + sizeof(struct etk_block);
	if (size < len)
		return -1;
	clock_gettime(CLOCK_REALTIME, &tm);

	etblock = (struct etk_block *)buf;
	etblock->txbuf = malloc(sizeof(gensis));
	memcpy(etblock->txbuf, gensis, sizeof(gensis));
	etblock->txbuf_len = sizeof(gensis);
	etblock->tx_nums = 0;

	bhdr = &etblock->hdr;
	memset(bhdr, 0, sizeof(struct bl_header));
	sha256_reset(&hash.sha);
	sha256(&hash.sha, (const unsigned char *)etblock->txbuf, etblock->txbuf_len);
	memcpy(bhdr->mtree_root, hash.sha.H, sizeof(bhdr->mtree_root));
	bhdr->ver = VER;
	bhdr->zbits = ZBITS;
	bhdr->tm = tm.tv_sec;
	ripemd160_reset(&hash.ripe);
	ripemd160_dgst(&hash.ripe, (const unsigned char *)bhdr, sizeof(struct bl_header));
	bhdr->nonce = hash.ripe.H[1];
	bhdr->nonce = (bhdr->nonce << 32) | hash.ripe.H[0];
	
	zbits = block_mining(bhdr, &fin);
	printf("Leading bits: %d\n", zbits);
	assert(zbits >= ZBITS);

	tmpbuf = etblock->txbuf;
	memcpy(&etblock->mkerle, etblock->txbuf, etblock->txbuf_len);
	free(tmpbuf);
	return sizeof(struct etk_block) + etblock->txbuf_len - 16;
}
