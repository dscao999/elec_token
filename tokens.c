#include <stdio.h>
#include <string.h>
#include <time.h>
#include "tokens.h"
#include "loglog.h"
#include "ecc256/ripemd160.h"
#include "ecc256/sha256.h"

static const int LENOVO = 168;
static const int PCWANT = 168;

static inline struct etk_option *next_option(struct etk_option *opt)
{
	void *nx_opt;
	
	nx_opt = ((void *)(opt + 1)) + opt->len;
	return nx_opt;
}
static inline const struct etk_option *cnext_option(const struct etk_option *opt)
{
	const void *nx_opt;

	nx_opt = ((const void *)(opt + 1)) + opt->len;
	return nx_opt;
}

static inline int option_length(const struct etk_option *copts)
{
	int len = 0;

	while (copts->id != 0) {
		len += sizeof(struct etk_option) + copts->len;
		copts = cnext_option(copts);
	}
	return len + sizeof(struct etk_option);
}

void etoken_set_subtype(struct etoken *et, int sub, const char *desc)
{
	et->subtype = sub;
	memset(et->desc, 0, 12);
	strncpy((char *)et->desc, desc, 12);
}

void etoken_set_options(struct etoken *et, const struct etk_option *copt)
{
	struct etk_option *opt;

	if (et->optlen != option_length(copt))
		return;
	opt = et->options;
	while (copt->id != 0) {
		opt->id = copt->id;
		opt->len = copt->len;
		memcpy(opt->desc, copt->desc, copt->len);
		copt = cnext_option(copt);
		opt = next_option(opt);
	}
	opt->id = 0;
	opt->len = 0;
}

int etoken_equiv(const struct etoken *etl, const struct etoken *etr)
{
	if (etl->ver != etr->ver)
		return 0;
	if (etl->vendor != etr->vendor)
		return 0;
	if (etl->type != etr->type)
		return 0;
	if (etl->hlen != etr->hlen)
		return 0;
	if (etl->subtype != etr->subtype)
		return 0;
	if (memcmp(etl->desc, etr->desc, 12) != 0)
		return 0;
	if (etl->optlen != etr->optlen)
		return 0;
	if (memcmp(etl->options, etr->options, etl->optlen) != 0)
		return 0;

	return 1;
}

int etoken_expired(const struct etoken *et)
{
	struct timespec tm;

	if (et->expire == 0)
		return 0;
	clock_gettime(CLOCK_REALTIME, &tm);
	if (et->expire < tm.tv_sec)
		return 1;
	return 0;
}

struct etoken *etoken_new(unsigned long value, int subtype, const char *desc,
		const struct etk_option *opts)
{
	struct etoken *et;
	int tlen, optlen;
	struct timespec tm;

	optlen = option_length(opts);
	tlen = sizeof(struct etoken) + optlen;
	et = malloc(tlen);
	check_pointer(et);
	memset(et, 0, tlen);
	et->ver = ETK_VERSION;
	et->hlen = sizeof(struct etoken);
	etoken_set_vendor(et, LENOVO, PCWANT);
	etoken_set_subtype(et, subtype, desc);
	et->value = value;
	clock_gettime(CLOCK_REALTIME, &tm);
	et->tm = tm.tv_sec;
	et->optlen = optlen;
	etoken_set_options(et, opts);

	return et;
}

struct etoken *etoken_clone(const struct etoken *et, unsigned long value)
{
	struct etoken *etn;
	int len;
	struct timespec tm;

	len = et->hlen + option_length(et->options);
	etn = malloc(len);
	check_pointer(etn);
	memcpy(etn, et, len);
	etn->locklen = 0;
	etn->lockscript = NULL;
	etn->value = value;
	clock_gettime(CLOCK_REALTIME, &tm);
	etn->tm = tm.tv_sec;
	memset(etn->id, 0, RIPEMD_ID_LEN);
	return etn;
}

int etoken_lock(struct etoken *et, int locklen, const BYTE *lockscript)
{
	struct ripemd160 *ripe;
	BYTE *buf;
	int len;

	if (et->lockscript != NULL)
		return 0;
	et->locklen = locklen;
	et->lockscript = malloc(locklen);
	check_pointer(et->lockscript);
	memcpy(et->lockscript, lockscript, locklen);
	len = et->hlen + et->optlen + locklen;
	buf = malloc(len);
	check_pointer(buf);
	memcpy(buf, et, len - locklen);
	((struct etoken *)buf)->lockscript = NULL;
	memcpy(buf+len-locklen, lockscript, locklen);
	ripe = ripemd160_init();
	check_pointer(ripe);
	ripemd160_dgst(ripe, buf, len);
	memcpy(et->id, ripe->H, 20);
	ripemd160_exit(ripe);
	free(buf);
	return 1;
}

static void etoken_sha256(BYTE dgst[SHA256_ID_LEN], const struct etoken *et)
{
	struct sha256 *sha;

	sha = sha256_init();
	check_pointer(sha);
	sha256(sha, (const BYTE *)et, et->hlen+et->optlen);
	memcpy(dgst, sha->H, SHA256_ID_LEN);
	sha256_exit(sha);
}

#define OPERAND		0x80
#define SHA256_DIGEST	(OPERAND|0x01)

static inline int virt_exec(const BYTE *script, int len)
{
	return 1; /* always true */
}

int etoken_unlock(const struct etoken *et, int unlen, const BYTE *unlock)
{
	BYTE *buf, *sha, *script;
	int retv;

	buf = malloc(et->locklen + unlen + SHA256_ID_LEN);
	check_pointer(buf);
	sha = buf + 1;
	script = buf + SHA256_ID_LEN + 1;
	memcpy(script, unlock, unlen);
	memcpy(buf+unlen, et->lockscript, et->locklen);
	buf[0] = SHA256_DIGEST;
	etoken_sha256(sha, et);
	retv = virt_exec(buf, unlen + et->locklen);
	free(buf);
	return retv;
}
