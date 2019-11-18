#include <stdio.h>
#include <string.h>
#include <time.h>
#include "tokens.h"
#include "loglog.h"
#include "ecc256/ripemd160.h"
#include "virtmach.h"

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
	if (etl->optlen != etr->optlen)
		return 0;
	if (memcmp(etl->options, etr->options, etl->optlen) != 0)
		return 0;

	return 1;
}

int etoken_expired(const struct etoken *et)
{
	struct timespec tm;

	clock_gettime(CLOCK_REALTIME, &tm);
	if (et->expire < tm.tv_sec)
		return 1;
	return 0;
}

struct etoken *etoken_new(int vendor, int type, int subtype,
		const struct etk_option *opts)
{
	struct etoken *et;
	int tlen, optlen;
	struct timespec tm;

	optlen = option_length(opts);
	tlen = sizeof(struct etoken) + optlen;
	et = malloc(tlen);
	if (!check_pointer(et, LOG_ERR, "Out of Memory"))
		return NULL;
	memset(et, 0, tlen);
	et->ver = ETK_VERSION;
	et->subver = ETK_SUB_VERSION;
	et->hlen = sizeof(struct etoken);
	etoken_set_type(et, vendor, type, subtype);
	clock_gettime(CLOCK_REALTIME, &tm);
	et->tm = tm.tv_sec;
	et->expire = tm.tv_sec + 100*365*24*3600ul;
	et->optlen = optlen;
	etoken_set_options(et, opts);

	return et;
}

struct etoken *etoken_clone(const struct etoken *et, unsigned long value)
{
	struct etoken *etn;
	int len;
	struct timespec tm;

	len = etoken_length(et);
	etn = malloc(len);
	if (!check_pointer(etn, LOG_CRIT, "Out of Memory!\n"))
		return NULL;
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
	et->lockscript = malloc(locklen);
	if (!check_pointer(et->lockscript, LOG_CRIT, nomem))
		return 0;
	et->locklen = locklen;
	memcpy(et->lockscript, lockscript, locklen);
	len = etoken_length(et) + locklen;
	buf = malloc(len);
	if (!check_pointer(buf, LOG_CRIT, nomem))
		goto err_10;
	memcpy(buf, et, len - locklen);
	((struct etoken *)buf)->lockscript = NULL;
	memcpy(buf+len-locklen, lockscript, locklen);
	ripe = ripemd160_init();
	if (!check_pointer(ripe, LOG_CRIT, nomem))
		goto err_20;
	ripemd160_dgst(ripe, buf, len);
	memcpy(et->id, ripe->H, RIPEMD_LEN);
	ripemd160_exit(ripe);
	free(buf);
	return 1;

err_20:
	free(buf);
err_10:
	free(et->lockscript);
	et->lockscript = NULL;
	et->locklen = 0;
	return 0;
}

int etoken_unlock(const struct etoken *et, int unlen, const BYTE *unlock)
{
	BYTE *buf;
	int retv;
	struct vmach *vm;

	buf = malloc(et->locklen + unlen);
	if (!check_pointer(buf, LOG_CRIT, nomem))
		return 0;
	memcpy(buf, unlock, unlen);
	memcpy(buf+unlen, et->lockscript, et->locklen);
	vm = vmach_init(et->id, RIPEMD_LEN);
	if (!check_pointer(vm, LOG_CRIT, nomem)) {
		free(buf);
		return 0;
	}
	retv = vmach_execute(vm, buf, unlen + et->locklen);
	vmach_exit(vm);
	free(buf);
	return retv;
}
