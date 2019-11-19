#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "tokens.h"
#include "loglog.h"

static inline struct etk_option *next_option(struct etk_option *opt)
{
	struct etk_option *nx_opt;
	
	nx_opt = ((void *)(opt + 1)) + opt->len;
	assert(nx_opt->id > opt->id);
	return nx_opt;
}
static inline const struct etk_option *cnext_option(const struct etk_option *opt)
{
	const struct etk_option *nx_opt;

	nx_opt = ((const void *)(opt + 1)) + opt->len;
	assert(nx_opt->id > opt->id);
	return nx_opt;
}

static inline int option_length(const struct etk_option *copts)
{
	int len = 0;

	while (copts->id != ENDOPT) {
		len += sizeof(struct etk_option) + copts->len;
		copts = cnext_option(copts);
	}
	return len + sizeof(struct etk_option);
}

int etoken_option_insert(struct etoken **pet, const struct etk_option *copt)
{
	struct etk_option *optn, *opt;
	struct etoken *etn, *et = *pet;
	int optsiz, nlen;

	if (et->locklen != 0)
		return -ENOSPACE;
	optsiz = copt->len + 2;
	nlen =  et->hlen + et->optlen + optsiz;
	etn = malloc(nlen);
	if (!check_pointer(etn, LOG_CRIT, nomem))
		return -ENOMEM;
	memcpy(etn, et, et->hlen);
	optn = etn->options;
	opt = et->options;
	while (opt->id < copt->id && opt->id != ENDOPT) {
		optn->id = opt->id;
		optn->len = opt->len;
		memcpy(optn->desc, opt->desc, opt->len);
		opt = next_option(opt);
		optn = next_option(optn);
	}
	optn->id = copt->id;
	optn->len = copt->len;
	memcpy(optn->desc, copt->desc, copt->len);
	optn = next_option(optn);
	while (opt->id != ENDOPT) {
		optn->id = opt->id;
		optn->len = opt->len;
		memcpy(optn->desc, opt->desc, opt->len);
		opt = next_option(opt);
		optn = next_option(optn);
	}

	optn->id = opt->id;
	optn->len = opt->len;
	et = realloc(et, nlen);
	if (!check_pointer(et, LOG_CRIT, nomem)) {
		free(etn);
		return -ENOMEM;
	}
	memcpy(et, etn, nlen);
	free(etn);
	*pet = et;
	return 0;
}

int etoken_equiv_type(const struct etoken *etl, const struct etoken *etr)
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

struct etoken *etoken_new(int vendor, int type, int subtype, unsigned long v)
{
	struct etoken *et;
	int tlen, optlen;
	struct timespec tm;

	optlen = 2;
	tlen = sizeof(struct etoken) + optlen;
	et = malloc(tlen);
	if (!check_pointer(et, LOG_ERR, nomem))
		return NULL;
	memset(et, 0, tlen);
	et->ver = ETK_VERSION;
	et->subver = ETK_SUB_VERSION;
	et->hlen = sizeof(struct etoken);
	etoken_set_type(et, vendor, type, subtype);
	clock_gettime(CLOCK_REALTIME, &tm);
	et->tm = tm.tv_sec;
	et->expire = tm.tv_sec + 100*365*24*3600ul;
	et->value = v;
	et->optlen = optlen;
	et->options[0].id = ENDOPT;
	return et;
}

struct etoken *etoken_clone(const struct etoken *et, unsigned long value)
{
	struct etoken *etn;
	int len;
	struct timespec tm;

	len = etoken_length(et);
	etn = malloc(len);
	if (!check_pointer(etn, LOG_CRIT, nomem))
		return NULL;
	memcpy(etn, et, len);
	etn->locklen = 0;
	etn->lockoff = 0;
	etn->value = value;
	clock_gettime(CLOCK_REALTIME, &tm);
	etn->tm = tm.tv_sec;
	return etn;
}

int etoken_lock(struct etoken **pet, int locklen, const BYTE *lockscript)
{
	struct etoken *etn, *et = *pet;
	int len;
	void *lockbuf;

	if (et->lockoff != 0) {
		logmsg(LOG_ERR, "Already locked!\n");
		return 1;
	}

	assert((locklen & 1) == 0);
	len = et->hlen + et->optlen + locklen;
	etn = malloc(len);
	if (!check_pointer(etn, LOG_CRIT, nomem))
		return -ENOMEM;

	memcpy(etn, et, et->hlen + et->optlen);
	etn->locklen = locklen;
	etn->lockoff = et->hlen + et->optlen;
	lockbuf = ((void *)etn) + et->lockoff;
	memcpy(lockbuf, lockscript, locklen);
	et = realloc(et, len);
	if (!check_pointer(et, LOG_CRIT, nomem)) {
		free(etn);
		return -ENOMEM;
	}
	memcpy(et, etn, len);
	free(etn);
	*pet = et;
	return 0;
}
